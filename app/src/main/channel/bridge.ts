// The app's way to the service. The app never opens the service's pipe or
// socket itself: it starts the command-line client as `ubc-vpn bridge` and
// talks to it over standard input and output, one JSON message per line. The
// client is what checks that the other end really is the service.
//
// The contract is `crates/core/src/bridge.rs`. In short: the bridge's first
// line is `ready` or the reason there is no channel; after `ready`, every
// message from the service arrives as a `server` line; any other line is the
// bridge's last. The app acts on the last line, never on the exit status.
//
// Nothing in this file logs a line, puts one in an error, or reads the
// bridge's standard error.

import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { dirname } from "node:path";
import type { UnavailableReason } from "@shared/api";
import type { BridgeLine } from "@shared/protocol/BridgeLine";
import type { Event } from "@shared/protocol/Event";
import type { Outcome } from "@shared/protocol/Outcome";
import type { Request } from "@shared/protocol/Request";
import type { RequestBody } from "@shared/protocol/RequestBody";
import type { ServerMessage } from "@shared/protocol/ServerMessage";
import { encodeLine, LineDecoder } from "./framing";
import { isBridgeLine } from "./validate";

/**
 * What the app may ask the service through the bridge. `connect` is left out
 * on purpose: it carries the session cookie, which the app must never hold.
 * Connecting goes through `ubc-vpn connect --json`.
 */
export type BridgeRequestBody = Exclude<RequestBody, { method: "connect" }>;

export type BridgeStatus =
    /** The first bridge has been started and has not yet said anything. */
    | { status: "connecting" }
    | { status: "unavailable"; reason: UnavailableReason }
    /** The service speaks a different protocol version. */
    | { status: "update_needed"; serviceVersion: string }
    /** Something is listening where the service should be, and it is not the service. */
    | { status: "untrusted_service" }
    /** The service belongs to another user of this computer. */
    | { status: "not_owner" }
    | { status: "ready"; serviceVersion: string; ownerClaimed: boolean };

/** Why a request got no answer. Never carries any part of a message. */
export class BridgeError extends Error {
    constructor(readonly reason: "not_connected" | "closed" | "timeout" | "not_allowed") {
        super(`bridge request failed: ${reason}`);
        this.name = "BridgeError";
    }
}

/**
 * Things that should never happen and are worth a line in the log. The text
 * is fixed: it never includes anything that was sent or received.
 */
export type BridgeFault =
    /** The bridge refused a line the app wrote. A bug in the app. */
    "the bridge refused a line the app wrote";

export interface BridgeOptions {
    /** The command-line client, as an absolute path. */
    command: string;
    /** Its arguments: `["bridge"]`. */
    args: readonly string[];
    onStatus(status: BridgeStatus): void;
    onEvent(event: Event): void;
    onFault?(fault: BridgeFault): void;
    /** Delay before the first restart; doubles up to `maxRetryDelayMs`. */
    initialRetryDelayMs?: number;
    maxRetryDelayMs?: number;
    /** How long a new bridge has to write its first line. */
    startTimeoutMs?: number;
    /** How long to wait for the answer to a request. */
    replyTimeoutMs?: number;
    /** How long a bridge whose input was closed has to leave before it is killed. */
    exitGraceMs?: number;
    /** The app's own environment, from which the bridge's short one is taken. */
    env?: Record<string, string | undefined>;
}

/**
 * The only variables the bridge is started with. The app's environment is
 * not passed on: nothing set for the app, by the user or by anything else,
 * reaches the client unless it is named here. (On Windows, Node adds back
 * a fixed handful the OS needs to start any process, such as `PATH` and
 * `USERNAME`; the client is started by absolute path and does not use them.)
 */
export const BRIDGE_ENV = [
    // Windows: where the system's own libraries are. A program cannot start without it.
    "SystemRoot",
    // Windows: where the service's policy file is.
    "ProgramData",
    // Windows: the user's settings folder.
    "APPDATA",
    // Windows: the user's profile, which the settings folder falls back to.
    "USERPROFILE",
    // Windows: temporary files.
    "TEMP",
    "TMP",
    // macOS and Linux: the user's home, where settings live.
    "HOME",
    // Linux: where settings live when the user has moved them.
    "XDG_CONFIG_HOME",
    // Linux: the per-user runtime folder, where a development service listens.
    "XDG_RUNTIME_DIR",
    // macOS and Linux: temporary files, and macOS's per-user runtime folder.
    "TMPDIR",
] as const;

/** The bridge's environment: the entries of {@link BRIDGE_ENV} that are set, and nothing else. */
export function bridgeEnv(env: Record<string, string | undefined>): Record<string, string> {
    const kept: Record<string, string> = {};
    for (const name of BRIDGE_ENV) {
        const value = env[name];
        if (value !== undefined) {
            kept[name] = value;
        }
    }
    return kept;
}

/** The pause before each new attempt: it doubles, and never passes `maxMs`. */
export class Backoff {
    private nextMs: number;

    constructor(
        private readonly initialMs: number,
        private readonly maxMs: number,
    ) {
        this.nextMs = Math.min(initialMs, maxMs);
    }

    /** The pause to take now. The one after it is longer, up to the limit. */
    take(): number {
        const delay = this.nextMs;
        this.nextMs = Math.min(delay * 2, this.maxMs);
        return delay;
    }

    reset(): void {
        this.nextMs = Math.min(this.initialMs, this.maxMs);
    }
}

/**
 * Starts the command-line client, the same way whatever it is asked to do:
 * no shell, a fixed program and fixed arguments, a short environment of its
 * own, and the program's own folder to work in. Its standard error is
 * discarded unread: that is the client's own log, not the app's.
 */
export function startClient(
    command: string,
    args: readonly string[],
    env: Record<string, string | undefined>,
): ChildProcessWithoutNullStreams {
    return spawn(command, [...args], {
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "ignore"],
        env: bridgeEnv(env),
        cwd: dirname(command),
    }) as unknown as ChildProcessWithoutNullStreams;
}

interface Pending {
    resolve(outcome: Outcome): void;
    reject(error: BridgeError): void;
    timer: NodeJS.Timeout;
}

const U32_MAX = 0xffffffff;

export class BridgeClient {
    private readonly options: Required<BridgeOptions>;
    private readonly backoff: Backoff;
    private child: ChildProcessWithoutNullStreams | null = null;
    private ready = false;
    private stopped = true;
    /** Bridges that were let go and have not yet left. */
    private readonly leaving = new Set<ChildProcessWithoutNullStreams>();
    private retryTimer: NodeJS.Timeout | null = null;
    private nextId = 1;
    private readonly pending = new Map<number, Pending>();

    constructor(options: BridgeOptions) {
        this.options = {
            onFault: () => {},
            initialRetryDelayMs: 250,
            maxRetryDelayMs: 5_000,
            startTimeoutMs: 10_000,
            replyTimeoutMs: 10_000,
            exitGraceMs: 2_000,
            env: process.env,
            ...options,
        };
        this.backoff = new Backoff(this.options.initialRetryDelayMs, this.options.maxRetryDelayMs);
    }

    /** Starts a bridge, and keeps one running until {@link stop}. */
    start(): void {
        if (!this.stopped) {
            return;
        }
        this.stopped = false;
        this.options.onStatus({ status: "connecting" });
        this.launch();
    }

    /**
     * Stops for good. Every bridge is ended at once, including any that were
     * let go a moment ago and are still being given time to leave: the timer
     * that would kill them dies with the app, and nothing may outlive it.
     */
    stop(): void {
        this.stopped = true;
        this.clearRetry();
        this.drop(0);
        for (const child of this.leaving) {
            child.kill();
        }
        this.leaving.clear();
    }

    /** Skips the wait before the next attempt. Does nothing while a bridge is running. */
    retryNow(): void {
        if (this.stopped || this.child !== null) {
            return;
        }
        this.clearRetry();
        this.launch();
    }

    /**
     * Sends one request and resolves with the service's outcome, which may
     * itself be a refusal. Rejects with a {@link BridgeError} when there is
     * no answer.
     *
     * A request that is never answered means the bridge can no longer be
     * relied on, so it is replaced: the app is not left waiting on it.
     */
    request(body: BridgeRequestBody): Promise<Outcome> {
        // The type already forbids `connect`. This holds the line for a caller
        // that got round the type; nothing is written, and nothing of the
        // request is kept.
        if ((body as RequestBody).method === "connect") {
            return Promise.reject(new BridgeError("not_allowed"));
        }
        const child = this.child;
        if (child === null || !this.ready) {
            return Promise.reject(new BridgeError("not_connected"));
        }
        const id = this.takeId();
        const request: Request = { id, body };
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new BridgeError("timeout"));
                this.fail(child, "protocol_error");
            }, this.options.replyTimeoutMs);
            this.pending.set(id, { resolve, reject, timer });
            child.stdin.write(encodeLine(request));
        });
    }

    private takeId(): number {
        const id = this.nextId;
        this.nextId = id >= U32_MAX ? 1 : id + 1;
        return id;
    }

    private launch(): void {
        let child: ChildProcessWithoutNullStreams;
        try {
            child = startClient(this.options.command, this.options.args, this.options.env);
        } catch {
            // Starting a program can fail outright, for example when the file
            // is there but is not a program. That is the service being out of
            // reach, like any other; it must never take the app down.
            this.options.onStatus({ status: "unavailable", reason: "not_running" });
            this.retryAfter(this.backoff.take());
            return;
        }
        this.child = child;
        const decoder = new LineDecoder();
        let greeted = false;

        // A bridge that starts and then says nothing is as unusable as none.
        const firstLineTimer = setTimeout(() => {
            this.fail(child, "protocol_error");
        }, this.options.startTimeoutMs);

        child.stdout.on("data", (chunk: Buffer) => {
            let lines: string[];
            try {
                lines = decoder.push(chunk);
            } catch {
                this.fail(child, "protocol_error");
                return;
            }
            for (const text of lines) {
                if (this.child !== child) {
                    return;
                }
                let line: unknown;
                try {
                    line = JSON.parse(text);
                } catch {
                    line = null;
                }
                if (!isBridgeLine(line)) {
                    this.fail(child, "protocol_error");
                    return;
                }
                if (!greeted) {
                    greeted = true;
                    clearTimeout(firstLineTimer);
                    // Only `ready` or a reason may come first.
                    if (line.type === "server") {
                        this.fail(child, "protocol_error");
                        return;
                    }
                }
                this.onLine(child, line);
            }
        });

        // A program that cannot be started reports it here, and a broken pipe
        // on its input reports it on `stdin`. Both are followed by "close",
        // which does the work; the listeners keep them from being uncaught.
        child.on("error", () => {});
        child.stdin.on("error", () => {});
        child.once("close", () => {
            clearTimeout(firstLineTimer);
            // An exit with no last line: the service is taken to be gone.
            this.fail(child, "not_running");
        });
    }

    private onLine(child: ChildProcessWithoutNullStreams, line: BridgeLine): void {
        switch (line.type) {
            case "ready":
                if (this.ready) {
                    this.fail(child, "protocol_error");
                    return;
                }
                this.ready = true;
                this.backoff.reset();
                this.options.onStatus({
                    status: "ready",
                    serviceVersion: line.service_version,
                    ownerClaimed: line.owner_claimed,
                });
                return;
            case "server":
                this.onServerMessage(child, line.message);
                return;
            case "service_unavailable":
                this.fail(child, "not_running");
                return;
            case "bad_line":
                this.options.onFault("the bridge refused a line the app wrote");
                this.fail(child, "protocol_error");
                return;
            case "update_needed":
                // An installer may replace either side, so keep looking, slowly.
                this.end(
                    child,
                    { status: "update_needed", serviceVersion: line.service_version.slice(0, 32) },
                    this.options.maxRetryDelayMs,
                );
                return;
            case "untrusted_service":
                this.end(child, { status: "untrusted_service" }, this.options.maxRetryDelayMs);
                return;
            case "not_owner":
                // A new bridge would be told the same, so none is started.
                this.end(child, { status: "not_owner" }, null);
                return;
        }
    }

    private onServerMessage(child: ChildProcessWithoutNullStreams, message: ServerMessage): void {
        // Only reached after `ready`: a first line must be `ready` or a
        // reason, and every reason ends the bridge.
        if (message.type === "event") {
            this.options.onEvent(message.data);
            return;
        }
        const pending = this.pending.get(message.data.id);
        // An unanswered request replaces the bridge, so every answer has a
        // request waiting. One that does not was never asked for.
        if (pending === undefined) {
            this.fail(child, "protocol_error");
            return;
        }
        this.pending.delete(message.data.id);
        clearTimeout(pending.timer);
        pending.resolve(message.data.outcome);
    }

    /** Ends this bridge, reports that the service cannot be used, and tries again later. */
    private fail(child: ChildProcessWithoutNullStreams, reason: UnavailableReason): void {
        if (this.child !== child) {
            return;
        }
        this.end(child, { status: "unavailable", reason }, this.backoff.take());
    }

    /** Ends this bridge with its last word, and starts another after `retryMs`, if given. */
    private end(
        child: ChildProcessWithoutNullStreams,
        status: BridgeStatus,
        retryMs: number | null,
    ): void {
        if (this.child !== child) {
            return;
        }
        this.drop(this.options.exitGraceMs);
        if (this.stopped) {
            return;
        }
        this.options.onStatus(status);
        if (retryMs !== null) {
            this.retryAfter(retryMs);
        }
    }

    private retryAfter(delayMs: number): void {
        this.clearRetry();
        this.retryTimer = setTimeout(() => {
            this.retryTimer = null;
            this.launch();
        }, delayMs);
    }

    /**
     * Lets go of the current bridge, and makes sure it ends. Closing its
     * input is how a bridge is told the app has gone, and it then leaves by
     * itself. One that has not left after `graceMs` is killed.
     */
    private drop(graceMs: number): void {
        const child = this.child;
        this.child = null;
        this.ready = false;
        if (child !== null) {
            child.stdin.end();
            if (graceMs <= 0) {
                child.kill();
            } else if (child.exitCode === null && child.signalCode === null) {
                this.leaving.add(child);
                const timer = setTimeout(() => child.kill(), graceMs);
                child.once("close", () => {
                    clearTimeout(timer);
                    this.leaving.delete(child);
                });
            }
        }
        for (const pending of this.pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(new BridgeError("closed"));
        }
        this.pending.clear();
    }

    private clearRetry(): void {
        if (this.retryTimer !== null) {
            clearTimeout(this.retryTimer);
            this.retryTimer = null;
        }
    }
}
