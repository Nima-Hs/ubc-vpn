// The user's settings and the rules for routes. The app never opens
// `settings.json` or the policy file: it runs the command-line client, so the
// rules exist in one place and are the ones the service applies when it
// connects. The contract is `crates/core/src/settings_cli.rs`.
//
// Each call starts the client once, the same way the bridge is started. What
// the user typed goes to the client on standard input and never on its
// command line. The client writes exactly one line and exits: with status 0
// when the line is the answer, and with status 1 when it is a failure.
// Anything else at all is treated as the client being unusable.

import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { SettingsResult } from "@shared/api";
import type { RouteInput } from "@shared/protocol/RouteInput";
import type { RoutesReply } from "@shared/protocol/RoutesReply";
import type { SettingsView } from "@shared/protocol/SettingsView";
import { startClient } from "./bridge";
import { encodeLine, LineDecoder } from "./framing";
import { isRoutesReply, isSettingsFailure, isSettingsView } from "./validate";

/** What the rest of the main process needs from the settings, real or fake. */
export interface SettingsService {
    getSettings(): Promise<SettingsResult<SettingsView>>;
    /** Checks routes and changes nothing. A newer check replaces one still running. */
    checkRoutes(input: RouteInput): Promise<SettingsResult<RoutesReply>>;
    /** Checks routes and, if every entry is acceptable, saves them. One at a time. */
    saveRoutes(input: RouteInput): Promise<SettingsResult<RoutesReply>>;
    /** Ends every client still running, for when the app quits. */
    stop(): void;
}

/** The three things the client can be asked, as its fixed arguments. */
export const SETTINGS_ARGS = {
    get: ["settings", "get", "--json"],
    check: ["settings", "check-routes", "--json"],
    save: ["settings", "set-routes", "--json"],
} as const;

export interface SettingsOptions {
    /** The command-line client, as an absolute path. */
    command: string;
    /** Put before the fixed arguments. Empty in the app; tests use it to run a script. */
    leadingArgs?: readonly string[];
    /** How long one call may take before the client is ended. */
    timeoutMs?: number;
    /** The app's own environment, from which the client's short one is taken. */
    env?: Record<string, string | undefined>;
}

const UNAVAILABLE = { ok: false, error: "unavailable" } as const;

/**
 * Whether every problem in a reply points at an entry that was sent, or at
 * the input as a whole. A reply that points anywhere else is not an answer
 * to this input, and the interface must not be made to mark a row with it.
 */
function fitsInput(reply: RoutesReply, input: RouteInput): boolean {
    if (reply.type === "ok") {
        return true;
    }
    return reply.problems.every((problem) => {
        if (problem.list === null || problem.index === null) {
            return problem.list === null && problem.index === null;
        }
        return problem.index < input[problem.list].length;
    });
}

export class SettingsRunner implements SettingsService {
    private readonly options: Required<SettingsOptions>;
    private readonly running = new Set<ChildProcessWithoutNullStreams>();
    private saving = false;
    private checking: ChildProcessWithoutNullStreams | null = null;

    constructor(options: SettingsOptions) {
        this.options = { leadingArgs: [], timeoutMs: 10_000, env: process.env, ...options };
    }

    async getSettings(): Promise<SettingsResult<SettingsView>> {
        const line = await this.run(SETTINGS_ARGS.get, null);
        if (line === null) {
            return UNAVAILABLE;
        }
        if (line.status === 0 && isSettingsView(line.value)) {
            return { ok: true, value: line.value };
        }
        return failureOf(line);
    }

    async checkRoutes(input: RouteInput): Promise<SettingsResult<RoutesReply>> {
        // Only the newest check matters, and none may pile up behind it.
        this.checking?.kill();
        const mine: { child: ChildProcessWithoutNullStreams | null } = { child: null };
        const result = await this.routes(SETTINGS_ARGS.check, input, (child) => {
            mine.child = child;
            this.checking = child;
        });
        if (mine.child !== null && this.checking !== mine.child) {
            return { ok: false, error: "superseded" };
        }
        this.checking = null;
        return result;
    }

    async saveRoutes(input: RouteInput): Promise<SettingsResult<RoutesReply>> {
        // Two saves at once could finish in either order.
        if (this.saving) {
            return { ok: false, error: "busy" };
        }
        this.saving = true;
        try {
            return await this.routes(SETTINGS_ARGS.save, input);
        } finally {
            this.saving = false;
        }
    }

    stop(): void {
        for (const child of this.running) {
            child.kill();
        }
        this.running.clear();
    }

    private async routes(
        args: readonly string[],
        input: RouteInput,
        onStart?: (child: ChildProcessWithoutNullStreams) => void,
    ): Promise<SettingsResult<RoutesReply>> {
        let encoded: Buffer;
        try {
            // Only the two lists, whatever else the object carried.
            encoded = encodeLine({ subnets: input.subnets, dns_domains: input.dns_domains });
        } catch {
            // Longer than a line may be. The client would say the same.
            return { ok: false, error: "bad_input" };
        }
        const line = await this.run(args, encoded, onStart);
        if (line === null) {
            return UNAVAILABLE;
        }
        if (line.status === 0 && isRoutesReply(line.value) && fitsInput(line.value, input)) {
            return { ok: true, value: line.value };
        }
        return failureOf(line);
    }

    /**
     * Runs the client once and returns its one line with its exit status, or
     * `null` if it did not behave: could not be started, ran out of time,
     * wrote nothing, more than one line, too much, or something unreadable.
     */
    private run(
        args: readonly string[],
        input: Buffer | null,
        onStart?: (child: ChildProcessWithoutNullStreams) => void,
    ): Promise<{ status: number | null; value: unknown } | null> {
        return new Promise((resolve) => {
            let child: ChildProcessWithoutNullStreams;
            try {
                child = startClient(
                    this.options.command,
                    [...this.options.leadingArgs, ...args],
                    this.options.env,
                );
            } catch {
                resolve(null);
                return;
            }
            this.running.add(child);
            onStart?.(child);
            const decoder = new LineDecoder();
            const lines: string[] = [];
            let broken = false;
            const timer = setTimeout(() => {
                broken = true;
                child.kill();
            }, this.options.timeoutMs);

            child.stdout.on("data", (chunk: Buffer) => {
                try {
                    lines.push(...decoder.push(chunk));
                } catch {
                    broken = true;
                    child.kill();
                }
            });
            child.on("error", () => {});
            child.stdin.on("error", () => {});
            child.once("close", (status) => {
                clearTimeout(timer);
                this.running.delete(child);
                // Exactly one whole line, and nothing after it.
                const [text] = lines;
                if (broken || lines.length !== 1 || text === undefined || decoder.hasPartial()) {
                    resolve(null);
                    return;
                }
                try {
                    resolve({ status, value: JSON.parse(text) });
                } catch {
                    resolve(null);
                }
            });
            // The one line of input, then the end of input.
            child.stdin.end(input ?? undefined);
        });
    }
}

/** A failure line with exit status 1 is the client's answer; anything else is not one. */
function failureOf(line: { status: number | null; value: unknown }): {
    ok: false;
    error: "unavailable" | "bad_input" | "unreadable" | "unwritable";
} {
    return line.status === 1 && isSettingsFailure(line.value)
        ? { ok: false, error: line.value.error }
        : UNAVAILABLE;
}
