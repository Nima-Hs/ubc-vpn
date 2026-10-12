// Logging in and connecting. The app does neither itself: it starts the
// command-line client as `ubc-vpn connect --json`, shows the user the
// questions the client asks, and passes the answers back. The client talks to
// the gateway and hands the session cookie to the service, so the app never
// sees it. The contract is `crates/core/src/login.rs`.
//
// An answer may be a password. It is written to the client's standard input
// once and kept nowhere: not in a field of this class, not in the state the
// interface is shown, not in an error, and never in a log. This file logs
// nothing at all.

import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { LoginPrompt, LoginState } from "@shared/api";
import type { AppMessage } from "@shared/protocol/AppMessage";
import { startClient } from "./bridge";
import { encodeLine, LineDecoder } from "./framing";
import { isCliMessage } from "./validate";

/** What the rest of the main process needs from a login, real or fake. */
export interface LoginRunner {
    /** Starts a login. Returns `false`, and does nothing, if one is under way. */
    start(): boolean;
    /**
     * Passes on the user's answer to the prompt with this `id`. Returns
     * `false`, and sends nothing, unless that prompt is the one waiting.
     */
    answer(id: number, value: string): boolean;
    /** Gives up, or dismisses a failure. Safe to call at any time. */
    cancel(): void;
    /** Ends everything at once, for when the app quits. */
    stop(): void;
}

export interface ConnectOptions {
    /** The command-line client, as an absolute path. */
    command: string;
    /** Its arguments: `["connect", "--json"]`. The app passes no routes. */
    args: readonly string[];
    onState(state: LoginState): void;
    /** How long a client that was told to stop has to leave before it is killed. */
    exitGraceMs?: number;
    /** The app's own environment, from which the client's short one is taken. */
    env?: Record<string, string | undefined>;
    /**
     * The least time between one login starting and the next. Each start can
     * send an MFA request to the user's phone; nothing, whether a held-down
     * key or a page gone wrong, may send them in a stream.
     */
    minStartGapMs?: number;
}

/** The longest a label and a message from the gateway may be when shown. */
const MAX_LABEL = 200;
const MAX_MESSAGE = 1000;

// Control characters, including newlines and tabs; the characters that
// reverse or override the direction text is drawn in; and the line and
// paragraph separators.
const UNSAFE_IN_TEXT = /[\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]+/gu;

/**
 * Text from the gateway or the client, made safe to show: one line of plain
 * characters, kept to a sensible length. Without this a message could draw
 * itself backwards, or push the real question off the screen with newlines.
 */
export function plainText(text: string, maxLength: number): string {
    return text.replace(UNSAFE_IN_TEXT, " ").replace(/ {2,}/g, " ").trim().slice(0, maxLength);
}

const IDLE: LoginState = { phase: "idle" };
const WORKING: LoginState = { phase: "working" };
/** For everything that is the client misbehaving and not the gateway answering. */
const BROKEN: LoginState = { phase: "failed", code: "internal", message: "" };

export class ConnectRunner implements LoginRunner {
    private readonly options: Required<ConnectOptions>;
    private child: ChildProcessWithoutNullStreams | null = null;
    /**
     * The prompt waiting for an answer, if one is. The client numbers its
     * prompts from the start with every login, so its ids say nothing about
     * which login a prompt belongs to. The interface is given an id the app
     * makes itself, never used twice, and only that id is accepted back: an
     * answer typed for one login's question cannot reach another's.
     */
    private waiting: { ours: number; clients: number } | null = null;
    private lastPromptId = 0;
    private readonly leaving = new Set<ChildProcessWithoutNullStreams>();
    /** When the client was last started, and the wait before the next start, if one is on. */
    private lastStartAt = Number.NEGATIVE_INFINITY;
    private startTimer: NodeJS.Timeout | null = null;

    constructor(options: ConnectOptions) {
        this.options = { exitGraceMs: 2_000, env: process.env, minStartGapMs: 3_000, ...options };
    }

    start(): boolean {
        // One login at a time: a second would mean a second MFA request.
        if (this.child !== null || this.startTimer !== null) {
            return false;
        }
        // The user sees the login begin at once. The client itself is started
        // no sooner than the gap after the last one.
        this.options.onState(WORKING);
        const wait = this.lastStartAt + this.options.minStartGapMs - Date.now();
        if (wait > 0) {
            this.startTimer = setTimeout(() => {
                this.startTimer = null;
                this.launch();
            }, wait);
        } else {
            this.launch();
        }
        return true;
    }

    private launch(): void {
        this.lastStartAt = Date.now();
        let child: ChildProcessWithoutNullStreams;
        try {
            child = startClient(this.options.command, this.options.args, this.options.env);
        } catch {
            this.options.onState(BROKEN);
            return;
        }
        this.child = child;
        const decoder = new LineDecoder();

        child.stdout.on("data", (chunk: Buffer) => {
            let lines: string[];
            try {
                lines = decoder.push(chunk);
            } catch {
                this.finish(child, BROKEN);
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
                this.onLine(child, line);
            }
        });
        child.on("error", () => {});
        child.stdin.on("error", () => {});
        // Leaving without a last line is a failure, not a quiet success.
        child.once("close", () => this.finish(child, BROKEN));
    }

    answer(id: number, value: string): boolean {
        const child = this.child;
        const waiting = this.waiting;
        if (child === null || waiting === null || waiting.ours !== id) {
            return false;
        }
        const answer: AppMessage = { type: "answer", id: waiting.clients, value };
        let line: Buffer;
        try {
            line = encodeLine(answer);
        } catch {
            // Longer than a line may be. Nothing is sent; the prompt still waits.
            return false;
        }
        this.waiting = null;
        // Written once, and the bytes are wiped as soon as they have gone.
        // Nothing here keeps the value or the line. (The text itself cannot
        // be wiped: a JavaScript string cannot be changed. It is simply not
        // kept, and is gone once the caller lets go of it.)
        child.stdin.write(line, () => line.fill(0));
        this.options.onState(WORKING);
        return true;
    }

    cancel(): void {
        if (this.startTimer !== null) {
            clearTimeout(this.startTimer);
            this.startTimer = null;
        }
        const child = this.child;
        if (child !== null) {
            const cancel: AppMessage = { type: "cancel" };
            child.stdin.write(encodeLine(cancel));
        }
        this.finish(child, IDLE);
    }

    stop(): void {
        this.cancel();
        for (const child of this.leaving) {
            child.kill();
        }
        this.leaving.clear();
    }

    private onLine(child: ChildProcessWithoutNullStreams, line: unknown): void {
        if (!isCliMessage(line)) {
            this.finish(child, BROKEN);
            return;
        }
        switch (line.type) {
            case "prompt": {
                // A second question while the first still waits is not something
                // the client does; the answer could go to the wrong one.
                if (this.waiting !== null) {
                    this.finish(child, BROKEN);
                    return;
                }
                this.lastPromptId += 1;
                this.waiting = { ours: this.lastPromptId, clients: line.id };
                const prompt: LoginPrompt = {
                    id: this.lastPromptId,
                    kind: line.kind,
                    label: plainText(line.label, MAX_LABEL),
                    ...(line.message !== undefined && {
                        message: plainText(line.message, MAX_MESSAGE),
                    }),
                };
                this.options.onState({ phase: "prompt", prompt });
                return;
            }
            case "done":
                // The connection's progress now arrives from the service.
                this.finish(child, IDLE);
                return;
            case "error":
                this.finish(
                    child,
                    line.code === "cancelled"
                        ? IDLE
                        : {
                              phase: "failed",
                              code: line.code,
                              message: plainText(line.message, MAX_MESSAGE),
                          },
                );
                return;
        }
    }

    /**
     * Lets go of the client and reports where that leaves the login. Closing
     * its input tells the client the app has gone; one that has not left
     * after the grace period is killed.
     */
    private finish(child: ChildProcessWithoutNullStreams | null, state: LoginState): void {
        if (child !== null) {
            if (this.child !== child) {
                return;
            }
            this.child = null;
            this.waiting = null;
            child.stdin.end();
            if (child.exitCode === null && child.signalCode === null) {
                this.leaving.add(child);
                const timer = setTimeout(() => child.kill(), this.options.exitGraceMs);
                child.once("close", () => {
                    clearTimeout(timer);
                    this.leaving.delete(child);
                });
            }
        }
        this.options.onState(state);
    }
}
