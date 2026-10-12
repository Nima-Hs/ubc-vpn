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
//
// The client's last line is the truth about a login, not what the app last
// sent. A cancel can arrive after the service has already been asked to
// connect; the client then ends with `done`. So after sending a cancel the
// app keeps reading until the last line, and if the request reached the
// service, or may have, it asks the service to disconnect.

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
    /**
     * Asks the service, through the bridge, to disconnect. Called when a
     * login the user gave up was accepted by the service all the same, or
     * may have been. Asking is harmless when nothing is connected.
     */
    disconnect(): Promise<unknown>;
    /**
     * How long a client has to give its last line after a cancel, and to
     * leave once the app has let go of it, before it is killed.
     */
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
// paragraph separators. The zero-width joiner and non-joiner are not here:
// Persian needs the one and joined emoji the other.
const UNSAFE_IN_TEXT = /[\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]+/gu;

/**
 * Text from the gateway or the client, made safe to show: one line of plain
 * characters, kept to a sensible length. Without this a message could draw
 * itself backwards, or push the real question off the screen with newlines.
 */
export function plainText(text: string, maxLength: number): string {
    return cut(text.replace(UNSAFE_IN_TEXT, " ").replace(/ {2,}/g, " ").trim(), maxLength);
}

/**
 * Text the user will edit and send back, such as a stored route. What
 * cannot be shown is not taken away quietly: U+FFFD stands in its place, and
 * nothing is trimmed. An entry that is not what it seems then looks wrong,
 * and is refused when it is checked, instead of passing for a good one.
 */
export function markedText(text: string, maxLength: number): string {
    return cut(text.replace(UNSAFE_IN_TEXT, "\ufffd"), maxLength);
}

function cut(clean: string, maxLength: number): string {
    if (clean.length <= maxLength) {
        return clean;
    }
    // Cut between whole characters as a reader sees them, so the limit never
    // leaves half of a two-part character or half of a joined emoji.
    let kept = "";
    for (const { segment } of new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(
        clean,
    )) {
        if (kept.length + segment.length > maxLength) {
            break;
        }
        kept += segment;
    }
    return kept;
}

/** What a question is called when the gateway's own label comes to nothing. */
export const FALLBACK_LABEL = "Answer";

const IDLE: LoginState = { phase: "idle" };
const WORKING: LoginState = { phase: "working" };
const CANCEL: AppMessage = { type: "cancel" };
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
    /**
     * Running from the moment the client is told to cancel until its last
     * line: how long it has to give one. While this is set the app does not
     * know whether the service was asked to connect.
     */
    private cancelling: NodeJS.Timeout | null = null;
    /** A disconnect after a cancel is on its way to the service. */
    private settling = false;
    private readonly leaving = new Set<ChildProcessWithoutNullStreams>();
    /** When the client was last started, and the wait before the next start, if one is on. */
    private lastStartAt = Number.NEGATIVE_INFINITY;
    private startTimer: NodeJS.Timeout | null = null;

    constructor(options: ConnectOptions) {
        this.options = { exitGraceMs: 2_000, env: process.env, minStartGapMs: 3_000, ...options };
    }

    start(): boolean {
        // One login at a time: a second would mean a second MFA request.
        // Nor does one start while the last is still being wound up.
        if (this.child !== null || this.startTimer !== null || this.settling) {
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
                this.finish(child, BROKEN, true);
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
        child.once("close", () => this.finish(child, BROKEN, true));
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
        if (child === null) {
            // Nothing is running: a failure is dismissed, or a start called off.
            if (!this.settling) {
                this.options.onState(IDLE);
            }
            return;
        }
        if (this.cancelling !== null) {
            return;
        }
        this.waiting = null;
        child.stdin.write(encodeLine(CANCEL));
        // Its input stays open: the client takes a closed input as a cancel
        // too, and its last line is still to come.
        this.cancelling = setTimeout(() => {
            child.kill();
            this.finish(child, BROKEN, true);
        }, this.options.exitGraceMs);
        this.options.onState(WORKING);
    }

    stop(): void {
        if (this.startTimer !== null) {
            clearTimeout(this.startTimer);
            this.startTimer = null;
        }
        const child = this.child;
        if (child !== null) {
            // The app is quitting: there is no time to wait for a last line.
            if (this.cancelling === null) {
                child.stdin.write(encodeLine(CANCEL));
            } else {
                clearTimeout(this.cancelling);
                this.cancelling = null;
            }
            this.finish(child, IDLE);
        }
        for (const child of this.leaving) {
            child.kill();
        }
        this.leaving.clear();
    }

    private onLine(child: ChildProcessWithoutNullStreams, line: unknown): void {
        if (!isCliMessage(line)) {
            this.finish(child, BROKEN, true);
            return;
        }
        switch (line.type) {
            case "prompt": {
                // Asked before the client read the cancel. Nobody will answer.
                if (this.cancelling !== null) {
                    return;
                }
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
                    // A label that was nothing but characters the app removes
                    // would leave a field with no name.
                    label: plainText(line.label, MAX_LABEL) || FALLBACK_LABEL,
                    ...(line.message !== undefined && {
                        message: plainText(line.message, MAX_MESSAGE),
                    }),
                };
                this.options.onState({ phase: "prompt", prompt });
                return;
            }
            case "done":
                // The connection's progress now arrives from the service.
                this.finish(child, IDLE, true);
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
     *
     * `reached` says the service was asked to connect, or that the app cannot
     * tell: every ending but an `error` line. It matters only for a login
     * the user gave up, which then ends with a disconnect, and shows as
     * given up only once that has been sent.
     */
    private finish(
        child: ChildProcessWithoutNullStreams,
        state: LoginState,
        reached = false,
    ): void {
        let cancelled = false;
        if (this.child !== child) {
            return;
        }
        this.child = null;
        this.waiting = null;
        if (this.cancelling !== null) {
            clearTimeout(this.cancelling);
            this.cancelling = null;
            cancelled = true;
        }
        child.stdin.end();
        if (child.exitCode === null && child.signalCode === null) {
            this.leaving.add(child);
            const timer = setTimeout(() => child.kill(), this.options.exitGraceMs);
            child.once("close", () => {
                clearTimeout(timer);
                this.leaving.delete(child);
            });
        }
        if (!cancelled) {
            this.options.onState(state);
        } else if (!reached) {
            this.options.onState(IDLE);
        } else {
            this.settling = true;
            const settled = () => {
                this.settling = false;
                this.options.onState(IDLE);
            };
            // Whatever the answer, the service's own state says what is so.
            Promise.resolve()
                .then(() => this.options.disconnect())
                .then(settled, settled);
        }
    }
}
