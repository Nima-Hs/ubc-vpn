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
//
// What a view holds comes from a file the user, or anything running as the
// user, can edit. Its text is cleaned here, as text from a login is, before
// the interface is given it.

import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { SettingsResult } from "@shared/api";
import type { RouteInput } from "@shared/protocol/RouteInput";
import type { RouteSet } from "@shared/protocol/RouteSet";
import type { RoutesReply } from "@shared/protocol/RoutesReply";
import type { SettingsView } from "@shared/protocol/SettingsView";
import { startClient } from "./bridge";
import { markedText, plainText } from "./connect";
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

/** The longest a username or a route from the client may be when shown. */
export const MAX_SHOWN_LENGTH = 512;

const shown = (text: string): string => plainText(text, MAX_SHOWN_LENGTH);

// The user edits these and sends them back, so what is removed leaves a
// mark: a stored entry that is not what it seems must not pass for a good
// one. Entries are never dropped: a problem names an entry by where it is
// in its list.
const marked = (text: string): string => markedText(text, MAX_SHOWN_LENGTH);
const shownRoutes = (routes: RouteSet): RouteSet => ({
    subnets: routes.subnets.map(marked),
    dns_domains: routes.dns_domains.map(marked),
});

function shownView(view: SettingsView): SettingsView {
    const { username, routes } = view.settings;
    return {
        ...view,
        settings: {
            ...view.settings,
            username: username === null ? null : shown(username),
            routes: shownRoutes(routes),
        },
        allowed_routes: view.allowed_routes?.map(shown) ?? null,
    };
}

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
    /** Each client still running, with what ends it and its call at once. */
    private readonly running = new Map<ChildProcessWithoutNullStreams, () => void>();
    private reading: Promise<SettingsResult<SettingsView>> | null = null;
    private saving = false;
    private checking: ChildProcessWithoutNullStreams | null = null;

    constructor(options: SettingsOptions) {
        this.options = { leadingArgs: [], timeoutMs: 10_000, env: process.env, ...options };
    }

    getSettings(): Promise<SettingsResult<SettingsView>> {
        // Everyone who asks while one read is under way shares its answer,
        // so asking in a stream cannot start clients in a stream.
        this.reading ??= this.read().finally(() => {
            this.reading = null;
        });
        return this.reading;
    }

    private async read(): Promise<SettingsResult<SettingsView>> {
        const line = await this.run(SETTINGS_ARGS.get, null);
        if (line === null) {
            return UNAVAILABLE;
        }
        if (line.status === 0 && isSettingsView(line.value)) {
            return { ok: true, value: shownView(line.value) };
        }
        return failureOf(line);
    }

    async checkRoutes(input: RouteInput): Promise<SettingsResult<RoutesReply>> {
        // Only the newest check matters, and none may pile up behind it.
        if (this.checking !== null) {
            this.end(this.checking);
        }
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
        for (const end of [...this.running.values()]) {
            end();
        }
        this.running.clear();
    }

    /** Ends a client, and its call with it, whether or not the client goes. */
    private end(child: ChildProcessWithoutNullStreams): void {
        this.running.get(child)?.();
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
            const reply = line.value;
            return {
                ok: true,
                value:
                    reply.type === "ok" ? { ...reply, routes: shownRoutes(reply.routes) } : reply,
            };
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
        return new Promise((answer) => {
            let child: ChildProcessWithoutNullStreams;
            try {
                child = startClient(
                    this.options.command,
                    [...this.options.leadingArgs, ...args],
                    this.options.env,
                );
            } catch {
                answer(null);
                return;
            }
            // Only the first answer counts: a client that was ended has none.
            const resolve = (result: { status: number | null; value: unknown } | null) => {
                clearTimeout(timer);
                answer(result);
            };
            // Ending does not wait for the client to go. One that ignores
            // being killed would otherwise hold its call, and with it a
            // save, for ever.
            this.running.set(child, () => {
                child.kill();
                resolve(null);
            });
            onStart?.(child);
            const decoder = new LineDecoder();
            const lines: string[] = [];
            const timer = setTimeout(() => this.end(child), this.options.timeoutMs);

            child.stdout.on("data", (chunk: Buffer) => {
                try {
                    lines.push(...decoder.push(chunk));
                } catch {
                    this.end(child);
                }
            });
            child.on("error", () => {});
            child.stdin.on("error", () => {});
            child.once("close", (status) => {
                this.running.delete(child);
                // Exactly one whole line, and nothing after it.
                const [text] = lines;
                if (lines.length !== 1 || text === undefined || decoder.hasPartial()) {
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
