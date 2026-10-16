// Runs the command-line client for one answer: one line of input on its
// standard input, one line of output, then it exits. Used by the settings
// and the profiles commands alike, so the rules for a client that does not
// behave exist once.

import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { startClient } from "./bridge";
import { LineDecoder } from "./framing";

export interface OneLineOptions {
    /** The command-line client, as an absolute path. */
    command: string;
    /**
     * Put before the fixed arguments. Empty in the app, or `--dev` in dev
     * mode; tests use it to run a script.
     */
    leadingArgs?: readonly string[];
    /** How long one call may take before the client is ended. */
    timeoutMs?: number;
    /** The app's own environment, from which the client's short one is taken. */
    env?: Record<string, string | undefined>;
    /** Whether the client is started in dev mode; see `bridgeCommand`. */
    dev?: boolean;
}

/** The client's one line, parsed, and how it exited. */
export interface OneLine {
    status: number | null;
    value: unknown;
}

export class OneLineCalls {
    readonly options: Required<OneLineOptions>;
    /** Each client still running, with what ends it and its call at once. */
    private readonly running = new Map<ChildProcessWithoutNullStreams, () => void>();

    constructor(options: OneLineOptions) {
        this.options = {
            leadingArgs: [],
            timeoutMs: 10_000,
            env: process.env,
            dev: false,
            ...options,
        };
    }

    /** Ends every client still running, for when the app quits. */
    stop(): void {
        for (const end of [...this.running.values()]) {
            end();
        }
        this.running.clear();
    }

    /** Ends a client, and its call with it, whether or not the client goes. */
    end(child: ChildProcessWithoutNullStreams): void {
        this.running.get(child)?.();
    }

    /**
     * Runs the client once and returns its one line with its exit status, or
     * `null` if it did not behave: could not be started, ran out of time,
     * wrote nothing, more than one line, too much, or something unreadable.
     */
    run(
        args: readonly string[],
        input: Buffer | null,
        onStart?: (child: ChildProcessWithoutNullStreams) => void,
    ): Promise<OneLine | null> {
        return new Promise((answer) => {
            let child: ChildProcessWithoutNullStreams;
            try {
                child = startClient(
                    this.options.command,
                    [...this.options.leadingArgs, ...args],
                    this.options.env,
                    this.options.dev,
                );
            } catch {
                answer(null);
                return;
            }
            // Only the first answer counts: a client that was ended has none.
            const resolve = (result: OneLine | null) => {
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
