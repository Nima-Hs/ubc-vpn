// Shared by the tests that run the app's bridge client against the mock
// bridge in `mock-bridge.mjs`.

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** One start of the mock bridge. See `mock-bridge.mjs` for what each field does. */
export interface MockRun {
    first?:
        | "ready"
        | "service_unavailable"
        | "update_needed"
        | "untrusted_service"
        | "not_owner"
        | "none"
        | "silent"
        | "raw";
    firstAfterMs?: number;
    raw?: string;
    exitAfterRaw?: boolean;
    serviceVersion?: string;
    ownerClaimed?: boolean;
    state?: unknown;
    firstEvent?: boolean;
    ignore?: string[];
    requestsRefusedAsNotOwner?: boolean;
    answerWithWrongId?: boolean;
    watchEarlyInput?: boolean;
    later?: { afterMs: number; state?: unknown; raw?: string; end?: string; exit?: number }[];
}

export interface MockBridge {
    /** What to give the client as `command` and `args`. */
    command: string;
    args: string[];
    /** How many times the bridge has been started. */
    starts(): number;
    /** What the bridge received, in order: request methods, "bad_line", "early". */
    received(): string[];
}

/** Scripts the mock bridge: each start takes the next run, and the last repeats. */
export function mockBridge(...runs: MockRun[]): MockBridge {
    const dir = mkdtempSync(join(tmpdir(), "ubc-vpn-bridge-"));
    const config = join(dir, "config.json");
    const counter = join(dir, "starts");
    const log = join(dir, "log");
    writeFileSync(config, JSON.stringify({ runs: runs.length > 0 ? runs : [{}], counter, log }));
    return {
        command: process.execPath,
        args: [join(__dirname, "mock-bridge.mjs"), "bridge", config],
        starts: () => (existsSync(counter) ? Number(readFileSync(counter, "utf8")) : 0),
        received: () =>
            existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean) : [],
    };
}

export async function until(
    condition: () => boolean,
    what: string,
    timeoutMs = 8000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!condition()) {
        if (Date.now() > deadline) {
            throw new Error(`timed out waiting for ${what}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
    }
}

export const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const TUNNEL = {
    interface: "utun4",
    address: "198.51.100.42",
    subnets: ["203.0.113.0/24"],
    dns_domains: ["campus.example"],
};
