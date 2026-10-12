// The app's bridge client, run against a mock bridge that follows the
// contract in `crates/core/src/bridge.rs`.

import { spawn } from "node:child_process";
import type { Event } from "@shared/protocol/Event";
import type { RequestBody } from "@shared/protocol/RequestBody";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
    Backoff,
    BridgeClient,
    BridgeError,
    type BridgeFault,
    type BridgeRequestBody,
    type BridgeStatus,
} from "../src/main/channel/bridge";
import { bridgeCommand } from "../src/main/channel/cli";
import {
    encodeLine,
    LineDecoder,
    LineTooLongError,
    MAX_LINE_BYTES,
} from "../src/main/channel/framing";
import { type MockBridge, type MockRun, mockBridge, pause, TUNNEL, until } from "./bridge-harness";

/** Obviously fake, and searched for wherever a secret must not turn up. */
const COOKIE = "not-a-real-cookie-0123456789";

const cleanups: (() => unknown)[] = [];

afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
        await cleanup();
    }
});

interface Harness {
    bridge: MockBridge;
    client: BridgeClient;
    statuses: BridgeStatus[];
    events: Event[];
    faults: BridgeFault[];
    last(): BridgeStatus["status"] | undefined;
}

function start(
    runs: MockRun[],
    options: {
        replyTimeoutMs?: number;
        maxRetryDelayMs?: number;
        initialRetryDelayMs?: number;
    } = {},
): Harness {
    const bridge = mockBridge(...runs);
    const statuses: BridgeStatus[] = [];
    const events: Event[] = [];
    const faults: BridgeFault[] = [];
    const client = new BridgeClient({
        command: bridge.command,
        args: bridge.args,
        onStatus: (status) => statuses.push(status),
        onEvent: (event) => events.push(event),
        onFault: (fault) => faults.push(fault),
        initialRetryDelayMs: 20,
        maxRetryDelayMs: 80,
        replyTimeoutMs: 3000,
        ...options,
    });
    cleanups.push(() => client.stop());
    client.start();
    return { bridge, client, statuses, events, faults, last: () => statuses.at(-1)?.status };
}

describe("starting the bridge", () => {
    it("runs the command-line client with the one argument 'bridge', and reports ready", async () => {
        const { bridge, last, statuses } = start([{ serviceVersion: "0.3.1", ownerClaimed: true }]);
        await until(() => last() === "ready", "ready");

        // The mock says nothing unless it was started as `<program> bridge`.
        expect(bridge.args[1]).toBe("bridge");
        expect(statuses[0]).toEqual({ status: "connecting" });
        expect(statuses.at(-1)).toEqual({
            status: "ready",
            serviceVersion: "0.3.1",
            ownerClaimed: true,
        });
    });

    it("writes nothing to the bridge before it says ready", async () => {
        const { bridge, client, last } = start([{ firstAfterMs: 150, watchEarlyInput: true }]);
        await expect(client.request({ method: "claim" })).rejects.toMatchObject({
            reason: "not_connected",
        });
        await until(() => last() === "ready", "ready");
        await client.request({ method: "status" });
        expect(bridge.received()).toEqual(["status"]);
    });

    it("reports a service that is not running, and starts another bridge after a pause", async () => {
        const { bridge, last, statuses } = start([{ first: "service_unavailable" }, {}]);
        await until(() => statuses.some((s) => s.status === "unavailable"), "unavailable");
        expect(statuses.find((s) => s.status === "unavailable")).toEqual({
            status: "unavailable",
            reason: "not_running",
        });
        await until(() => last() === "ready", "ready on the second start");
        expect(bridge.starts()).toBe(2);
    });

    it("treats an exit with no line as a service that is not running", async () => {
        const { last, statuses } = start([{ first: "none" }], {
            maxRetryDelayMs: 60_000,
            initialRetryDelayMs: 60_000,
        });
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "not_running" });
    });

    it("treats a client that cannot be started as a service that is not running", async () => {
        const statuses: BridgeStatus[] = [];
        const client = new BridgeClient({
            command: bridgeCommand({
                isPackaged: true,
                resourcesPath: "/nowhere/that/exists",
                platform: process.platform,
                env: {},
            }).command,
            args: ["bridge"],
            onStatus: (status) => statuses.push(status),
            onEvent: () => {},
            initialRetryDelayMs: 60_000,
        });
        cleanups.push(() => client.stop());
        client.start();
        await until(() => statuses.at(-1)?.status === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "not_running" });
    });

    it("reports 'update needed' with the service's version, and does not hammer", async () => {
        const { bridge, last, statuses } = start(
            [{ first: "update_needed", serviceVersion: "0.2.0" }],
            {
                maxRetryDelayMs: 60_000,
            },
        );
        await until(() => last() === "update_needed", "update_needed");
        expect(statuses.at(-1)).toEqual({ status: "update_needed", serviceVersion: "0.2.0" });
        await pause(200);
        expect(bridge.starts()).toBe(1);
    });

    it("reports something that is not the service, and does not hammer", async () => {
        const { bridge, client, last } = start([{ first: "untrusted_service" }], {
            maxRetryDelayMs: 60_000,
        });
        await until(() => last() === "untrusted_service", "untrusted_service");
        await expect(client.request({ method: "status" })).rejects.toMatchObject({
            reason: "not_connected",
        });
        await pause(200);
        expect(bridge.starts()).toBe(1);
    });

    it("reports another user's service, and never starts another bridge by itself", async () => {
        // Short pauses: if it were going to try again, it would have by now.
        const { bridge, client, last } = start([{ first: "not_owner" }], {
            initialRetryDelayMs: 10,
            maxRetryDelayMs: 20,
        });
        await until(() => last() === "not_owner", "not_owner");
        await pause(250);
        expect(bridge.starts()).toBe(1);
        expect(last()).toBe("not_owner");
        // Asking again by hand is still possible.
        client.retryNow();
        await until(() => bridge.starts() === 2, "a second start, on request");
    });

    it("treats a bridge that starts and says nothing as unusable", async () => {
        const { last, statuses } = start([{ first: "silent" }], { replyTimeoutMs: 150 });
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
    });

    it.each([
        ["not JSON", "this is not json\n"],
        ["an unknown line type", '{"type":"surprise"}\n'],
        ["ready with a field missing", '{"type":"ready","service_version":"0.1.0"}\n'],
        [
            "a service message before ready",
            '{"type":"server","message":{"type":"event","data":{"kind":"state_changed","value":{"state":"connecting"}}}}\n',
        ],
    ])("treats a first line that is %s as unusable", async (_name, raw) => {
        const { events, last, statuses } = start([{ first: "raw", raw }], {
            initialRetryDelayMs: 60_000,
        });
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
        expect(events).toEqual([]);
    });
});

describe("events and requests", () => {
    it("delivers the current state as the first event, then every change", async () => {
        const connected = { state: "connected", tunnel: TUNNEL };
        const { events, last } = start([
            { state: { state: "connecting" }, later: [{ afterMs: 60, state: connected }] },
        ]);
        await until(() => last() === "ready" && events.length === 2, "two events");
        expect(events).toEqual([
            { kind: "state_changed", value: { state: "connecting" } },
            { kind: "state_changed", value: connected },
        ]);
    });

    it("matches each response to its request by id", async () => {
        const { bridge, client, last } = start([{}]);
        await until(() => last() === "ready", "ready");
        const [claim, status, disconnect] = await Promise.all([
            client.request({ method: "claim" }),
            client.request({ method: "status" }),
            client.request({ method: "disconnect" }),
        ]);
        expect(claim).toEqual({ status: "ok", value: { kind: "claimed" } });
        expect(status).toEqual({
            status: "ok",
            value: { kind: "status", value: { state: "disconnected" } },
        });
        expect(disconnect).toEqual({ status: "ok", value: { kind: "accepted" } });
        expect(bridge.received()).toEqual(["claim", "status", "disconnect"]);
    });

    it("passes a refusal through as an outcome, not as a failure", async () => {
        const { client, last } = start([{ requestsRefusedAsNotOwner: true }]);
        await until(() => last() === "ready", "ready");
        await expect(client.request({ method: "disconnect" })).resolves.toEqual({
            status: "error",
            value: { code: "not_owner", message: "only the owner may do this" },
        });
    });

    it("replaces a bridge that never answers a request, so nothing waits on it for ever", async () => {
        const { bridge, client, last, statuses } = start([{ ignore: ["claim"] }, {}], {
            replyTimeoutMs: 200,
        });
        await until(() => last() === "ready", "ready");
        await expect(client.request({ method: "claim" })).rejects.toMatchObject({
            reason: "timeout",
        });
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
        await until(() => last() === "ready" && bridge.starts() === 2, "a new bridge");
        await expect(client.request({ method: "claim" })).resolves.toMatchObject({ status: "ok" });
    });

    it("treats an answer to a question it never asked as a broken bridge", async () => {
        const { client, last, statuses } = start([{ answerWithWrongId: true }], {
            initialRetryDelayMs: 60_000,
        });
        await until(() => last() === "ready", "ready");
        await expect(client.request({ method: "claim" })).rejects.toMatchObject({
            reason: "closed",
        });
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
    });

    it("cannot be made to send connect, and keeps nothing of the attempt", async () => {
        const { bridge, client, last } = start([{}]);
        await until(() => last() === "ready", "ready");
        const connect: RequestBody = {
            method: "connect",
            params: {
                cookie: COOKIE,
                gateway_addr: "192.0.2.1",
                routes: { subnets: ["203.0.113.0/24"], dns_domains: [] },
            },
        };
        // @ts-expect-error The type does not accept `connect`; this checks the guard behind it.
        const typed: BridgeRequestBody = connect;
        const error = await client.request(typed).catch((caught: unknown) => caught);

        expect(error).toBeInstanceOf(BridgeError);
        expect(error).toMatchObject({ reason: "not_allowed" });
        const failure = error as BridgeError;
        expect(`${failure.message} ${failure.stack} ${JSON.stringify(failure)}`).not.toContain(
            COOKIE,
        );
        // The bridge is still up, and never saw a connect.
        await client.request({ method: "status" });
        expect(bridge.received()).toEqual(["status"]);
    });
});

describe("when the bridge ends", () => {
    it("fails what was waiting, reports it, and starts another", async () => {
        const { bridge, client, events, last } = start([
            { ignore: ["status"], later: [{ afterMs: 150, end: "service_unavailable" }] },
            { state: { state: "login_needed" } },
        ]);
        await until(() => last() === "ready", "ready");
        const waiting = client.request({ method: "status" });
        await expect(waiting).rejects.toMatchObject({ reason: "closed" });

        await until(() => last() === "ready" && bridge.starts() === 2, "ready again");
        // A new bridge starts with the current state, as the first did.
        await until(
            () => events.at(-1)?.value.state === "login_needed",
            "the state after restarting",
        );
    });

    it("reports a line of its own that the bridge refused, without the line, and starts another", async () => {
        const { bridge, faults, last, statuses } = start([
            { later: [{ afterMs: 40, end: "bad_line" }] },
            {},
        ]);
        await until(() => faults.length === 1, "the fault");
        expect(faults).toEqual(["the bridge refused a line the app wrote"]);
        expect(
            statuses.some((s) => s.status === "unavailable" && s.reason === "protocol_error"),
        ).toBe(true);
        await until(() => last() === "ready" && bridge.starts() === 2, "a new bridge");
    });

    it("drops a bridge that sends a line longer than 64 KiB", async () => {
        const marker = "oversized-line-marker";
        const { events, last, statuses } = start(
            [
                {
                    later: [
                        { afterMs: 30, raw: `{"type":"${marker}${"x".repeat(MAX_LINE_BYTES)}"}\n` },
                    ],
                },
            ],
            { initialRetryDelayMs: 60_000 },
        );
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
        expect(events).toHaveLength(1);
        expect(JSON.stringify(statuses)).not.toContain(marker);
    });

    it("drops a bridge that sends a line that never ends", async () => {
        const { last } = start(
            [{ later: [{ afterMs: 30, raw: "x".repeat(MAX_LINE_BYTES + 1) }] }],
            {
                initialRetryDelayMs: 60_000,
            },
        );
        await until(() => last() === "unavailable", "unavailable");
    });

    it.each([
        [
            "an unknown state",
            '{"type":"server","message":{"type":"event","data":{"kind":"state_changed","value":{"state":"levitating"}}}}\n',
        ],
        [
            "an unknown error code",
            '{"type":"server","message":{"type":"event","data":{"kind":"state_changed","value":{"state":"failed","code":"gremlins","message":"m"}}}}\n',
        ],
        [
            "a tunnel with a missing field",
            '{"type":"server","message":{"type":"event","data":{"kind":"state_changed","value":{"state":"connected","tunnel":{"address":"198.51.100.1"}}}}}\n',
        ],
        ["a second ready", '{"type":"ready","service_version":"0.1.0","owner_claimed":true}\n'],
    ])("drops a bridge that sends %s", async (_name, raw) => {
        const { events, last, statuses } = start([{ later: [{ afterMs: 30, raw }] }], {
            initialRetryDelayMs: 60_000,
        });
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
        expect(events).toHaveLength(1);
    });

    it("stops starting bridges once stopped, and lets the last one go", async () => {
        const { bridge, client, last } = start([{ first: "service_unavailable" }], {
            initialRetryDelayMs: 30,
            maxRetryDelayMs: 30,
        });
        await until(() => bridge.starts() >= 2, "a restart");
        client.stop();
        await pause(60);
        const seen = bridge.starts();
        await pause(200);
        expect(bridge.starts()).toBe(seen);
        expect(last()).not.toBe("ready");
    });
});

describe("the pause between attempts", () => {
    it("doubles each time", () => {
        const backoff = new Backoff(20, 10_000);
        expect([backoff.take(), backoff.take(), backoff.take(), backoff.take()]).toEqual([
            20, 40, 80, 160,
        ]);
    });

    it("never passes its limit, however long this goes on", () => {
        const backoff = new Backoff(20, 80);
        const delays = Array.from({ length: 50 }, () => backoff.take());
        expect(Math.max(...delays)).toBe(80);
        expect(delays.slice(0, 4)).toEqual([20, 40, 80, 80]);
        expect(new Backoff(500, 80).take()).toBe(80);
    });

    it("starts over once a bridge is ready", () => {
        const backoff = new Backoff(20, 80);
        backoff.take();
        backoff.take();
        backoff.reset();
        expect(backoff.take()).toBe(20);
    });

    it("starts over in the client once a bridge has been ready", async () => {
        const down: MockRun = { first: "service_unavailable" };
        const { bridge, statuses } = start(
            [down, down, down, down, { later: [{ afterMs: 30, end: "service_unavailable" }] }, {}],
            { initialRetryDelayMs: 50, maxRetryDelayMs: 5000 },
        );
        // Four failures: pauses of 50, 100, 200 and 400 ms. The fifth start is ready.
        await until(() => statuses.at(-1)?.status === "ready", "ready", 10_000);
        await until(() => statuses.at(-1)?.status === "unavailable", "the bridge ending");
        const ended = Date.now();
        await until(() => bridge.starts() === 6, "the next start");
        // Back to 50 ms. Had the pauses carried on growing, it would be 800.
        expect(Date.now() - ended).toBeLessThan(600);
    });

    it("is what the client waits between attempts", async () => {
        const { bridge } = start([{ first: "service_unavailable" }], {
            initialRetryDelayMs: 40,
            maxRetryDelayMs: 160,
        });
        const started = Date.now();
        await until(() => bridge.starts() === 4, "four starts");
        // Pauses of 40, 80 and 160 ms come before the fourth start. With no
        // growth it would follow after 120.
        expect(Date.now() - started).toBeGreaterThanOrEqual(270);
    });
});

describe("secrets", () => {
    it("never writes a line anywhere, and never puts one in an error or a status", async () => {
        const writes: string[] = [];
        const record = (...args: unknown[]) => {
            writes.push(args.map(String).join(" "));
            return true;
        };
        for (const method of ["log", "info", "warn", "error", "debug"] as const) {
            vi.spyOn(console, method).mockImplementation(record);
        }
        vi.spyOn(process.stdout, "write").mockImplementation(record);
        vi.spyOn(process.stderr, "write").mockImplementation(record);

        // A valid line, then one that is not, each carrying the marker.
        const { faults, last, statuses } = start(
            [
                {
                    later: [
                        {
                            afterMs: 20,
                            state: { state: "failed", code: "internal", message: COOKIE },
                        },
                        { afterMs: 60, raw: `{"type":"server","cookie":"${COOKIE}"}\n` },
                    ],
                },
            ],
            { initialRetryDelayMs: 60_000 },
        );
        await until(() => last() === "unavailable", "unavailable");

        expect(JSON.stringify(statuses)).not.toContain(COOKIE);
        expect(JSON.stringify(faults)).not.toContain(COOKIE);
        expect(writes).toEqual([]);
    });
});

describe("where the command-line client is", () => {
    const installed = {
        isPackaged: true,
        resourcesPath: "/opt/UBC VPN/resources",
        platform: "linux" as const,
    };

    it("is the bundled client, by absolute path, started as 'bridge'", () => {
        expect(bridgeCommand({ ...installed, env: {} })).toEqual({
            command: "/opt/UBC VPN/resources/bin/ubc-vpn".replaceAll(
                "/",
                process.platform === "win32" ? "\\" : "/",
            ),
            args: ["bridge"],
        });
        const windows = bridgeCommand({ ...installed, platform: "win32", env: {} });
        expect(windows.command.endsWith("ubc-vpn.exe")).toBe(true);
    });

    it("cannot be redirected through the environment in an installed app", () => {
        const command = bridgeCommand({ ...installed, env: { UBC_VPN_CLI: "/tmp/evil" } }).command;
        expect(command).not.toContain("evil");
        expect(command).toBe(bridgeCommand({ ...installed, env: {} }).command);
    });

    it("can be pointed at a locally built client in development, as an absolute path", () => {
        const dev = { ...installed, isPackaged: false };
        expect(
            bridgeCommand({ ...dev, env: { UBC_VPN_CLI: "target/debug/ubc-vpn" } }).command,
        ).toMatch(/^(\/|[A-Za-z]:\\).*target[\\/]debug[\\/]ubc-vpn$/);
        // Unset or empty, it falls back to the bundled place.
        expect(bridgeCommand({ ...dev, env: { UBC_VPN_CLI: "" } })).toEqual(
            bridgeCommand({ ...dev, env: {} }),
        );
    });

    it("refuses a place that is not an absolute path, so PATH is never searched", () => {
        expect(() =>
            bridgeCommand({ ...installed, resourcesPath: "resources", env: {} }),
        ).toThrow();
    });
});

describe("the mock bridge follows the contract", () => {
    function run(
        bridge: MockBridge,
        input: string,
    ): Promise<{ lines: unknown[]; code: number | null }> {
        return new Promise((done) => {
            const child = spawn(bridge.command, bridge.args, { stdio: ["pipe", "pipe", "ignore"] });
            let out = "";
            child.stdout.on("data", (chunk: Buffer) => {
                out += chunk.toString("utf8");
            });
            child.on("close", (code) =>
                done({
                    lines: out
                        .split("\n")
                        .filter(Boolean)
                        .map((line) => JSON.parse(line)),
                    code,
                }),
            );
            child.stdin.on("error", () => {});
            child.stdin.end(input);
        });
    }

    it("answers connect itself with bad_request and carries on", async () => {
        const request = { id: 7, body: { method: "connect", params: { cookie: COOKIE } } };
        const { lines, code } = await run(
            mockBridge({ firstEvent: false }),
            `${JSON.stringify(request)}\n`,
        );
        expect(lines[1]).toMatchObject({
            type: "server",
            message: {
                type: "response",
                data: { id: 7, outcome: { status: "error", value: { code: "bad_request" } } },
            },
        });
        expect(JSON.stringify(lines)).not.toContain(COOKIE);
        // Standard input closed: it leaves with status 0 and no further line.
        expect(code).toBe(0);
    });

    it("answers a line that is not a request with bad_line, and exits", async () => {
        const { lines, code } = await run(
            mockBridge({ firstEvent: false }),
            `{"id":1,"body":{"method":"reboot"}}\n`,
        );
        expect(lines).toEqual([expect.objectContaining({ type: "ready" }), { type: "bad_line" }]);
        expect(code).toBe(1);
    });
});

describe("line framing", () => {
    it("accepts a line of exactly the limit and refuses one byte more", () => {
        const atLimit = Buffer.from(`${"a".repeat(MAX_LINE_BYTES - 1)}\n`);
        expect(new LineDecoder().push(atLimit)).toEqual(["a".repeat(MAX_LINE_BYTES - 1)]);
        const over = Buffer.from(`${"a".repeat(MAX_LINE_BYTES)}\n`);
        expect(() => new LineDecoder().push(over)).toThrow(LineTooLongError);
    });

    it("refuses an over-long line before its newline arrives", () => {
        const decoder = new LineDecoder();
        expect(decoder.push(Buffer.alloc(MAX_LINE_BYTES - 1, "a"))).toEqual([]);
        expect(() => decoder.push(Buffer.from("a"))).toThrow(LineTooLongError);
    });

    it("joins lines split across chunks, even inside a character", () => {
        const bytes = Buffer.from('{"name":"café"}\n{"n":2}\n');
        const cut = bytes.indexOf(0xc3) + 1;
        const decoder = new LineDecoder();
        expect(decoder.push(bytes.subarray(0, cut))).toEqual([]);
        expect(decoder.push(bytes.subarray(cut))).toEqual(['{"name":"café"}', '{"n":2}']);
    });

    it("does not put the line in its error", () => {
        const error = new LineTooLongError();
        expect(error.message).toBe("line is longer than 65536 bytes");
        expect(() => encodeLine({ cookie: COOKIE.repeat(4000) })).toThrow(error.message);
    });
});
