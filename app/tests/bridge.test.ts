// The app's bridge client, run against a mock bridge that follows the
// contract in `crates/core/src/bridge.rs`.

import { type SpawnOptions, spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Event } from "@shared/protocol/Event";
import type { RequestBody } from "@shared/protocol/RequestBody";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
    APP_METHODS,
    Backoff,
    BRIDGE_ENV,
    BridgeClient,
    BridgeError,
    type BridgeFault,
    type BridgeOptions,
    type BridgeRequestBody,
    type BridgeStatus,
    bridgeEnv,
    DEV_ENV,
} from "../src/main/channel/bridge";
import { bridgeCommand } from "../src/main/channel/cli";
import {
    encodeLine,
    LineDecoder,
    LineTooLongError,
    MAX_LINE_BYTES,
} from "../src/main/channel/framing";
import { isServerMessage } from "../src/main/channel/validate";
import { profileFolder } from "../src/main/user-data";
import {
    alive,
    type MockBridge,
    type MockRun,
    mockBridge,
    pause,
    TUNNEL,
    until,
} from "./bridge-harness";

/** Obviously fake, and searched for wherever a secret must not turn up. */
const COOKIE = "not-a-real-cookie-0123456789";

// The real `spawn`, watched: the tests below read how the bridge was started.
vi.mock("node:child_process", async (original) => {
    const actual = await original<typeof import("node:child_process")>();
    return { ...actual, spawn: vi.fn(actual.spawn) };
});

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
    options: Partial<
        Pick<
            BridgeOptions,
            | "startTimeoutMs"
            | "replyTimeoutMs"
            | "maxRetryDelayMs"
            | "initialRetryDelayMs"
            | "exitGraceMs"
            | "env"
            | "dev"
        >
    > = {},
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
        // Generous: a slow start of the mock must never look like a failure.
        startTimeoutMs: 20_000,
        replyTimeoutMs: 10_000,
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
            command: bridgeCommand(
                { isPackaged: true },
                { resourcesPath: "/nowhere/that/exists", platform: process.platform, env: {} },
            ).command,
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

    it("keeps the version it shows to the length of a real one", async () => {
        const { last, statuses } = start(
            [{ first: "update_needed", serviceVersion: `0.2.0-${"x".repeat(500)}` }],
            { maxRetryDelayMs: 60_000 },
        );
        await until(() => last() === "update_needed", "update_needed");
        expect(statuses.at(-1)).toEqual({
            status: "update_needed",
            serviceVersion: `0.2.0-${"x".repeat(26)}`,
        });
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

    it("treats the service's own 'not the owner' as final, though the bridge then reports it gone", async () => {
        // The channel was not reserved for the owner, so the bridge got
        // through. The service refuses the request and hangs up.
        const refusing: MockRun = { requestsRefusedAsNotOwner: true, hangsUpOnNonOwner: true };
        const { bridge, client, last, statuses } = start([refusing], {
            initialRetryDelayMs: 10,
            maxRetryDelayMs: 20,
        });
        await until(() => last() === "ready", "ready");
        await expect(client.request({ method: "claim" })).resolves.toEqual({
            status: "error",
            value: { code: "not_owner", message: "only the owner may do this" },
        });
        expect(last()).toBe("not_owner");

        // Short pauses: if it were going to try again, it would have by now.
        await pause(300);
        expect(bridge.starts()).toBe(1);
        expect(last()).toBe("not_owner");
        expect(statuses.some((status) => status.status === "unavailable")).toBe(false);
    });

    it("treats a bridge that starts and says nothing as unusable", async () => {
        const { last, statuses } = start([{ first: "silent" }], { startTimeoutMs: 150 });
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
                tunnel: "split",
            },
        };
        // @ts-expect-error The type does not accept `connect`; this checks the guard behind it.
        const typed: BridgeRequestBody = connect;
        // The type check fails here, too, if `add_log` ever becomes something
        // the app may send: an "expected error" that stops being one is an error.
        const addLog: RequestBody = { method: "add_log", params: { level: "info", text: "x" } };
        // @ts-expect-error The app has nothing to add to the service's log.
        const added: BridgeRequestBody = addLog;
        await expect(client.request(added)).rejects.toMatchObject({ reason: "not_allowed" });
        // What it may send is a list, not "everything but": a method the
        // protocol gains later is not allowed until it is put here.
        expect([...APP_METHODS]).toEqual([
            "claim",
            "status",
            "disconnect",
            "logs",
            "watch_logs",
            "diagnostics",
        ]);
        const unheard = { method: "summon_comet" } as unknown as BridgeRequestBody;
        await expect(client.request(unheard)).rejects.toMatchObject({ reason: "not_allowed" });
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
        await until(() => {
            const event = events.at(-1);
            return event?.kind === "state_changed" && event.value.state === "login_needed";
        }, "the state after restarting");
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

    it("refuses an answer of a kind it does not know, though it lets such an event by", () => {
        const answer = (value: unknown) => ({
            type: "response",
            data: { id: 1, outcome: { status: "ok", value } },
        });
        expect(isServerMessage(answer({ kind: "claimed" }))).toBe(true);
        expect(isServerMessage(answer({ kind: "status", value: { state: "disconnected" } }))).toBe(
            true,
        );
        for (const kind of ["comet_sighted", "constructor", "", 7, undefined]) {
            expect(isServerMessage(answer({ kind, value: {} })), String(kind)).toBe(false);
        }
        // The same unknown word on an event is let through, to be ignored.
        expect(isServerMessage({ type: "event", data: { kind: "comet_sighted" } })).toBe(true);
        // A connected state says its tunnel mode, one of the two.
        const connected = (tunnel: unknown) =>
            answer({ kind: "status", value: { state: "connected", tunnel } });
        expect(isServerMessage(connected(TUNNEL))).toBe(true);
        expect(isServerMessage(connected({ ...TUNNEL, mode: "full" }))).toBe(true);
        for (const mode of ["everything", "Full", "", undefined, true]) {
            expect(isServerMessage(connected({ ...TUNNEL, mode })), String(mode)).toBe(false);
        }
    });

    // Protocol 4 adds `not_connected`. Every code of the contract is taken;
    // one it does not know is a fault, which drops the bridge and shows
    // the general "could not make sense of the service" state (see "drops a
    // bridge that sends an unknown error code" below), never a crash.
    it("takes every error code of the contract, not_connected included, and only those", () => {
        const refusal = (code: unknown) => ({
            type: "response",
            data: { id: 1, outcome: { status: "error", value: { code, message: "made up" } } },
        });
        const failed = (code: unknown) => ({
            type: "event",
            data: { kind: "state_changed", value: { state: "failed", code, message: "made up" } },
        });
        for (const code of ["not_connected", "busy", "route_refused", "internal"]) {
            expect(isServerMessage(refusal(code)), code).toBe(true);
            expect(isServerMessage(failed(code)), code).toBe(true);
        }
        for (const code of ["gremlins", "constructor", "__proto__", "", 7, null, undefined]) {
            expect(isServerMessage(refusal(code)), String(code)).toBe(false);
            expect(isServerMessage(failed(code)), String(code)).toBe(false);
        }
    });

    it("ignores an event of a kind it does not know, and carries on as before", async () => {
        // A newer service may say things this app has no use for.
        const unknown = (value: unknown) =>
            `${JSON.stringify({
                type: "server",
                message: { type: "event", data: { kind: "comet_sighted", value } },
            })}\n`;
        const { bridge, client, events, statuses, last } = start([
            {
                later: [
                    { afterMs: 30, raw: unknown({ state: "connected" }) },
                    { afterMs: 40, raw: unknown("anything at all") },
                    {
                        afterMs: 50,
                        raw: '{"type":"server","message":{"type":"event","data":{"kind":"comet_sighted"}}}\n',
                    },
                    { afterMs: 80, state: { state: "login_needed" } },
                ],
            },
        ]);
        await until(() => events.length === 2, "the event it does know");
        // Nothing of the unknown ones was passed on, in any form.
        expect(events.map((event) => event.kind)).toEqual(["state_changed", "state_changed"]);
        expect(JSON.stringify(events)).not.toContain("comet");
        // The bridge was not taken for a broken one: it is the same bridge,
        // still ready, and it still answers.
        expect(last()).toBe("ready");
        expect(statuses.filter((status) => status.status === "unavailable")).toEqual([]);
        expect(bridge.starts()).toBe(1);
        await expect(client.request({ method: "status" })).resolves.toMatchObject({ status: "ok" });
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
        // An answer is to a request the app itself made, and it makes none
        // whose answer it cannot read. So, unlike an event, an answer of a
        // kind it does not know is a fault.
        [
            "an answer of a kind it does not know",
            '{"type":"server","message":{"type":"response","data":{"id":1,"outcome":{"status":"ok","value":{"kind":"comet_sighted","value":{}}}}}}\n',
        ],
        [
            "an event that does not say its kind",
            '{"type":"server","message":{"type":"event","data":{"value":1}}}\n',
        ],
        [
            "an event whose kind is not text",
            '{"type":"server","message":{"type":"event","data":{"kind":7,"value":1}}}\n',
        ],
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
            [
                down,
                down,
                down,
                down,
                down,
                down,
                { later: [{ afterMs: 30, end: "service_unavailable" }] },
                {},
            ],
            { initialRetryDelayMs: 50, maxRetryDelayMs: 5000 },
        );
        // Six failures: pauses of 50, 100, 200, 400, 800 and 1,600 ms. The
        // seventh start is ready.
        await until(() => statuses.at(-1)?.status === "ready", "ready", 15_000);
        await until(() => statuses.at(-1)?.status === "unavailable", "the bridge ending");
        const ended = Date.now();
        await until(() => bridge.starts() === 8, "the next start");
        // Back to 50 ms. Had the pauses carried on growing, it would be 3,200.
        // What is measured also includes starting the mock bridge, a Node
        // program, which on a busy machine takes hundreds of milliseconds:
        // the gap between the two answers is wide enough that this limit
        // leaves room on either side.
        expect(Date.now() - ended).toBeLessThan(1500);
    }, 30_000);

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
        const { client, faults, last, statuses } = start(
            [
                {
                    later: [
                        {
                            afterMs: 200,
                            state: { state: "failed", code: "internal", message: COOKIE },
                        },
                        { afterMs: 400, raw: `{"type":"server","cookie":"${COOKIE}"}\n` },
                    ],
                },
            ],
            { initialRetryDelayMs: 60_000 },
        );
        // Requests too: nothing sent is written anywhere either.
        await until(() => last() === "ready", "ready");
        await client.request({ method: "status" });
        await client.request({ method: "claim" });
        await until(() => last() === "unavailable", "unavailable");

        expect(JSON.stringify(statuses)).not.toContain(COOKIE);
        expect(JSON.stringify(faults)).not.toContain(COOKIE);
        expect(writes).toEqual([]);
    });
});

describe("where the command-line client is", () => {
    const resources = "/opt/UBC VPN/resources";
    const native = (path: string) =>
        path.replaceAll("/", process.platform === "win32" ? "\\" : "/");
    const command = (
        isPackaged: boolean,
        env: Record<string, string | undefined> = {},
        platform: NodeJS.Platform = "linux",
        resourcesPath = resources,
    ) => bridgeCommand({ isPackaged }, { resourcesPath, platform, env });

    it("is the bundled client, by absolute path, started as 'bridge'", () => {
        expect(command(true)).toEqual({
            command: native(`${resources}/bin/ubc-vpn`),
            args: ["bridge"],
            dev: false,
        });
        expect(command(true, {}, "win32").command.endsWith("ubc-vpn.exe")).toBe(true);
    });

    it("cannot be redirected through the environment in an installed app", () => {
        const redirected = command(true, { UBC_VPN_CLI: "/tmp/evil" }).command;
        expect(redirected).not.toContain("evil");
        expect(redirected).toBe(command(true).command);
    });

    it("can be pointed at a locally built client in development, as an absolute path", () => {
        expect(command(false, { UBC_VPN_CLI: "target/debug/ubc-vpn" }).command).toMatch(
            /^(\/|[A-Za-z]:\\).*target[\\/]debug[\\/]ubc-vpn$/,
        );
        // Unset or empty, it falls back to the bundled place.
        expect(command(false, { UBC_VPN_CLI: "" })).toEqual(command(false));
        expect(command(false)).toEqual(command(true));
    });

    it("is told to use dev mode only when the switch is exactly 1, and never when installed", () => {
        expect(command(false, { UBC_VPN_DEV: "1" })).toMatchObject({
            args: ["--dev", "bridge"],
            dev: true,
        });
        // Anything else leaves it off.
        for (const value of ["", "0", "true", "yes", "1 ", " 1", "11", undefined]) {
            expect(command(false, { UBC_VPN_DEV: value }), String(value)).toMatchObject({
                args: ["bridge"],
                dev: false,
            });
        }
        // An installed app cannot be turned away from the real service.
        expect(command(true, { UBC_VPN_DEV: "1" })).toEqual(command(true));
        expect(command(true, { UBC_VPN_DEV: "1" })).toMatchObject({ args: ["bridge"], dev: false });
    });

    it("refuses a place that is not an absolute path, so PATH is never searched", () => {
        expect(() => command(true, {}, "linux", "resources")).toThrow();
    });
});

describe("where the app keeps its own profile", () => {
    const CONFIG = join("/home/someone/.config");
    const HOME = join("/home/someone");
    // Electron's own answer for the settings parent; on Linux the app works
    // it out by the client's rule and does not ask.
    const electron = (isPackaged: boolean, appData = CONFIG) => ({
        isPackaged,
        getPath: (name: "appData" | "home") => (name === "home" ? HOME : appData),
    });
    const on = (platform: NodeJS.Platform, env: Record<string, string | undefined> = {}) => ({
        platform,
        env,
    });

    it("is a sub-folder named 'app' of the client's settings folder, when installed", () => {
        // The client's folder is "UBC VPN" on Windows and macOS and
        // "ubc-vpn" on Linux; settings.json sits directly in it.
        expect(profileFolder(electron(true), on("win32"))).toBe(join(CONFIG, "UBC VPN", "app"));
        expect(profileFolder(electron(true), on("darwin"))).toBe(join(CONFIG, "UBC VPN", "app"));
        expect(profileFolder(electron(true), on("linux"))).toBe(join(CONFIG, "ubc-vpn", "app"));
    });

    it("follows the client's rule for XDG_CONFIG_HOME on Linux, whatever Electron makes of it", () => {
        const packaged = (env: Record<string, string | undefined>, appData?: string) =>
            profileFolder(electron(true, appData), on("linux", env));
        // An absolute value is used.
        expect(packaged({ XDG_CONFIG_HOME: join("/srv/config") })).toBe(
            join("/srv/config", "ubc-vpn", "app"),
        );
        // A relative one is ignored, as the client ignores it, even where
        // Electron has taken it as given.
        for (const relative of ["config/here", "./config", "config", ""]) {
            expect(packaged({ XDG_CONFIG_HOME: relative }, relative), relative).toBe(
                join(HOME, ".config", "ubc-vpn", "app"),
            );
        }
        expect(packaged({})).toBe(join(HOME, ".config", "ubc-vpn", "app"));
        // The variable means nothing on the other two.
        expect(
            profileFolder(electron(true), on("darwin", { XDG_CONFIG_HOME: join("/srv/config") })),
        ).toBe(join(CONFIG, "UBC VPN", "app"));
    });

    it("is chosen before anything can use the profile: before the single-instance lock, and before the app is ready", () => {
        // On macOS and Linux the lock is a file in the profile folder. Set
        // after it, the lock would sit in the folder the app must keep out of.
        const source = readFileSync(join(__dirname, "..", "src", "main", "index.ts"), "utf8");
        const at = (text: string) => {
            const index = source.indexOf(text);
            expect(index, text).toBeGreaterThan(-1);
            return index;
        };
        const set = at('app.setPath("userData", profileFolder(app, process));');
        for (const later of ["requestSingleInstanceLock", "whenReady", "registerAppScheme("]) {
            expect(set, later).toBeLessThan(at(later));
        }
        // Nothing before it asks Electron for a path or its command line.
        expect(source.slice(0, set)).not.toMatch(/app\.(getPath|commandLine|on)\(/);
    });

    it("is never the folder that holds the user's settings file, on any OS, installed or not", () => {
        for (const platform of ["win32", "darwin", "linux"] as const) {
            for (const isPackaged of [true, false]) {
                const profile = profileFolder(electron(isPackaged), on(platform));
                expect(profile, `${platform} ${isPackaged}`).not.toMatch(/(UBC VPN|ubc-vpn)$/);
            }
        }
    });

    it("is outside the installed product's folders altogether, when not installed", () => {
        for (const platform of ["win32", "darwin", "linux"] as const) {
            const profile = profileFolder(electron(false), on(platform));
            expect(profile).toBe(join(CONFIG, "UBC VPN App Dev"));
            // Nor is it the folder dev mode keeps its own files in.
            expect(profile).not.toMatch(/UBC VPN Dev$/);
        }
    });

    it("is where the variable says, as an absolute path, when not installed", () => {
        const profile = profileFolder(
            electron(false),
            on("linux", { UBC_VPN_PROFILE: "some/folder" }),
        );
        expect(profile).toMatch(/^(\/|[A-Za-z]:\\).*some[\\/]folder$/);
        expect(profileFolder(electron(false), on("linux", { UBC_VPN_PROFILE: "" }))).toBe(
            profileFolder(electron(false), on("linux")),
        );
    });

    it("leaves the settings file to the client: the app's own code writes no file at all", () => {
        // The one use of the file system in the app is reading its own
        // interface files to serve them. Nothing can create, read or write
        // settings.json, in the profile folder or anywhere else.
        const root = join(__dirname, "..", "src");
        const users = (readdirSync(root, { recursive: true }) as string[])
            .filter((name) => /\.tsx?$/.test(name))
            .filter((name) =>
                /["']node:fs|["']fs["']|require\(/.test(readFileSync(join(root, name), "utf8")),
            )
            .map((name) => name.replaceAll("\\", "/"));
        expect(users).toEqual(["main/security.ts"]);
        const imports = readFileSync(join(root, "main/security.ts"), "utf8").match(
            /import \{([^}]*)\} from "node:fs[^"]*"/g,
        );
        expect(imports).toEqual(['import { readFile } from "node:fs/promises"']);
    });

    it("cannot be moved through the environment in an installed app", () => {
        expect(
            profileFolder(electron(true), on("linux", { UBC_VPN_PROFILE: "/tmp/elsewhere" })),
        ).toBe(profileFolder(electron(true), on("linux")));
    });
});

describe("how the bridge is started", () => {
    it("gets a short environment of its own, not the app's", async () => {
        const { bridge, last } = start([{ reportStart: true }], {
            env: {
                ...process.env,
                UBC_VPN_TEST_MARKER: "must not reach the bridge",
                UBC_VPN_CLI: "/tmp/evil",
                NODE_OPTIONS: "--no-warnings",
                HOME: "/home/someone",
            },
        });
        await until(() => last() === "ready", "ready");
        const names = (bridge.received().find((entry) => entry.startsWith("env:")) ?? "")
            .slice(4)
            .split(",")
            .map((name) => name.toUpperCase());

        expect(names).toContain("HOME");
        for (const leaked of ["UBC_VPN_TEST_MARKER", "UBC_VPN_CLI", "NODE_OPTIONS"]) {
            expect(names, leaked).not.toContain(leaked);
        }
        // Nothing reaches it that is not on the list, with one exception the
        // app cannot avoid: Windows will not start a process without a few
        // variables of its own, so Node copies those in when they are left out.
        const fromTheSystem =
            process.platform === "win32"
                ? [
                      "HOMEDRIVE",
                      "HOMEPATH",
                      "LOGONSERVER",
                      "PATH",
                      "SYSTEMDRIVE",
                      "USERDOMAIN",
                      "USERNAME",
                      "WINDIR",
                  ]
                : ["__CF_USER_TEXT_ENCODING"];
        const allowed = [...BRIDGE_ENV.map((name) => name.toUpperCase()), ...fromTheSystem];
        expect(names.filter((name) => !allowed.includes(name))).toEqual([]);
        if (process.platform !== "win32") {
            expect(names).not.toContain("PATH");
        }
    });

    it("passes on where a dev-mode service listens only in dev mode", async () => {
        const env = { HOME: "/home/someone", XDG_RUNTIME_DIR: "/run/user/1000", TMPDIR: "/tmp/x" };
        expect(bridgeEnv(env)).toEqual({ HOME: "/home/someone" });
        expect(bridgeEnv(env, true)).toEqual(env);
        expect(bridgeEnv({ ...env, SECRET_TOKEN: "x" }, true)).toEqual(env);
        expect(DEV_ENV).toEqual(["XDG_RUNTIME_DIR", "TMPDIR"]);
        // And that is what the bridge is really started with.
        const spawned = vi.mocked(spawn);
        for (const dev of [false, true]) {
            spawned.mockClear();
            const { last } = start([{}], { env: { ...process.env, ...env }, dev });
            await until(() => last() === "ready", "ready");
            const [, , options] = spawned.mock.calls.at(-1) as [string, string[], SpawnOptions];
            expect(Object.keys(options.env ?? {}).includes("XDG_RUNTIME_DIR"), String(dev)).toBe(
                dev,
            );
        }
    });

    it("keeps only the listed variables, and only those that are set", () => {
        expect(bridgeEnv({ HOME: "/home/someone", SECRET_TOKEN: "x", APPDATA: undefined })).toEqual(
            {
                HOME: "/home/someone",
            },
        );
        expect(bridgeEnv({})).toEqual({});
    });

    it("works in the client's own folder, wherever the app was started from", async () => {
        const { bridge, last } = start([{ reportStart: true }]);
        await until(() => last() === "ready", "ready");
        const cwd = bridge
            .received()
            .find((entry) => entry.startsWith("cwd:"))
            ?.slice(4);
        expect(realpathSync(cwd ?? "")).toBe(realpathSync(dirname(bridge.command)));
        expect(realpathSync(cwd ?? "")).not.toBe(realpathSync(process.cwd()));
    });

    it("never shows or reads what the bridge writes to standard error", async () => {
        const spawned = vi.mocked(spawn);
        spawned.mockClear();
        const { last } = start([{ stderr: "bridge-stderr-marker" }]);
        await until(() => last() === "ready", "ready");

        const options = spawned.mock.calls.at(-1)?.[2] as SpawnOptions;
        // Discarded: not inherited, where it would land in the app's own
        // output, and not piped, where the app would hold it.
        expect(options.stdio).toEqual(["pipe", "pipe", "ignore"]);
        expect(spawned.mock.results.at(-1)?.value.stderr).toBeNull();
    });

    it("is started without a shell", async () => {
        const spawned = vi.mocked(spawn);
        spawned.mockClear();
        const { bridge, last } = start([{}]);
        await until(() => last() === "ready", "ready");
        const [command, args, options] = spawned.mock.calls.at(-1) as [
            string,
            string[],
            SpawnOptions,
        ];
        expect(command).toBe(bridge.command);
        expect(args).toEqual(bridge.args);
        expect(options.shell).toBe(false);
        expect(options.windowsHide).toBe(true);
    });

    it("survives a client file that is there but is not a program", async () => {
        // On Windows starting this throws outright; elsewhere it fails a
        // moment later. Either way the app carries on and tries again.
        const dir = mkdtempSync(join(tmpdir(), "ubc-vpn-not-a-program-"));
        const notAProgram = join(dir, process.platform === "win32" ? "ubc-vpn.exe" : "ubc-vpn");
        writeFileSync(notAProgram, "this is a text file, not a program\n");

        const statuses: BridgeStatus[] = [];
        const client = new BridgeClient({
            command: notAProgram,
            args: ["bridge"],
            onStatus: (status) => statuses.push(status),
            onEvent: () => {},
            initialRetryDelayMs: 20,
            maxRetryDelayMs: 40,
        });
        cleanups.push(() => client.stop());
        expect(() => client.start()).not.toThrow();

        // Reported, and tried again from the retry timer without bringing
        // anything down.
        const failures = () => statuses.filter((status) => status.status === "unavailable").length;
        await until(() => failures() >= 3, "three failed starts");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "not_running" });
        await expect(client.request({ method: "status" })).rejects.toMatchObject({
            reason: "not_connected",
        });
    });
});

describe("the bridge process does not outlive its use", () => {
    it("is told the app has gone by its input closing, and leaves by itself", async () => {
        const { bridge, last } = start([{ later: [{ afterMs: 30, raw: "not json\n" }] }], {
            initialRetryDelayMs: 60_000,
            exitGraceMs: 60_000,
        });
        await until(() => last() === "unavailable", "the bridge being dropped");
        // Not killed (the grace period is a minute): it left because its input closed.
        await until(() => bridge.received().includes("input closed"), "its input closing");
        const [pid = 0] = bridge.pids();
        await until(() => !alive(pid), "the bridge leaving");
    });

    it("is killed if it does not leave when its input closes", async () => {
        const { bridge, last } = start(
            [{ staysAfterInputCloses: true, later: [{ afterMs: 30, raw: "not json\n" }] }],
            { initialRetryDelayMs: 60_000, exitGraceMs: 150 },
        );
        await until(() => last() === "unavailable", "the bridge being dropped");
        const [pid = 0] = bridge.pids();
        expect(alive(pid)).toBe(true);
        await until(() => !alive(pid), "the bridge being killed");
    });

    it("is ended when the app stops even if it was let go a moment before", async () => {
        // Dropped, and given a minute to leave, which it will not do. The
        // timer that would kill it would die with the app, so stopping must.
        const { bridge, client, last } = start(
            [{ staysAfterInputCloses: true, later: [{ afterMs: 30, raw: "not json\n" }] }],
            { initialRetryDelayMs: 60_000, exitGraceMs: 60_000 },
        );
        await until(() => last() === "unavailable", "the bridge being dropped");
        await until(() => bridge.received().includes("input closed"), "its input closing");
        const [pid = 0] = bridge.pids();
        expect(alive(pid)).toBe(true);
        client.stop();
        await until(() => !alive(pid), "the bridge ending", 3000);
    });

    it("is ended at once when the app stops, even one that would not leave", async () => {
        const { bridge, client, last } = start([{ staysAfterInputCloses: true }], {
            exitGraceMs: 60_000,
        });
        await until(() => last() === "ready", "ready");
        const [pid = 0] = bridge.pids();
        expect(alive(pid)).toBe(true);
        client.stop();
        await until(() => !alive(pid), "the bridge ending", 3000);
    });
});

describe("no bridge is started without its pause", () => {
    it("waits before replacing a bridge that failed", async () => {
        const { bridge, last } = start([{ first: "none" }], {
            initialRetryDelayMs: 500,
            maxRetryDelayMs: 500,
        });
        await until(() => last() === "unavailable", "unavailable");
        await pause(200);
        expect(bridge.starts()).toBe(1);
        await until(() => bridge.starts() === 2, "the second start");
    });

    it("waits before trying again when the client could not be started at all", async () => {
        const spawned = vi.mocked(spawn);
        spawned.mockClear();
        // What Windows does for a file that is there but is not a program.
        spawned.mockImplementationOnce(() => {
            throw new Error("spawn UNKNOWN");
        });
        const { last, statuses } = start([{}], { initialRetryDelayMs: 500, maxRetryDelayMs: 500 });
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "not_running" });
        await pause(200);
        expect(spawned).toHaveBeenCalledTimes(1);
        await until(() => spawned.mock.calls.length === 2, "the second attempt");
        await until(() => last() === "ready", "ready");
    });

    it("waits the longest pause before checking again on something that is not the service", async () => {
        const { bridge, last } = start([{ first: "untrusted_service" }], {
            initialRetryDelayMs: 10,
            maxRetryDelayMs: 500,
        });
        await until(() => last() === "untrusted_service", "untrusted_service");
        await pause(200);
        expect(bridge.starts()).toBe(1);
        await until(() => bridge.starts() === 2, "the second start");
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
        const request = {
            id: 7,
            body: {
                method: "connect",
                params: {
                    cookie: COOKIE,
                    gateway_addr: "192.0.2.1",
                    routes: { subnets: ["203.0.113.0/24"], dns_domains: [] },
                    tunnel: "split",
                },
            },
        };
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

    it("answers a connect that is not well formed with bad_line, like any bad request", async () => {
        const request = { id: 7, body: { method: "connect", params: { cookie: COOKIE } } };
        const { lines, code } = await run(
            mockBridge({ firstEvent: false }),
            `${JSON.stringify(request)}\n`,
        );
        expect(lines).toEqual([expect.objectContaining({ type: "ready" }), { type: "bad_line" }]);
        expect(JSON.stringify(lines)).not.toContain(COOKIE);
        expect(code).toBe(1);
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
