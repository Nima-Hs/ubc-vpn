import type { Event } from "@shared/protocol/Event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChannelClient, ChannelError, type ChannelStatus } from "../src/main/channel/client";
import {
    encodeLine,
    LineDecoder,
    LineTooLongError,
    MAX_LINE_BYTES,
} from "../src/main/channel/framing";
import { MockService, TUNNEL, uniqueChannelPath } from "./mock-service";

/** Obviously fake, and searched for wherever a secret must not turn up. */
const COOKIE = "not-a-real-cookie-0123456789";

async function until(condition: () => boolean, what: string, timeoutMs = 4000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!condition()) {
        if (Date.now() > deadline) {
            throw new Error(`timed out waiting for ${what}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
    }
}

interface Harness {
    client: ChannelClient;
    statuses: ChannelStatus[];
    events: Event[];
    last(): ChannelStatus["status"] | undefined;
}

const cleanups: (() => unknown)[] = [];

function connectTo(
    path: string,
    options: { replyTimeoutMs?: number; maxRetryDelayMs?: number } = {},
): Harness {
    const statuses: ChannelStatus[] = [];
    const events: Event[] = [];
    const client = new ChannelClient({
        path,
        clientVersion: "0.1.0",
        onStatus: (status) => statuses.push(status),
        onEvent: (event) => events.push(event),
        initialRetryDelayMs: 20,
        maxRetryDelayMs: 80,
        replyTimeoutMs: 1000,
        ...options,
    });
    cleanups.push(() => client.stop());
    client.start();
    return { client, statuses, events, last: () => statuses.at(-1)?.status };
}

async function startService(configure?: (service: MockService) => void): Promise<MockService> {
    const service = new MockService();
    configure?.(service);
    await service.start();
    cleanups.push(() => service.stop());
    return service;
}

afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
        await cleanup();
    }
});

describe("the handshake", () => {
    it("sends Hello first, as protocol version 2 from the app", async () => {
        const service = await startService();
        const { last, statuses } = connectTo(service.path);
        await until(() => last() === "ready", "ready");

        expect(service.received[0]).toEqual({
            protocol_version: 2,
            client: "app",
            client_version: "0.1.0",
        });
        expect(statuses[0]).toEqual({ status: "connecting" });
        expect(statuses.at(-1)).toEqual({
            status: "ready",
            hello: { protocol_version: 2, service_version: "0.1.0", owner_claimed: false },
        });
    });

    it("reports a version mismatch as 'update needed' and backs off", async () => {
        const service = await startService((s) => {
            s.protocolVersion = 3;
            s.serviceVersion = "0.2.0";
        });
        const { client, last, statuses } = connectTo(service.path, { maxRetryDelayMs: 60_000 });
        await until(() => last() === "update_needed", "update_needed");

        expect(statuses.at(-1)).toEqual({ status: "update_needed", serviceVersion: "0.2.0" });
        await expect(client.request({ method: "status" })).rejects.toMatchObject({
            reason: "not_connected",
        });
        // It does not hammer a service it cannot talk to.
        await new Promise((resolve) => setTimeout(resolve, 150));
        expect(service.connections).toBe(1);
        expect(last()).toBe("update_needed");
    });

    it("still reports 'update needed' when the other version's reply has another shape", async () => {
        // A future service might rename or drop every field but the version.
        const service = await startService((s) => {
            s.helloReplyOverride = '{"protocol_version":9,"build":{"number":41}}\n';
        });
        const { last, statuses } = connectTo(service.path, { maxRetryDelayMs: 60_000 });
        await until(() => last() === "update_needed", "update_needed");
        expect(statuses.at(-1)).toEqual({ status: "update_needed", serviceVersion: "" });
    });

    it("treats a service that accepts and says nothing as unusable", async () => {
        const service = await startService((s) => {
            s.silent = true;
        });
        const { last, statuses } = connectTo(service.path, { replyTimeoutMs: 60 });
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
    });
});

describe("events and requests", () => {
    it("delivers the current state as the first event, then every change", async () => {
        const service = await startService((s) => {
            s.state = { state: "connecting" };
        });
        const { events, last } = connectTo(service.path);
        await until(() => last() === "ready" && events.length === 1, "first event");
        expect(events[0]).toEqual({ kind: "state_changed", value: { state: "connecting" } });

        service.setState({ state: "connected", tunnel: TUNNEL });
        await until(() => events.length === 2, "second event");
        expect(events[1]).toEqual({
            kind: "state_changed",
            value: { state: "connected", tunnel: TUNNEL },
        });
    });

    it("matches each response to its request by id", async () => {
        const service = await startService();
        const { client, last } = connectTo(service.path);
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

        const ids = service.received.slice(1).map((request) => (request as { id: number }).id);
        expect(new Set(ids).size).toBe(3);
    });

    it("passes a refusal through as an outcome, not as a failure", async () => {
        const service = await startService((s) => {
            s.ownedByAnother = true;
        });
        const { client, last } = connectTo(service.path);
        await until(() => last() === "ready", "ready");
        await expect(client.request({ method: "disconnect" })).resolves.toEqual({
            status: "error",
            value: { code: "not_owner", message: "only the owner may do this" },
        });
    });

    it("gives up on a request the service never answers", async () => {
        const service = await startService((s) => {
            s.ignoreRequests = true;
        });
        const { client, last } = connectTo(service.path, { replyTimeoutMs: 60 });
        await until(() => last() === "ready", "ready");
        await expect(client.request({ method: "status" })).rejects.toMatchObject({
            reason: "timeout",
        });
    });

    it("refuses to send a request longer than the line limit", async () => {
        const service = await startService();
        const { client, last } = connectTo(service.path);
        await until(() => last() === "ready", "ready");
        const request = client.request({
            method: "connect",
            params: {
                cookie: "x".repeat(MAX_LINE_BYTES),
                gateway_addr: "192.0.2.1",
                routes: { subnets: [], dns_domains: [] },
            },
        });
        await expect(request).rejects.toMatchObject({ reason: "too_long" });
        expect(service.received).toHaveLength(1);
    });
});

describe("what the service sends is not trusted", () => {
    it("drops the connection on a line longer than 64 KiB", async () => {
        const marker = "oversized-line-marker";
        const service = await startService((s) => {
            s.firstLineOverride = `{"type":"${marker}${"x".repeat(MAX_LINE_BYTES)}"}\n`;
        });
        const { events, last, statuses } = connectTo(service.path);
        await until(() => last() === "unavailable", "unavailable");

        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
        expect(events).toEqual([]);
        expect(JSON.stringify(statuses)).not.toContain(marker);
    });

    it("drops the connection on a line that never ends", async () => {
        const service = await startService((s) => {
            s.firstLineOverride = "x".repeat(MAX_LINE_BYTES + 1);
        });
        const { last } = connectTo(service.path);
        await until(() => last() === "unavailable", "unavailable");
    });

    it.each([
        ["not JSON", "this is not json\n"],
        ["an unknown message type", '{"type":"surprise","data":{}}\n'],
        [
            "an unknown state",
            '{"type":"event","data":{"kind":"state_changed","value":{"state":"levitating"}}}\n',
        ],
        [
            "an unknown error code",
            '{"type":"event","data":{"kind":"state_changed","value":{"state":"failed","code":"gremlins","message":"m"}}}\n',
        ],
        [
            "a tunnel with a missing field",
            '{"type":"event","data":{"kind":"state_changed","value":{"state":"connected","tunnel":{"address":"198.51.100.1"}}}}\n',
        ],
    ])("drops the connection on %s", async (_name, line) => {
        const service = await startService((s) => {
            s.firstLineOverride = line;
        });
        const { events, last, statuses } = connectTo(service.path);
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "protocol_error" });
        expect(events).toEqual([]);
    });
});

describe("when the service is not there", () => {
    it("reports 'unavailable', then connects once the service starts", async () => {
        const path = uniqueChannelPath();
        const { last, statuses } = connectTo(path);
        await until(() => last() === "unavailable", "unavailable");
        expect(statuses.at(-1)).toEqual({ status: "unavailable", reason: "not_running" });

        const service = new MockService(path);
        await service.start();
        cleanups.push(() => service.stop());
        await until(() => last() === "ready", "ready");
    });

    it("notices the service going away, fails what was waiting, and comes back", async () => {
        const service = await startService((s) => {
            s.ignoreRequests = true;
        });
        const { client, events, last } = connectTo(service.path);
        await until(() => last() === "ready", "ready");

        const waiting = client.request({ method: "status" });
        const failed = expect(waiting).rejects.toMatchObject({ reason: "closed" });
        await service.stop();
        await failed;
        await until(() => last() === "unavailable", "unavailable");

        service.ignoreRequests = false;
        service.state = { state: "login_needed" };
        await service.start();
        await until(() => last() === "ready", "ready again");
        // A new connection starts with the current state, as the first did.
        await until(
            () => events.at(-1)?.value.state === "login_needed",
            "the state after reconnecting",
        );
        await expect(client.request({ method: "claim" })).resolves.toMatchObject({ status: "ok" });
    });

    it("waits longer after each failed attempt", async () => {
        const { statuses } = connectTo(uniqueChannelPath(), { maxRetryDelayMs: 80 });
        const started = Date.now();
        const failures = () => statuses.filter((status) => status.status === "unavailable").length;
        await until(() => failures() === 4, "four failed attempts");
        // Attempts at 0, 20, 60 and 140 ms: the waits are 20, 40 and 80.
        // Without backoff the fourth would come after 60 ms.
        expect(Date.now() - started).toBeGreaterThanOrEqual(135);
    });

    it("stops trying once stopped", async () => {
        const { client, statuses } = connectTo(uniqueChannelPath());
        await until(() => statuses.length >= 2, "a failed attempt");
        client.stop();
        const seen = statuses.length;
        await new Promise((resolve) => setTimeout(resolve, 150));
        expect(statuses).toHaveLength(seen);
    });
});

describe("secrets", () => {
    it("never writes a line anywhere, and never puts one in an error", async () => {
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

        const service = await startService((s) => {
            s.ignoreRequests = true;
        });
        const { client, last, statuses } = connectTo(service.path, { replyTimeoutMs: 60 });
        await until(() => last() === "ready", "ready");

        // A request that times out, then a reply that is not valid.
        const error = await client
            .request({
                method: "connect",
                params: {
                    cookie: COOKIE,
                    gateway_addr: "192.0.2.1",
                    routes: { subnets: ["203.0.113.0/24"], dns_domains: [] },
                },
            })
            .catch((caught: unknown) => caught);
        service.sendRaw(`{"type":"response","cookie":"${COOKIE}"}\n`);
        await until(() => last() === "unavailable", "unavailable");

        expect(JSON.stringify(service.received)).toContain(COOKIE);
        expect(error).toBeInstanceOf(ChannelError);
        const error_ = error as ChannelError;
        expect(`${error_.message} ${error_.stack} ${JSON.stringify(error_)}`).not.toContain(COOKIE);
        expect(JSON.stringify(statuses)).not.toContain(COOKIE);
        expect(writes.join("\n")).not.toContain(COOKIE);
        expect(writes).toEqual([]);
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
