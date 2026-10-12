import { type SpawnOptions, spawn } from "node:child_process";
import type { LinkState, LoginState, Snapshot } from "@shared/api";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { createServiceLink, type ServiceLink } from "../src/main/link";
import { clientLogin, disconnectForCancel } from "../src/main/login";
import {
    type MockBridge,
    type MockRun,
    mockBridge,
    mockCli,
    pause,
    TUNNEL,
    until,
} from "./bridge-harness";

// The real `spawn`, watched: one test reads how the bridge was started.
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

type Linked = { bridge: MockBridge; link: ServiceLink; seen: LinkState[] };

/** Generous limits: a slow start of the mock must never look like a failure. */
const linkTo = (...runs: MockRun[]): Linked => linkWith({ replyTimeoutMs: 10_000 }, ...runs);

function linkWith(limits: { replyTimeoutMs: number }, ...runs: MockRun[]): Linked {
    const bridge = mockBridge(...runs);
    const link = createServiceLink({
        command: bridge.command,
        args: bridge.args,
        appVersion: "0.1.0",
        initialRetryDelayMs: 20,
        maxRetryDelayMs: 80,
        startTimeoutMs: 20_000,
        replyTimeoutMs: limits.replyTimeoutMs,
    });
    cleanups.push(() => link.dispose());
    const seen: LinkState[] = [link.getState()];
    link.subscribe((state) => seen.push(state));
    return { bridge, link, seen };
}

describe("a login given up after the service had taken it", () => {
    const PROMPT = { id: 1, kind: "password", label: "Password" } as const;

    // The real link over the mock bridge, and the real runner over the mock
    // client, joined the way the app joins them.
    async function cancelledLogin(afterCancel: Parameters<typeof mockCli>[0]) {
        const { bridge, link } = linkTo({});
        await until(() => link.getState().link === "ready", "ready");
        const cli = mockCli([{ prompt: PROMPT }, { hang: true }], { afterCancel });
        const states: LoginState[] = [];
        const runner = clientLogin(
            link,
            { command: cli.command, args: cli.args, dev: false },
            { minStartGapMs: 0 },
        )((state) => states.push(state));
        cleanups.push(() => runner.stop());
        runner.start();
        await until(() => states.at(-1)?.phase === "prompt", "the prompt");
        runner.cancel();
        await until(() => states.at(-1)?.phase === "idle", "the login being given up");
        return bridge;
    }

    it("is undone: the disconnect really goes through the bridge to the service", async () => {
        const bridge = await cancelledLogin([{ done: true }]);
        expect(bridge.received().filter((entry) => entry === "disconnect")).toHaveLength(1);
    });

    it("is left alone when the client says nothing reached the service", async () => {
        const bridge = await cancelledLogin([
            { error: { code: "cancelled", message: "cancelled" } },
        ]);
        await pause(100);
        expect(bridge.received()).not.toContain("disconnect");
    });

    // A link the test steers by hand.
    function fakeLink(answers: ("ok" | "service_unavailable" | "refused")[]) {
        let state: LinkState = { link: "unavailable", reason: "not_running" };
        const listeners = new Set<(state: LinkState) => void>();
        const link = {
            asked: 0,
            disconnect: async () => {
                const answer = answers[link.asked] ?? "ok";
                link.asked += 1;
                return answer === "ok"
                    ? ({ ok: true } as const)
                    : answer === "refused"
                      ? ({
                            ok: false,
                            error: { kind: "refused", code: "busy", message: "" },
                        } as const)
                      : ({ ok: false, error: { kind: "service_unavailable" } } as const);
            },
            getState: () => state,
            subscribe: (listener: (state: LinkState) => void) => {
                listeners.add(listener);
                return () => listeners.delete(listener);
            },
            becomes: (next: LinkState) => {
                state = next;
                for (const listener of [...listeners]) {
                    listener(next);
                }
            },
            listening: () => listeners.size,
        };
        return link;
    }
    const READY: LinkState = { link: "ready", conn: { state: "disconnected" } };

    it("is sent once more, when the bridge is next ready, if the service could not be reached", async () => {
        const link = fakeLink(["service_unavailable", "ok"]);
        let sent = false;
        void disconnectForCancel(link).then(() => {
            sent = true;
        });
        await pause(50);
        // Not sent yet, so the login is not yet shown as given up.
        expect(link.asked).toBe(1);
        expect(sent).toBe(false);
        // Other changes of state are not the bridge being ready.
        link.becomes({ link: "starting" });
        await pause(20);
        expect(link.asked).toBe(1);
        link.becomes(READY);
        await until(() => sent, "the disconnect being sent");
        expect(link.asked).toBe(2);
        // Once, not in a loop: later changes send nothing more.
        expect(link.listening()).toBe(0);
        link.becomes({ link: "starting" });
        link.becomes(READY);
        await pause(20);
        expect(link.asked).toBe(2);
    });

    it("is not sent a third time, whatever the second answer", async () => {
        const link = fakeLink(["service_unavailable", "service_unavailable", "ok"]);
        link.becomes(READY);
        await disconnectForCancel(link);
        expect(link.asked).toBe(2);
    });

    it("is not sent again when the service answered, yes or no", async () => {
        for (const answer of ["ok", "refused"] as const) {
            const link = fakeLink([answer]);
            await disconnectForCancel(link);
            expect(link.asked, answer).toBe(1);
            expect(link.listening()).toBe(0);
        }
    });
});

describe("the link to the service", () => {
    it("starts the bridge in dev mode when it is told to, and not otherwise", async () => {
        const spawned = vi.mocked(spawn);
        const env = { ...process.env, XDG_RUNTIME_DIR: "/run/user/1000" };
        for (const dev of [undefined, true]) {
            const bridge = mockBridge({});
            spawned.mockClear();
            const link = createServiceLink({
                command: bridge.command,
                args: bridge.args,
                appVersion: "0.1.0",
                env,
                ...(dev !== undefined && { dev }),
            });
            cleanups.push(() => link.dispose());
            const [, , options] = spawned.mock.calls.at(-1) as [string, string[], SpawnOptions];
            expect(Object.keys(options.env ?? {}).includes("XDG_RUNTIME_DIR")).toBe(dev === true);
        }
    });

    it("claims the service once the bridge is ready, then shows the state it reports", async () => {
        const connected = { state: "connected", tunnel: TUNNEL };
        const { bridge, link, seen } = linkTo({
            state: connected,
            later: [{ afterMs: 150, state: { state: "login_needed" } }],
        });
        await until(() => link.getState().link === "ready", "ready");

        expect(seen[0]).toEqual({ link: "starting" });
        expect(link.getState()).toEqual({ link: "ready", conn: connected });
        // The bridge claims nothing itself; the app's first request is the claim.
        expect(bridge.received()[0]).toBe("claim");

        await until(() => JSON.stringify(link.getState()).includes("login_needed"), "the change");
        expect(link.getState()).toEqual({ link: "ready", conn: { state: "login_needed" } });
    });

    it("claims even when the bridge says an owner already exists", async () => {
        const { bridge, link } = linkTo({ ownerClaimed: true });
        await until(() => link.getState().link === "ready", "ready");
        expect(bridge.received()).toContain("claim");
    });

    it("asks for the state when the first event does not come", async () => {
        const { bridge, link } = linkTo({ firstEvent: false, state: { state: "connecting" } });
        await until(() => link.getState().link === "ready", "ready");
        expect(link.getState()).toEqual({ link: "ready", conn: { state: "connecting" } });
        expect(bridge.received()).toEqual(["claim", "status"]);
    });

    it("says so when the bridge reports another user's service", async () => {
        const { link } = linkTo({ first: "not_owner" });
        await until(() => link.getState().link === "not_owner", "not_owner");
    });

    it("says the same when it is the service that refuses the claim", async () => {
        // The channel was not reserved for the owner, so the bridge got through
        // and the service itself answers "not the owner".
        const { link } = linkTo({ requestsRefusedAsNotOwner: true });
        await until(() => link.getState().link === "not_owner", "not_owner");
        expect(link.getState()).toEqual({ link: "not_owner" });
    });

    it("stays on 'another user' when the service refuses and then hangs up", async () => {
        const { bridge, link, seen } = linkTo({
            requestsRefusedAsNotOwner: true,
            hangsUpOnNonOwner: true,
        });
        await until(() => link.getState().link === "not_owner", "not_owner");
        await pause(300);
        // Not "service not running", and no second bridge.
        expect(link.getState()).toEqual({ link: "not_owner" });
        expect(seen.some((state) => state.link === "unavailable")).toBe(false);
        expect(bridge.starts()).toBe(1);
    });

    it("says so when something other than the service is listening", async () => {
        const { link } = linkTo({ first: "untrusted_service" });
        await until(() => link.getState().link === "untrusted_service", "untrusted_service");
    });

    it("says an update is needed when the versions differ", async () => {
        const { link } = linkTo({ first: "update_needed", serviceVersion: "0.2.0" });
        await until(() => link.getState().link === "update_needed", "update_needed");
        expect(link.getState()).toEqual({
            link: "update_needed",
            appVersion: "0.1.0",
            serviceVersion: "0.2.0",
        });
    });

    it("says the service is unavailable, and recovers when it appears", async () => {
        const { link, seen } = linkTo({ first: "service_unavailable" }, { first: "none" }, {});
        await until(() => link.getState().link === "ready", "ready");
        expect(seen).toContainEqual({ link: "unavailable", reason: "not_running" });
    });

    it("does not wait for ever on a claim that is never answered", async () => {
        // The one test that needs an answer to be given up on quickly. Only
        // answers: a bridge still has as long as ever to start.
        const { link, seen } = linkWith({ replyTimeoutMs: 300 }, { ignore: ["claim"] }, {});
        await until(() => seen.some((state) => state.link === "unavailable"), "unavailable");
        expect(seen).toContainEqual({ link: "unavailable", reason: "protocol_error" });
        // The next bridge answers, and the app carries on.
        await until(() => link.getState().link === "ready", "ready");
    });

    it("cannot connect yet, and sends nothing when asked to", async () => {
        const { bridge, link } = linkTo({});
        await until(() => link.getState().link === "ready", "ready");

        await expect(link.connect()).resolves.toEqual({
            ok: false,
            error: { kind: "login_unavailable" },
        });
        await pause(50);
        expect(bridge.received()).not.toContain("connect");
        expect(bridge.received()).toEqual(["claim"]);
    });

    it("disconnects, and follows the service through to disconnected", async () => {
        const { link } = linkTo({ state: { state: "connected", tunnel: TUNNEL } });
        await until(() => link.getState().link === "ready", "ready");

        await expect(link.disconnect()).resolves.toEqual({ ok: true });
        await until(
            () => JSON.stringify(link.getState()).includes('"disconnected"'),
            "disconnected",
        );
    });

    it("shows 'not the owner' when the service refuses a disconnect for that reason", async () => {
        // The claim goes unanswered here so that only the disconnect is refused.
        const { bridge, link } = linkTo({ requestsRefusedAsNotOwner: true, ignore: ["claim"] });
        await until(() => bridge.received().includes("claim"), "the claim being sent");
        await expect(link.disconnect()).resolves.toEqual({
            ok: false,
            error: { kind: "refused", code: "not_owner", message: "only the owner may do this" },
        });
        expect(link.getState()).toEqual({ link: "not_owner" });
    });

    it("reports a refusal in the service's words when there is no service to ask", async () => {
        const { link } = linkTo({ first: "service_unavailable" });
        await until(() => link.getState().link === "unavailable", "unavailable");
        await expect(link.disconnect()).resolves.toEqual({
            ok: false,
            error: { kind: "service_unavailable" },
        });
    });
});

describe("the controller", () => {
    it("explains an action that did not start, until the state next changes", async () => {
        const demo = createDemoLink(10);
        const controller = new Controller({
            ...demo,
            connect: async () => ({ ok: false, error: { kind: "login_unavailable" } }),
        });
        cleanups.push(() => controller.dispose());
        const seen: Snapshot[] = [];
        controller.subscribe((snapshot) => seen.push(snapshot));

        await controller.connect();
        expect(controller.getSnapshot().notice).toEqual({ kind: "login_unavailable" });

        await controller.disconnect();
        expect(controller.getSnapshot().notice).toBeNull();
        expect(seen.at(-1)?.state).toEqual({ link: "ready", conn: { state: "disconnecting" } });
    });
});

describe("the demo service", () => {
    it("ignores a scenario name it does not have, even one every object answers to", () => {
        const demo = createDemoLink(10);
        cleanups.push(() => demo.dispose());
        const before = demo.getState();
        for (const name of ["__proto__", "constructor", "toString", "no-such-state"]) {
            demo.setScenario(name);
            expect(demo.getState(), name).toEqual(before);
        }
        demo.setScenario("connecting");
        expect(demo.getState()).toEqual({ link: "ready", conn: { state: "connecting" } });
    });

    it("walks from disconnected through connecting to connected, and back", async () => {
        const demo = createDemoLink(10);
        cleanups.push(() => demo.dispose());
        const seen: string[] = [];
        demo.subscribe((state) =>
            seen.push(state.link === "ready" ? state.conn.state : state.link),
        );

        await demo.connect();
        await until(() => seen.at(-1) === "connected", "connected");
        // Asking again while it is working is refused, as the service would.
        await demo.disconnect();
        await expect(demo.connect()).resolves.toMatchObject({ ok: false });
        await until(() => seen.at(-1) === "disconnected", "disconnected");
        expect(seen).toEqual(["connecting", "connected", "disconnecting", "disconnected"]);
    });
});
