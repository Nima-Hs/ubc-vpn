import type { LinkState, Snapshot } from "@shared/api";
import { afterEach, describe, expect, it } from "vitest";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { createServiceLink, type ServiceLink } from "../src/main/link";
import { type MockBridge, type MockRun, mockBridge, pause, TUNNEL, until } from "./bridge-harness";

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

describe("the link to the service", () => {
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
