import type { LinkState, Snapshot } from "@shared/api";
import { afterEach, describe, expect, it } from "vitest";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { createServiceLink, type ServiceLink } from "../src/main/link";
import { MockService, TUNNEL, uniqueChannelPath } from "./mock-service";

async function until(condition: () => boolean, what: string, timeoutMs = 4000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!condition()) {
        if (Date.now() > deadline) {
            throw new Error(`timed out waiting for ${what}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
    }
}

const cleanups: (() => unknown)[] = [];

afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
        await cleanup();
    }
});

function linkTo(path: string): { link: ServiceLink; seen: LinkState[] } {
    const link = createServiceLink({
        path,
        appVersion: "0.1.0",
        initialRetryDelayMs: 20,
        maxRetryDelayMs: 80,
        replyTimeoutMs: 1000,
    });
    cleanups.push(() => link.dispose());
    const seen: LinkState[] = [link.getState()];
    link.subscribe((state) => seen.push(state));
    return { link, seen };
}

async function startService(configure?: (service: MockService) => void): Promise<MockService> {
    const service = new MockService();
    configure?.(service);
    await service.start();
    cleanups.push(() => service.stop());
    return service;
}

const methods = (service: MockService) =>
    service.received
        .slice(1)
        .map((request) => (request as { body: { method: string } }).body.method);

describe("the link to the service", () => {
    it("claims the service, then shows the state it reports", async () => {
        const service = await startService((s) => {
            s.state = { state: "connected", tunnel: TUNNEL };
        });
        const { link, seen } = linkTo(service.path);
        await until(() => link.getState().link === "ready", "ready");

        expect(seen[0]).toEqual({ link: "starting" });
        expect(link.getState()).toEqual({
            link: "ready",
            conn: { state: "connected", tunnel: TUNNEL },
        });
        expect(methods(service)[0]).toBe("claim");

        service.setState({ state: "login_needed" });
        await until(() => seen.at(-1)?.link === "ready" && seen.length > 2, "the change");
        expect(link.getState()).toEqual({ link: "ready", conn: { state: "login_needed" } });
    });

    it("says so when another user owns the service", async () => {
        const service = await startService((s) => {
            s.ownedByAnother = true;
        });
        const { link } = linkTo(service.path);
        await until(() => link.getState().link === "not_owner", "not_owner");
    });

    it("says an update is needed when the versions differ", async () => {
        const service = await startService((s) => {
            s.protocolVersion = 3;
            s.serviceVersion = "0.2.0";
        });
        const { link } = linkTo(service.path);
        await until(() => link.getState().link === "update_needed", "update_needed");
        expect(link.getState()).toEqual({
            link: "update_needed",
            appVersion: "0.1.0",
            serviceVersion: "0.2.0",
        });
    });

    it("says the service is unavailable, and recovers when it appears", async () => {
        const path = uniqueChannelPath();
        const { link } = linkTo(path);
        await until(() => link.getState().link === "unavailable", "unavailable");
        expect(link.getState()).toEqual({ link: "unavailable", reason: "not_running" });

        const service = new MockService(path);
        await service.start();
        cleanups.push(() => service.stop());
        await until(() => link.getState().link === "ready", "ready");
    });

    it("cannot connect yet, and sends nothing when asked to", async () => {
        const service = await startService();
        const { link } = linkTo(service.path);
        await until(() => link.getState().link === "ready", "ready");

        await expect(link.connect()).resolves.toEqual({
            ok: false,
            error: { kind: "login_unavailable" },
        });
        expect(methods(service)).not.toContain("connect");
    });

    it("disconnects, and reports a refusal in the service's words", async () => {
        const service = await startService((s) => {
            s.state = { state: "connected", tunnel: TUNNEL };
        });
        const { link } = linkTo(service.path);
        await until(() => link.getState().link === "ready", "ready");

        await expect(link.disconnect()).resolves.toEqual({ ok: true });
        await until(
            () => JSON.stringify(link.getState()).includes('"disconnected"'),
            "disconnected",
        );

        service.ownedByAnother = true;
        await expect(link.disconnect()).resolves.toEqual({
            ok: false,
            error: { kind: "refused", code: "not_owner", message: "only the owner may do this" },
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
