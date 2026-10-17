// Split or full tunnel: the client command, the one switch the window and
// the tray share, and what each says and shows. Made-up values only.

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LinkState } from "@shared/api";
import { describe as copyFor } from "@shared/copy";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { TunnelInfo } from "@shared/protocol/TunnelInfo";
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import type { TunnelReply } from "@shared/protocol/TunnelReply";
import {
    describeTunnelOutcome,
    shownMode,
    TUNNEL,
    type TunnelOutcome,
    type TunnelStatus,
    tunnelLocked,
    UNREAD_TUNNEL,
} from "@shared/tunnel";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
    PROFILES_ARGS,
    ProfilesRunner,
    SET_TUNNEL_TIMEOUT_MS,
    type TunnelResult,
} from "../src/main/channel/profiles";
import { isProfilesView, isTunnelReply } from "../src/main/channel/validate";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { takeTunnelMode } from "../src/main/ipc";
import { LinkStore } from "../src/main/link";
import { trayKind } from "../src/main/tray-icon";
import { type TrayActions, type TrayMenuItem, trayMenu, trayStatus } from "../src/main/tray-menu";
import { SETTLE_MS, TunnelSwitch } from "../src/main/tunnel-switch";

const ID = "0123456789abcdef0123456789abcdef";
const NUL = String.fromCharCode(0);

const VIEW: ProfilesView = {
    global: { start: "off", auto_connect: false, active_profile: ID, tunnel: "split" },
    profiles: [
        {
            id: ID,
            name: "Campus",
            username: "someone.example",
            routes: { subnets: ["198.19.0.0/24"], dns_domains: ["dept.campus.example"] },
            save_password: false,
            password_saved: false,
        },
    ],
    keyring: "available",
    policy_readable: true,
    allowed_routes: null,
    full_tunnel: "allowed",
};

const TUNNEL_INFO: TunnelInfo = {
    interface: "utun4",
    address: "198.19.0.42",
    subnets: ["198.19.0.0/24"],
    dns_domains: ["dept.campus.example"],
    mode: "split",
};

const connected = (mode: TunnelMode): LinkState => ({
    link: "ready",
    conn: { state: "connected", tunnel: { ...TUNNEL_INFO, mode } },
});
const DISCONNECTED: LinkState = { link: "ready", conn: { state: "disconnected" } };
const CONNECTING: LinkState = { link: "ready", conn: { state: "connecting" } };

const status = (change: Partial<TunnelStatus> = {}): TunnelStatus => ({
    ...UNREAD_TUNNEL,
    saved: "split",
    ...change,
});

// The client command ---------------------------------------------------------

type Answer = { line?: unknown; raw?: string; exit?: number; hang?: boolean };
const runners: ProfilesRunner[] = [];
afterEach(() => {
    for (const runner of runners.splice(0)) {
        runner.stop();
    }
    vi.useRealTimers();
});

function client(answers: Record<string, Answer>) {
    const dir = mkdtempSync(join(tmpdir(), "ubc-vpn-tunnel-"));
    const config = join(dir, "config.json");
    const log = join(dir, "log");
    writeFileSync(config, JSON.stringify({ answers, log }));
    const runner = new ProfilesRunner({
        command: process.execPath,
        leadingArgs: [join(__dirname, "mock-profiles.mjs"), config],
    });
    runners.push(runner);
    const received = () =>
        existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean) : [];
    return { runner, received };
}

describe("settings set-tunnel", () => {
    it("sends the mode alone, and gives back what the client said", async () => {
        const reply: TunnelReply = { type: "ok", tunnel: "full", live: { result: "applied" } };
        const { runner, received } = client({ "settings set-tunnel": { line: reply } });
        await expect(runner.setTunnel("full")).resolves.toEqual({ ok: true, value: reply });
        expect(received()).toEqual([
            `args:${JSON.stringify(PROFILES_ARGS.setTunnel)}`,
            `input:${JSON.stringify({ mode: "full" })}`,
        ]);
    });

    it("passes on a refusal by the policy", async () => {
        const { runner } = client({ "settings set-tunnel": { line: { type: "forbidden" } } });
        await expect(runner.setTunnel("full")).resolves.toEqual({
            ok: true,
            value: { type: "forbidden" },
        });
    });

    it("cleans the service's reason before anyone is given it", async () => {
        const { runner } = client({
            "settings set-tunnel": {
                line: {
                    type: "ok",
                    tunnel: "full",
                    live: { result: "refused", code: "route_refused", message: `no${NUL}  way ` },
                    extra: "not passed on",
                },
            },
        });
        const result = await runner.setTunnel("full");
        expect(result).toEqual({
            ok: true,
            value: {
                type: "ok",
                tunnel: "full",
                live: { result: "refused", code: "route_refused", message: "no way" },
            },
        });
    });

    it("cleans the reason the service gave no answer, too", async () => {
        const { runner } = client({
            "settings set-tunnel": {
                line: {
                    type: "ok",
                    tunnel: "full",
                    live: { result: "unknown", message: `not${NUL}  said ` },
                },
            },
        });
        await expect(runner.setTunnel("full")).resolves.toEqual({
            ok: true,
            value: {
                type: "ok",
                tunnel: "full",
                live: { result: "unknown", message: "not said" },
            },
        });
    });

    it("gives a switch its long time limit, whatever the other calls are given", () => {
        const runner = new ProfilesRunner({ command: process.execPath, timeoutMs: 1000 });
        runners.push(runner);
        const limit = (calls: string) =>
            (runner as unknown as Record<string, { options: { timeoutMs: number } }>)[calls]
                ?.options.timeoutMs;
        expect(limit("calls")).toBe(1000);
        expect(limit("slowCalls")).toBe(SET_TUNNEL_TIMEOUT_MS);
        expect(SET_TUNNEL_TIMEOUT_MS).toBeGreaterThan(120_000);
    });

    it("starts nothing for a mode that is not one", async () => {
        const { runner, received } = client({});
        await expect(runner.setTunnel("all" as TunnelMode)).resolves.toEqual({
            ok: false,
            error: "bad_input",
        });
        expect(received()).toEqual([]);
    });

    it("treats an answer of the wrong shape as no answer, and a failure as the client's", async () => {
        const wrong = client({
            "settings set-tunnel": { line: { type: "ok", tunnel: "all", live: {} } },
        });
        await expect(wrong.runner.setTunnel("full")).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
        const failed = client({
            "settings set-tunnel": { line: { error: "unwritable" }, exit: 1 },
        });
        await expect(failed.runner.setTunnel("split")).resolves.toEqual({
            ok: false,
            error: "unwritable",
        });
    });

    it("needs the profiles view to say whether full is allowed", () => {
        expect(isProfilesView(VIEW)).toBe(true);
        const { full_tunnel: _, ...without } = VIEW;
        expect(isProfilesView(without)).toBe(false);
        expect(isProfilesView({ ...VIEW, full_tunnel: "maybe" })).toBe(false);
        expect(isProfilesView({ ...VIEW, full_tunnel: "forbidden" })).toBe(true);
    });

    it("knows every reply the contract names, and nothing else", () => {
        const ok = (live: unknown) => ({ type: "ok", tunnel: "split", live });
        for (const live of [
            { result: "applied" },
            { result: "next_connect" },
            { result: "refused", code: "route_refused", message: "m" },
            { result: "failed", code: "verification_failed", message: "m" },
            { result: "unknown", message: "m" },
        ]) {
            expect(isTunnelReply(ok(live)), JSON.stringify(live)).toBe(true);
        }
        expect(isTunnelReply({ type: "forbidden" })).toBe(true);
        for (const wrong of [
            ok({ result: "refused", code: "no_such_code", message: "m" }),
            ok({ result: "refused", code: "route_refused" }),
            ok({ result: "later" }),
            { type: "ok", tunnel: "Full", live: { result: "applied" } },
            { type: "nope" },
            null,
        ]) {
            expect(isTunnelReply(wrong), JSON.stringify(wrong)).toBe(false);
        }
    });

    it("takes only split or full from the window", () => {
        expect(takeTunnelMode(["full"])).toBe("full");
        expect(takeTunnelMode(["split"])).toBe("split");
        for (const args of [[], ["Full"], ["full", "extra"], [{ mode: "full" }], ["__proto__"]]) {
            expect(() => takeTunnelMode(args), JSON.stringify(args)).toThrow();
        }
    });
});

// The switch ------------------------------------------------------------------

/** A switch against a pretend client whose answers the test gives. */
function rig(start: LinkState = connected("split")) {
    const link = new LinkStore();
    link.set(start);
    const published: TunnelStatus[] = [];
    const saves: TunnelMode[] = [];
    const answers: TunnelResult[] = [];
    let loggingIn = false;
    let rereads = 0;
    const tunnel = new TunnelSwitch({
        save: (mode) => {
            saves.push(mode);
            const answer = answers.shift();
            return answer === undefined ? new Promise(() => {}) : Promise.resolve(answer);
        },
        reread: () => {
            rereads += 1;
        },
        state: () => link.get(),
        subscribe: (listener) => link.subscribe(listener),
        loggingIn: () => loggingIn,
        publish: (next) => published.push(next),
    });
    tunnel.fromProfiles(VIEW);
    return {
        link,
        tunnel,
        published,
        saves,
        answers,
        rereads: () => rereads,
        login: (on: boolean) => {
            loggingIn = on;
        },
    };
}

const applied = (mode: TunnelMode): TunnelResult => ({
    ok: true,
    value: { type: "ok", tunnel: mode, live: { result: "applied" } },
});

describe("the tunnel switch", () => {
    it("reads the saved mode and the policy from the profiles", () => {
        const { tunnel } = rig();
        expect(tunnel.get()).toMatchObject({ saved: "split", fullAllowed: true });
        tunnel.fromProfiles({
            ...VIEW,
            global: { ...VIEW.global, tunnel: "full" },
            full_tunnel: "forbidden",
        });
        expect(tunnel.get()).toMatchObject({ saved: "full", fullAllowed: false });
    });

    it("shows switching, then the new mode once the connection has it", async () => {
        const { link, tunnel, published, saves, answers, rereads } = rig();
        answers.push(applied("full"));
        const done = tunnel.request("full");
        expect(tunnel.get().switching).toEqual({ from: "split", to: "full" });
        expect(saves).toEqual(["full"]);
        // The client has answered, but the new state has not arrived yet.
        await Promise.resolve();
        await Promise.resolve();
        expect(tunnel.get().switching).not.toBeNull();
        link.set(connected("full"));
        await done;
        expect(tunnel.get()).toMatchObject({ saved: "full", switching: null, outcome: null });
        expect(published.some((each) => each.switching?.to === "full")).toBe(true);
        expect(rereads()).toBe(1);
    });

    it("stops showing switching after a short while, whatever the state", async () => {
        vi.useFakeTimers();
        const { tunnel, answers } = rig();
        answers.push(applied("full"));
        const done = tunnel.request("full");
        await vi.advanceTimersByTimeAsync(SETTLE_MS - 1);
        expect(tunnel.get().switching).not.toBeNull();
        await vi.advanceTimersByTimeAsync(1);
        await done;
        expect(tunnel.get().switching).toBeNull();
    });

    it("keeps the old mode when the service refuses, and says why", async () => {
        const { link, tunnel, saves, answers } = rig();
        answers.push(
            {
                ok: true,
                value: {
                    type: "ok",
                    tunnel: "full",
                    live: { result: "refused", code: "route_refused", message: "No router here." },
                },
            },
            { ok: true, value: { type: "ok", tunnel: "split", live: { result: "applied" } } },
        );
        await tunnel.request("full");
        // Saved back, so what is chosen is what is in effect.
        expect(saves).toEqual(["full", "split"]);
        expect(tunnel.get()).toMatchObject({
            saved: "split",
            switching: null,
            outcome: {
                kind: "refused",
                kept: "split",
                wanted: "full",
                message: "No router here.",
                restored: true,
            },
        });
        expect(shownMode(link.get(), tunnel.get())).toBe("split");
        // Said until the connection changes.
        link.set(connected("split"));
        expect(tunnel.get().outcome).not.toBeNull();
        link.set(DISCONNECTED);
        expect(tunnel.get().outcome).toBeNull();
    });

    it("says so when the old mode could not be saved back after a refusal", async () => {
        const { tunnel, answers, rereads } = rig();
        answers.push(
            {
                ok: true,
                value: {
                    type: "ok",
                    tunnel: "full",
                    live: { result: "refused", code: "route_refused", message: "No router here." },
                },
            },
            { ok: false, error: "unwritable" },
        );
        await tunnel.request("full");
        // Full is still saved: the next connect would use it, and it is said.
        expect(tunnel.get()).toMatchObject({
            saved: "full",
            outcome: { kind: "refused", kept: "split", wanted: "full", restored: false },
        });
        const words = describeTunnelOutcome(tunnel.get().outcome as TunnelOutcome, String);
        expect(words.body).toContain("Full tunnel is still saved, so the next connect uses it.");
        expect(rereads()).toBe(1);
    });

    it("does not ask the client for full mode the policy forbids", async () => {
        const { tunnel, saves } = rig();
        tunnel.fromProfiles({ ...VIEW, full_tunnel: "forbidden" });
        await tunnel.request("full");
        expect(saves).toEqual([]);
        expect(tunnel.get().outcome).toEqual({ kind: "forbidden" });
    });

    it("learns from the client that the policy forbids full mode", async () => {
        const { tunnel, answers } = rig();
        answers.push({ ok: true, value: { type: "forbidden" } });
        await tunnel.request("full");
        expect(tunnel.get()).toMatchObject({
            saved: "split",
            fullAllowed: false,
            switching: null,
            outcome: { kind: "forbidden" },
        });
    });

    it("says so when the choice could not be saved, and reads the settings again", async () => {
        const { tunnel, answers, rereads } = rig();
        answers.push({ ok: false, error: "unavailable" });
        await tunnel.request("full");
        expect(tunnel.get()).toMatchObject({
            saved: "split",
            switching: null,
            outcome: { kind: "not_saved", wanted: "full", error: "unavailable" },
        });
        // A client ended after saving may have saved: the settings say.
        expect(rereads()).toBe(1);
    });

    it("says the settings could not be read, instead of reading for ever", () => {
        const link = new LinkStore();
        link.set(DISCONNECTED);
        const published: TunnelStatus[] = [];
        const tunnel = new TunnelSwitch({
            save: () => new Promise(() => {}),
            reread: () => {},
            state: () => link.get(),
            subscribe: (listener) => link.subscribe(listener),
            loggingIn: () => false,
            publish: (next) => published.push(next),
        });
        expect(tunnelLocked(DISCONNECTED, tunnel.get(), false)).toBe(TUNNEL.unread);
        tunnel.readFailed();
        expect(tunnel.get().readFailed).toBe(true);
        expect(tunnelLocked(DISCONNECTED, tunnel.get(), false)).toBe(TUNNEL.unreadable);
        // Read after all: usable, and the failure forgotten.
        tunnel.fromProfiles(VIEW);
        expect(tunnel.get()).toMatchObject({ saved: "split", readFailed: false });
        expect(tunnelLocked(DISCONNECTED, tunnel.get(), false)).toBeNull();
        // A later failure does not take back settings already read.
        tunnel.readFailed();
        expect(tunnel.get().readFailed).toBe(false);
    });

    it("saves for the next connect when not connected, with no wait", async () => {
        const { link, tunnel, answers } = rig(DISCONNECTED);
        answers.push({
            ok: true,
            value: { type: "ok", tunnel: "full", live: { result: "next_connect" } },
        });
        await tunnel.request("full");
        expect(tunnel.get()).toMatchObject({ saved: "full", switching: null, outcome: null });
        expect(shownMode(link.get(), tunnel.get())).toBe("full");
    });

    it("changes nothing while a connection is being made or a login is under way", async () => {
        const connecting = rig(CONNECTING);
        await connecting.tunnel.request("full");
        expect(connecting.saves).toEqual([]);
        const login = rig(DISCONNECTED);
        login.login(true);
        await login.tunnel.request("full");
        expect(login.saves).toEqual([]);
    });

    it("makes one switch at a time, and none to the mode in use", async () => {
        const { tunnel, saves } = rig();
        await tunnel.request("split");
        expect(saves).toEqual([]);
        void tunnel.request("full");
        void tunnel.request("split");
        void tunnel.request("full");
        expect(saves).toEqual(["full"]);
    });

    it("is in every snapshot the window and the tray are sent", () => {
        const controller = new Controller(createDemoLink(10));
        const seen: TunnelStatus[] = [];
        controller.subscribe((snapshot) => seen.push(snapshot.tunnel));
        expect(controller.getSnapshot().tunnel).toEqual(UNREAD_TUNNEL);
        const next = status({ switching: { from: "split", to: "full" } });
        controller.setTunnel(next);
        expect(controller.getSnapshot().tunnel).toEqual(next);
        expect(seen).toEqual([next]);
        controller.dispose();
    });
});

// What it says and shows --------------------------------------------------------

describe("the words and pictures for each mode", () => {
    it("says which mode a connection is in", () => {
        const split = copyFor(connected("split"), status());
        expect(split).toMatchObject({ tone: "on", title: "Connected", mode: "split" });
        expect(split.body).toMatch(/^Split tunnel: /);
        const full = copyFor(connected("full"), status({ saved: "full" }));
        expect(full).toMatchObject({ tone: "on", title: "Connected", mode: "full" });
        expect(full.body).toMatch(/^Full tunnel: all your traffic goes through UBC/);
        expect(full.body).toContain("local network");
        // Only what the computer looks up goes to UBC's DNS: no claim of every address.
        expect(full.body).toContain("name lookups go to UBC’s DNS servers");
        expect(full.body).not.toMatch(/every/);
        expect(TUNNEL.hints.full).toContain("DNS over HTTPS");
        expect(TUNNEL.hints.full).not.toMatch(/every/);
    });

    it("shows a switch under way, and warns that some connections may reset", () => {
        const copy = copyFor(
            connected("split"),
            status({ switching: { from: "split", to: "full" } }),
        );
        expect(copy).toMatchObject({
            // Short, so it keeps to one line.
            tone: "busy",
            title: "Switching",
            mode: "full",
            action: { kind: "disconnect", label: "Disconnect" },
        });
        expect(copy.body).toBe("Moving to full tunnel. The VPN stays connected.");
        // The warning is the choice's own line, the same before and during.
        expect(TUNNEL.live).toContain("may reset");
    });

    it("connects with the saved mode, and shows it while not connected", () => {
        expect(copyFor(CONNECTING, status({ saved: "full" }))).toMatchObject({
            tone: "busy",
            mode: "full",
        });
        expect(copyFor(CONNECTING, status({ saved: "full" })).body).toContain("all your traffic");
        expect(copyFor(DISCONNECTED, status({ saved: "full" })).mode).toBe("full");
        // Nothing known yet: split, the narrower.
        expect(copyFor(DISCONNECTED).mode).toBe("split");
    });

    it("follows the mode in effect over the one saved", () => {
        expect(shownMode(connected("split"), status({ saved: "full" }))).toBe("split");
        expect(shownMode(DISCONNECTED, status({ saved: "full" }))).toBe("full");
        expect(
            shownMode(connected("full"), status({ switching: { from: "full", to: "split" } })),
        ).toBe("split");
    });

    it("gives the tray and the taskbar the full-tunnel shapes in full mode", () => {
        expect(trayKind(connected("full"), status({ saved: "full" }))).toBe("on-full");
        expect(trayKind(connected("split"), status())).toBe("on");
        expect(trayKind(CONNECTING, status({ saved: "full" }))).toBe("busy-full");
        expect(trayKind(CONNECTING, status())).toBe("busy");
        expect(
            trayKind(connected("split"), status({ switching: { from: "split", to: "full" } })),
        ).toBe("busy-full");
        // Off is off, whichever mode is saved.
        expect(trayKind(DISCONNECTED, status({ saved: "full" }))).toBe("off");
    });

    it("says why the mode cannot be changed just now", () => {
        expect(tunnelLocked(DISCONNECTED, UNREAD_TUNNEL, false)).toBe(TUNNEL.unread);
        expect(tunnelLocked(CONNECTING, status(), false)).toBe(TUNNEL.whileConnecting);
        const disconnecting: LinkState = { link: "ready", conn: { state: "disconnecting" } };
        expect(tunnelLocked(disconnecting, status(), false)).toBe(TUNNEL.whileConnecting);
        expect(tunnelLocked(DISCONNECTED, status(), true)).toBe(TUNNEL.whileConnecting);
        expect(tunnelLocked(DISCONNECTED, status(), false)).toBeNull();
        expect(tunnelLocked(connected("split"), status(), false)).toBeNull();
    });

    it("explains every outcome in plain words", () => {
        const plain = (error: string) => `could not: ${error}`;
        expect(
            describeTunnelOutcome(
                {
                    kind: "refused",
                    kept: "split",
                    wanted: "full",
                    message: "No router here.",
                    restored: true,
                },
                plain,
            ),
        ).toEqual({ title: "Still on split tunnel", body: "No router here." });
        expect(describeTunnelOutcome({ kind: "forbidden" }, plain).body).toBe(TUNNEL.forbidden);
        expect(
            describeTunnelOutcome({ kind: "not_saved", wanted: "full", error: "busy" }, plain),
        ).toEqual({ title: "Not switched to full tunnel", body: "could not: busy" });
        expect(
            describeTunnelOutcome({ kind: "unknown", wanted: "full", message: "m" }, plain).title,
        ).toBe("Switch not confirmed");
    });
});

describe("the tray's tunnel menu", () => {
    const chosen: TunnelMode[] = [];
    const actions: TrayActions = {
        showWindow: () => {},
        connect: () => {},
        disconnect: () => {},
        retry: () => {},
        quit: () => {},
        switchProfile: () => {},
        setTunnel: (mode) => chosen.push(mode),
    };
    const submenu = (items: TrayMenuItem[]) =>
        items.find((item) => item.label === TUNNEL.legend)?.submenu ?? [];
    const radios = (items: TrayMenuItem[]) =>
        submenu(items).filter((item) => item.type === "radio");
    const notes = (items: TrayMenuItem[]) =>
        submenu(items)
            .filter((item) => item.type === undefined)
            .map((item) => item.label);

    it("offers both modes, the one in use checked, and switches as the window does", () => {
        const items = trayMenu(connected("split"), null, actions, false, status());
        const [split, full] = radios(items);
        expect(split).toMatchObject({ label: "Split tunnel", checked: true, enabled: true });
        expect(full).toMatchObject({ label: "Full tunnel", checked: false, enabled: true });
        full?.click?.();
        expect(chosen).toEqual(["full"]);
        // Said before anyone switches.
        expect(notes(items)).toEqual([TUNNEL.live]);
    });

    it("does not offer full mode the policy forbids, and says why", () => {
        const items = trayMenu(DISCONNECTED, null, actions, false, status({ fullAllowed: false }));
        const [split, full] = radios(items);
        expect(split?.enabled).toBe(true);
        expect(full?.enabled).toBe(false);
        expect(notes(items)).toEqual([TUNNEL.forbidden]);
    });

    it("cannot be changed while switching, connecting or logging in", () => {
        const during = [
            trayMenu(
                connected("split"),
                null,
                actions,
                false,
                status({ switching: { from: "split", to: "full" } }),
            ),
            trayMenu(CONNECTING, null, actions, false, status()),
            trayMenu(DISCONNECTED, null, actions, true, status()),
        ];
        for (const items of during) {
            expect(radios(items).every((item) => item.enabled === false)).toBe(true);
        }
        // While switching, the one being switched to is checked.
        expect(radios(during[0] ?? [])[1]?.checked).toBe(true);
    });

    it("says what came of a refused switch", () => {
        const items = trayMenu(
            connected("split"),
            null,
            actions,
            false,
            status({
                outcome: {
                    kind: "refused",
                    kept: "split",
                    wanted: "full",
                    message: "No router.",
                    restored: true,
                },
            }),
        );
        expect(notes(items)).toEqual(["Still on split tunnel", "No router.", TUNNEL.live]);
    });

    it("names the mode in the tray's status while connected", () => {
        expect(trayStatus(connected("full"), status({ saved: "full" }))).toBe(
            "Connected, full tunnel",
        );
        expect(trayStatus(connected("split"), status())).toBe("Connected, split tunnel");
        expect(trayStatus(DISCONNECTED, status({ saved: "full" }))).toBe("Not connected");
        expect(
            trayStatus(connected("split"), status({ switching: { from: "split", to: "full" } })),
        ).toBe("Switching to full tunnel");
    });
});
