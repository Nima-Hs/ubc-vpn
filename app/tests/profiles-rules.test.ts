// The demo's stand-in for the profiles commands follows the client's rules
// (`crates/core/src/profiles.rs`), so the screens show the right refusals in
// the demo too; the tray menu lists the profiles; and every request the
// screen sends is checked before anything is started.

import type { LinkState, LoginState } from "@shared/api";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import { describeProfileRefusal } from "@shared/settings-copy";
import { describe, expect, it } from "vitest";
import type { LoginRunner } from "../src/main/channel/connect";
import { withProfile } from "../src/main/channel/connect";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { createDemoProfiles } from "../src/main/demo/demo-profiles";
import { takeId, takeName, takeRename, takeUpdate } from "../src/main/profiles-checks";
import { type TrayActions, type TrayMenuItem, trayMenu } from "../src/main/tray-menu";

const view = async (result: Promise<{ ok: boolean; value?: ProfilesView }>) => {
    const answer = await result;
    expect(answer.ok).toBe(true);
    return answer.value as ProfilesView;
};

describe("profiles, as the demo keeps them", () => {
    it("are made, renamed and switched to, with names unique ignoring case", async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings");
        const made = await view(profiles.create("  Lab  "));
        const lab = made.profiles.find((profile) => profile.name === "Lab");
        expect(lab).toBeDefined();
        await expect(profiles.create("LAB")).resolves.toEqual({ ok: false, error: "name_taken" });
        await expect(profiles.create("   ")).resolves.toEqual({ ok: false, error: "bad_name" });
        await expect(profiles.create("x".repeat(65))).resolves.toEqual({
            ok: false,
            error: "bad_name",
        });
        const id = lab?.id as string;
        const renamed = await view(profiles.rename(id, "Lab 2"));
        expect(renamed.profiles.map((profile) => profile.name)).toEqual(["UBC VPN", "Lab 2"]);
        // Renaming to its own name in another case is no clash.
        await expect(profiles.rename(id, "LAB 2")).resolves.toMatchObject({ ok: true });
        const switched = await view(profiles.switchTo(id));
        expect(switched.global.active_profile).toBe(id);
    });

    it("never deletes the last profile, and moves the active one on when it goes", async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings-profiles");
        const start = await view(profiles.list());
        const [first, second] = start.profiles;
        const after = await view(profiles.remove(first?.id as string));
        expect(after.profiles).toHaveLength(1);
        expect(after.global.active_profile).toBe(second?.id);
        await expect(profiles.remove(second?.id as string)).resolves.toEqual({
            ok: false,
            error: "last_profile",
        });
    });

    it("forgets a saved password when the username changes or saving is turned off", async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings");
        const id = (await view(profiles.list())).global.active_profile;
        const renamed = await view(profiles.rename(id, "Campus"));
        expect(renamed.profiles[0]?.password_saved).toBe(true);
        const changed = await view(profiles.update(id, { username: "someone.else.example" }));
        expect(changed.profiles[0]).toMatchObject({
            username: "someone.else.example",
            password_saved: false,
        });
        profiles.setScenario("settings");
        const off = await view(profiles.update(id, { save_password: false }));
        expect(off.profiles[0]).toMatchObject({ save_password: false, password_saved: false });
    });

    it("refuses at most 32 profiles", async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings");
        for (let made = 2; made <= 32; made++) {
            await expect(profiles.create(`Profile ${made}`)).resolves.toMatchObject({ ok: true });
        }
        await expect(profiles.create("One too many")).resolves.toEqual({
            ok: false,
            error: "too_many_profiles",
        });
    });
});

describe("the tray menu", () => {
    const actions: TrayActions = {
        showWindow: () => {},
        connect: () => {},
        disconnect: () => {},
        retry: () => {},
        quit: () => {},
        switchProfile: () => {},
        setTunnel: () => {},
    };
    const disconnected: LinkState = { link: "ready", conn: { state: "disconnected" } };
    const two = async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings-profiles");
        return view(profiles.list());
    };
    const submenu = (items: TrayMenuItem[]) =>
        items.find((item) => item.label === "Profile")?.submenu;

    it("lists the profiles when there is a choice, the active one checked", async () => {
        const items = trayMenu(disconnected, await two(), actions);
        expect(
            submenu(items)?.map(({ label, type, checked }) => ({ label, type, checked })),
        ).toEqual([
            { label: "UBC VPN", type: "radio", checked: true },
            { label: "Lab", type: "radio", checked: false },
        ]);
    });

    it("has no list with one profile, or before the profiles are known", async () => {
        const one = createDemoProfiles();
        one.setScenario("settings");
        expect(submenu(trayMenu(disconnected, await view(one.list()), actions))).toBeUndefined();
        expect(submenu(trayMenu(disconnected, null, actions))).toBeUndefined();
    });

    it("says, while connected, that a choice applies to the next connect", async () => {
        const connected: LinkState = {
            link: "ready",
            conn: {
                state: "connected",
                tunnel: {
                    interface: "utun4",
                    mode: "split",
                    address: "198.51.100.42",
                    subnets: [],
                    dns_domains: [],
                },
            },
        };
        const [note] = submenu(trayMenu(connected, await two(), actions)) ?? [];
        expect(note).toEqual({ label: "Takes effect the next time you connect.", enabled: false });
    });

    it("switches by the profile's id", async () => {
        const chosen: string[] = [];
        const view = await two();
        const items = submenu(
            trayMenu(disconnected, view, { ...actions, switchProfile: (id) => chosen.push(id) }),
        );
        items?.[1]?.click?.();
        expect(chosen).toEqual([view.profiles[1]?.id]);
    });
});

describe("what the screen may send for profiles", () => {
    const ID = "0123456789abcdef0123456789abcdef";

    it("is a name, or an id and a name, of bounded length", () => {
        expect(takeName(["Lab"])).toBe("Lab");
        expect(takeRename([ID, "Lab"])).toEqual([ID, "Lab"]);
        for (const args of [[], [42], ["x".repeat(257)], ["Lab", "extra"]]) {
            expect(() => takeName(args), JSON.stringify(args).slice(0, 40)).toThrow("refused");
        }
        for (const args of [["not-an-id", "Lab"], [ID], [ID, 42]]) {
            expect(() => takeRename(args), JSON.stringify(args)).toThrow("refused");
        }
    });

    it("changes only a username and whether the password is saved", () => {
        expect(takeUpdate([ID, { username: "someone" }])).toEqual([ID, { username: "someone" }]);
        expect(takeUpdate([ID, { username: null, save_password: false }])).toEqual([
            ID,
            { username: null, save_password: false },
        ]);
        const refused: unknown[][] = [
            [ID, {}],
            [ID, { password: "x" }],
            [ID, { username: "someone", password: "x" }],
            [ID, { save_password: "yes" }],
            [ID, { username: 42 }],
            [ID, null],
            [ID, ["username"]],
            ["not-an-id", { username: "someone" }],
        ];
        for (const args of refused) {
            expect(() => takeUpdate(args), JSON.stringify(args)).toThrow("refused");
        }
    });

    it("names a profile by its id for delete and switch, never the active one by null", () => {
        expect(takeId([ID])).toBe(ID);
        for (const args of [[null], [], ["x"], [ID, ID]]) {
            expect(() => takeId(args), JSON.stringify(args)).toThrow("refused");
        }
    });
});

describe("a saved password that could not be cleared", () => {
    it("keeps saving off, and says why, as the keyring allows", async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings-old-password-stuck");
        const id = (await view(profiles.list())).global.active_profile;
        await expect(profiles.update(id, { save_password: true })).resolves.toEqual({
            ok: false,
            error: "keyring_not_cleared",
        });
        expect((await view(profiles.list())).profiles[0]?.save_password).toBe(false);
        expect(describeProfileRefusal("keyring_not_cleared")).toBe(
            "UBC VPN couldn't remove the old saved password, so saving stays off.",
        );
        expect(describeProfileRefusal("keyring_not_cleared", "unavailable")).toBe(
            "The keyring can't be used, so saving stays off.",
        );
    });
});

describe("a login, bound to its profile", () => {
    const ID = "0123456789abcdef0123456789abcdef";

    it("starts the client with --profile after connect, and nothing for the active one", () => {
        expect(withProfile(["connect", "--json"], ID)).toEqual([
            "connect",
            "--profile",
            ID,
            "--json",
        ]);
        expect(withProfile(["--dev", "connect", "--json"], ID)).toEqual([
            "--dev",
            "connect",
            "--profile",
            ID,
            "--json",
        ]);
        expect(withProfile(["connect", "--json"], null)).toEqual(["connect", "--json"]);
        // Never anything that is not an id.
        expect(withProfile(["connect", "--json"], "--json; rm")).toEqual(["connect", "--json"]);
    });

    it("keeps the profile it started with, whatever is chosen while it runs", async () => {
        let active = ID;
        const started: (string | null | undefined)[] = [];
        let report: (state: LoginState) => void = () => {};
        const runner: LoginRunner = {
            start: (profile) => {
                started.push(profile);
                report({ phase: "working" });
                return true;
            },
            answer: () => true,
            cancel: () => {},
            stop: () => {},
            windDown: () => null,
        };
        const controller = new Controller(createDemoLink(10), (onState) => {
            report = onState;
            return runner;
        });
        controller.setProfileForLogin(() => active);
        await controller.connect();
        expect(started).toEqual([ID]);
        expect(controller.getSnapshot().loginProfile).toBe(ID);
        // Another profile is chosen while it runs: the login keeps its own.
        active = "fedcba9876543210fedcba9876543210";
        report({ phase: "working" });
        expect(controller.getSnapshot().loginProfile).toBe(ID);
        // Once it ends, it is for nobody.
        report({ phase: "idle" });
        expect(controller.getSnapshot().loginProfile).toBeNull();
        controller.dispose();
    });
});

describe("the tray menu during a login", () => {
    it("keeps the profiles as they are, and says why", async () => {
        const profiles = createDemoProfiles();
        profiles.setScenario("settings-profiles");
        const actions: TrayActions = {
            showWindow: () => {},
            connect: () => {},
            disconnect: () => {},
            retry: () => {},
            quit: () => {},
            switchProfile: () => {},
            setTunnel: () => {},
        };
        const items = trayMenu(
            { link: "ready", conn: { state: "disconnected" } },
            await view(profiles.list()),
            actions,
            true,
        );
        const submenu = items.find((item) => item.label === "Profile")?.submenu ?? [];
        expect(submenu[0]).toEqual({
            label: "You can change profile once this login ends.",
            enabled: false,
        });
        expect(submenu.slice(1).every((item) => item.enabled === false)).toBe(true);
    });
});
