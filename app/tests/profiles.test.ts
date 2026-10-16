// The profiles commands, as the main process runs them: against a stand-in
// that follows `crates/cli/src/profiles.rs`. Made-up names and values only.

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import { afterEach, describe, expect, it } from "vitest";
import { PROFILES_ARGS, ProfilesRunner } from "../src/main/channel/profiles";
import { takeProfile, takeStartup } from "../src/main/profiles-checks";

const ID = "0123456789abcdef0123456789abcdef";
// A character that reverses text direction, and a NUL, written by code
// so neither is ever in this file itself.
const RLO = String.fromCharCode(0x202e);
const NUL = String.fromCharCode(0);
const LF = String.fromCharCode(10);
const OTHER = "fedcba9876543210fedcba9876543210";

const VIEW: ProfilesView = {
    global: { start: "off", auto_connect: false, active_profile: ID },
    profiles: [
        {
            id: ID,
            name: "Campus",
            username: "someone.example",
            routes: { subnets: ["203.0.113.0/24"], dns_domains: ["campus.example"] },
            save_password: true,
            password_saved: true,
        },
        {
            id: OTHER,
            name: "Lab",
            username: null,
            routes: { subnets: [], dns_domains: [] },
            save_password: false,
            password_saved: false,
        },
    ],
    keyring: "available",
    policy_readable: true,
    allowed_routes: null,
};

type Answer = { line?: unknown; raw?: string; exit?: number; hang?: boolean };

const runners: ProfilesRunner[] = [];
afterEach(() => {
    for (const runner of runners.splice(0)) {
        runner.stop();
    }
});

function client(answers: Record<string, Answer>, timeoutMs = 10_000) {
    const dir = mkdtempSync(join(tmpdir(), "ubc-vpn-profiles-"));
    const config = join(dir, "config.json");
    const log = join(dir, "log");
    writeFileSync(config, JSON.stringify({ answers, log }));
    const runner = new ProfilesRunner({
        command: process.execPath,
        leadingArgs: [join(__dirname, "mock-profiles.mjs"), config],
        timeoutMs,
    });
    runners.push(runner);
    const received = () =>
        existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean) : [];
    return { runner, received };
}

describe("the profiles commands", () => {
    it("lists the profiles with the shared settings", async () => {
        const { runner, received } = client({ "profiles list": { line: VIEW } });
        await expect(runner.list()).resolves.toEqual({ ok: true, value: VIEW });
        expect(received()).toEqual([`args:${JSON.stringify(PROFILES_ARGS.list)}`]);
    });

    it("sends the startup choice as the contract names it, and nothing else", async () => {
        const changed = { ...VIEW, global: { ...VIEW.global, start: "tray", auto_connect: true } };
        const { runner, received } = client({
            "settings set-startup": { line: changed },
        });
        await expect(runner.setStartup("tray", true)).resolves.toEqual({
            ok: true,
            value: changed,
        });
        expect(received()).toEqual([
            `args:${JSON.stringify(PROFILES_ARGS.setStartup)}`,
            `input:${JSON.stringify({ start: "tray", auto_connect: true })}`,
        ]);
    });

    it("forgets a profile's saved password by its id, or the active one's", async () => {
        const { runner, received } = client({ "password forget": { line: VIEW } });
        await expect(runner.forgetPassword(OTHER)).resolves.toMatchObject({ ok: true });
        await expect(runner.forgetPassword(null)).resolves.toMatchObject({ ok: true });
        expect(received().filter((line) => line.startsWith("input:"))).toEqual([
            `input:${JSON.stringify({ id: OTHER })}`,
            `input:${JSON.stringify({ id: null })}`,
        ]);
    });

    it("refuses an id that is not one before starting anything", async () => {
        const { runner, received } = client({ "password forget": { line: VIEW } });
        await expect(runner.forgetPassword("../../etc")).resolves.toEqual({
            ok: false,
            error: "bad_input",
        });
        expect(received()).toEqual([]);
    });

    it("passes on a refusal by the rules, and the client's own failures", async () => {
        for (const error of ["unknown_profile", "unreadable", "unwritable", "bad_input"]) {
            const { runner } = client({ "password forget": { line: { error }, exit: 1 } });
            await expect(runner.forgetPassword(ID)).resolves.toEqual({ ok: false, error });
        }
    });

    it("treats anything else as the client being unusable", async () => {
        const bad: Answer[] = [
            // A refusal with the wrong status, or an answer with one.
            { line: { error: "unknown_profile" }, exit: 0 },
            { line: VIEW, exit: 1 },
            // A code the contract does not have.
            { line: { error: "something_else" }, exit: 1 },
            // A view that breaks the contract's rules.
            { line: { ...VIEW, profiles: [] } },
            { line: { ...VIEW, global: { ...VIEW.global, active_profile: "not-an-id" } } },
            { line: { ...VIEW, profiles: [VIEW.profiles[0], VIEW.profiles[0]] } },
            { line: { ...VIEW, global: { ...VIEW.global, start: "sometimes" } } },
            // Not one line.
            { raw: `${JSON.stringify(VIEW)}\n${JSON.stringify(VIEW)}\n` },
            { raw: "not json\n" },
        ];
        for (const answer of bad) {
            const { runner } = client({ "profiles list": answer });
            await expect(runner.list(), JSON.stringify(answer).slice(0, 80)).resolves.toEqual({
                ok: false,
                error: "unavailable",
            });
        }
    });

    it("gives up on a client that takes too long", async () => {
        const { runner } = client({ "profiles list": { hang: true } }, 400);
        await expect(runner.list()).resolves.toEqual({ ok: false, error: "unavailable" });
    });

    it("makes one change at a time", async () => {
        const { runner } = client({ "settings set-startup": { hang: true } }, 2_000);
        const first = runner.setStartup("window", false);
        await expect(runner.forgetPassword(null)).resolves.toEqual({ ok: false, error: "busy" });
        runner.stop();
        await expect(first).resolves.toEqual({ ok: false, error: "unavailable" });
    });

    it("gives the interface only the fields it needs, never a password", async () => {
        const secret = "Sentinel-pw-profiles-not-real";
        // A client that answered with more than the contract: a password at
        // every level, and fields nobody asked for.
        const extra = {
            ...VIEW,
            password: secret,
            global: { ...VIEW.global, password: secret },
            profiles: VIEW.profiles.map((profile) => ({
                ...profile,
                password: secret,
                secret,
                routes: { ...profile.routes, password: secret },
            })),
        };
        const { runner } = client({ "profiles list": { line: extra } });
        const result = await runner.list();
        expect(result).toEqual({ ok: true, value: VIEW });
        expect(JSON.stringify(result)).not.toContain(secret);
        expect(JSON.stringify(result)).not.toContain('password":"');
    });

    it("cleans text from the settings file before the interface sees it", async () => {
        const tricky: ProfilesView = {
            ...VIEW,
            profiles: [
                {
                    ...(VIEW.profiles[0] as ProfilesView["profiles"][number]),
                    // A line break and a character that reverses text direction.
                    name: `Campus${LF}fake line${RLO}`,
                    username: `someone${NUL}.example`,
                },
            ],
        };
        const { runner } = client({ "profiles list": { line: tricky } });
        const result = await runner.list();
        expect(result.ok).toBe(true);
        const [profile] = result.ok ? result.value.profiles : [];
        expect(profile?.name).not.toContain(LF);
        expect(profile?.name).not.toContain(RLO);
        expect(profile?.username).not.toContain(NUL);
    });
});

describe("what the Settings screen may ask the main process", () => {
    it("is a startup choice and a yes or no, where the OS can start the app", () => {
        expect(takeStartup(["tray", true], "win32")).toEqual(["tray", true]);
        expect(takeStartup(["off", false], "linux")).toEqual(["off", false]);
        const refused: [unknown[], NodeJS.Platform][] = [
            [["sometimes", true], "win32"],
            [["tray", "yes"], "win32"],
            [["tray"], "win32"],
            [["tray", true, "extra"], "win32"],
            [[{ start: "tray" }, true], "win32"],
            // Linux has no way to start the app at sign-in yet.
            [["window", false], "linux"],
        ];
        for (const [args, platform] of refused) {
            expect(() => takeStartup(args, platform), JSON.stringify(args)).toThrow("refused");
        }
    });

    it("names a profile by its id, or the active one by null, and nothing else", () => {
        expect(takeProfile([ID])).toBe(ID);
        expect(takeProfile([null])).toBeNull();
        const refused: unknown[][] = [
            [],
            [undefined],
            ["../x"],
            [ID.toUpperCase()],
            [ID, ID],
            [{ id: ID }],
        ];
        for (const args of refused) {
            expect(() => takeProfile(args), JSON.stringify(args)).toThrow("refused");
        }
    });
});

describe("the commands that change profiles", () => {
    const inputs = (lines: string[]) =>
        lines.filter((line) => line.startsWith("input:")).map((line) => JSON.parse(line.slice(6)));

    it("send exactly what the contract names", async () => {
        const { runner, received } = client({
            "profiles create": { line: VIEW },
            "profiles rename": { line: VIEW },
            "profiles update": { line: VIEW },
            "profiles delete": { line: VIEW },
            "profiles switch": { line: VIEW },
        });
        await runner.create("Lab");
        await runner.rename(OTHER, "Lab 2");
        await runner.update(OTHER, { username: "someone.lab@app" });
        await runner.update(OTHER, { save_password: false });
        // Anything else passed in is left behind.
        await runner.update(OTHER, {
            username: null,
            ...({ password: "not-sent" } as object),
        });
        await runner.remove(OTHER);
        await runner.switchTo(OTHER);
        expect(inputs(received())).toEqual([
            { name: "Lab", username: null, routes: null, save_password: false },
            { id: OTHER, name: "Lab 2" },
            { id: OTHER, username: "someone.lab@app" },
            { id: OTHER, save_password: false },
            { id: OTHER, username: null },
            { id: OTHER },
            { id: OTHER },
        ]);
        expect(received().filter((line) => line.startsWith("args:"))).toEqual(
            [
                PROFILES_ARGS.create,
                PROFILES_ARGS.rename,
                PROFILES_ARGS.update,
                PROFILES_ARGS.update,
                PROFILES_ARGS.update,
                PROFILES_ARGS.remove,
                PROFILES_ARGS.switchTo,
            ].map((args) => `args:${JSON.stringify(args)}`),
        );
    });

    it("asks once more when the id the client drew was taken, and only once", async () => {
        const { runner, received } = client({
            "profiles create": { line: { error: "id_taken" }, exit: 1 },
        });
        await expect(runner.create("Lab")).resolves.toEqual({ ok: false, error: "id_taken" });
        expect(inputs(received())).toHaveLength(2);
    });

    it("passes on the rules' refusals", async () => {
        for (const error of ["bad_name", "name_taken", "too_many_profiles", "last_profile"]) {
            const { runner } = client({ "profiles delete": { line: { error }, exit: 1 } });
            await expect(runner.remove(OTHER)).resolves.toEqual({ ok: false, error });
        }
    });

    it("starts nothing for an id that is not one", async () => {
        const { runner, received } = client({ "profiles switch": { line: VIEW } });
        for (const call of [
            () => runner.switchTo("x"),
            () => runner.remove("../etc"),
            () => runner.rename("", "Lab"),
            () => runner.update(ID.toUpperCase(), { username: null }),
        ]) {
            await expect(call()).resolves.toEqual({ ok: false, error: "bad_input" });
        }
        expect(received()).toEqual([]);
    });
});
