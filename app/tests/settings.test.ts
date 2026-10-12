// Reading settings and checking and saving routes through the command-line
// client, run against a mock that follows `crates/core/src/settings_cli.rs`.
// Each case in that file's "The cases" has a test here.

import { type SpawnOptions, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { inspect } from "node:util";
import type { RouteInput } from "@shared/protocol/RouteInput";
import { afterEach, describe, expect, it, vi } from "vitest";
import { settingsCommand } from "../src/main/channel/cli";
import { MAX_LINE_BYTES } from "../src/main/channel/framing";
import { MAX_SHOWN_LENGTH, SETTINGS_ARGS, SettingsRunner } from "../src/main/channel/settings";
import { isRoutesReply, isSettingsFailure, isSettingsView } from "../src/main/channel/validate";
import { MAX_ROUTE_ENTRIES, MAX_ROUTE_ENTRY_LENGTH, takeRouteInput } from "../src/main/ipc";
import { stopForQuit } from "../src/main/quit";
import { alive, pause, until } from "./bridge-harness";

// The real `spawn`, watched: some tests read how the client was started.
vi.mock("node:child_process", async (original) => {
    const actual = await original<typeof import("node:child_process")>();
    return { ...actual, spawn: vi.fn(actual.spawn) };
});

type Answer = { line?: unknown; raw?: string; exit?: number; hang?: true; stay?: true };

const VIEW = {
    settings: {
        username: "someone",
        routes: { subnets: ["203.0.113.0/24"], dns_domains: ["campus.example"] },
        save_password: false,
    },
    policy_readable: true,
    allowed_routes: ["203.0.113.0/24", "198.51.100.0/24"],
    min_prefix_len: 8,
    max_routes: 256,
};
const INPUT: RouteInput = { subnets: ["203.0.113.0/24", "bad"], dns_domains: ["campus.example"] };
const OK = { type: "ok", routes: { subnets: ["203.0.113.0/24"], dns_domains: ["campus.example"] } };
const INVALID = { type: "invalid", problems: [{ code: "bad_subnet", list: "subnets", index: 1 }] };

const runners: SettingsRunner[] = [];

afterEach(() => {
    for (const runner of runners.splice(0)) {
        runner.stop();
    }
});

function client(
    answers: { get?: Answer; check?: Answer; save?: Answer },
    options: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
) {
    const dir = mkdtempSync(join(tmpdir(), "ubc-vpn-settings-"));
    const config = join(dir, "config.json");
    const log = join(dir, "log");
    const pids = join(dir, "pids");
    writeFileSync(config, JSON.stringify({ ...answers, log, pids }));
    const lines = (file: string) =>
        existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean) : [];
    const runner = new SettingsRunner({
        command: process.execPath,
        leadingArgs: [join(__dirname, "mock-settings.mjs"), config],
        timeoutMs: 10_000,
        ...options,
    });
    runners.push(runner);
    return { runner, received: () => lines(log), pids: () => lines(pids).map(Number) };
}

describe("the output of a command", () => {
    it("is a view, with status 0, for get", async () => {
        const { runner } = client({ get: { line: VIEW, exit: 0 } });
        await expect(runner.getSettings()).resolves.toEqual({ ok: true, value: VIEW });
    });

    it("is a routes reply, with status 0, for a check: acceptable or not", async () => {
        const accepted = client({ check: { line: OK, exit: 0 } });
        await expect(accepted.runner.checkRoutes(INPUT)).resolves.toEqual({ ok: true, value: OK });
        const refused = client({ check: { line: INVALID, exit: 0 } });
        await expect(refused.runner.checkRoutes(INPUT)).resolves.toEqual({
            ok: true,
            value: INVALID,
        });
    });

    it.each(["bad_input", "unreadable", "unwritable"] as const)(
        "is the failure %s, with status 1",
        async (error) => {
            const { runner } = client({
                get: { line: { error }, exit: 1 },
                save: { line: { error }, exit: 1 },
            });
            await expect(runner.getSettings()).resolves.toEqual({ ok: false, error });
            await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: false, error });
        },
    );

    it.each([
        ["a view with status 1", { line: VIEW, exit: 1 }],
        ["a failure with status 0", { line: { error: "unreadable" }, exit: 0 }],
        ["a routes reply where a view belongs", { line: OK, exit: 0 }],
        ["a failure with an unknown code", { line: { error: "gremlins" }, exit: 1 }],
        ["a view with a field missing", { line: { ...VIEW, max_routes: undefined }, exit: 0 }],
        [
            "a view whose prefix length is not one",
            { line: { ...VIEW, min_prefix_len: 99 }, exit: 0 },
        ],
        [
            "a view whose routes are not text",
            {
                line: {
                    ...VIEW,
                    settings: { ...VIEW.settings, routes: { subnets: [1], dns_domains: [] } },
                },
                exit: 0,
            },
        ],
        ["two lines", { raw: `${JSON.stringify(VIEW)}\n${JSON.stringify(VIEW)}\n`, exit: 0 }],
        ["a line and then more", { raw: `${JSON.stringify(VIEW)}\nextra`, exit: 0 }],
        ["a line with no end", { raw: JSON.stringify(VIEW), exit: 0 }],
        ["nothing at all", { raw: "", exit: 0 }],
        ["something that is not JSON", { raw: "this is not json\n", exit: 0 }],
        ["more than 64 KiB", { raw: `{"settings":"${"x".repeat(MAX_LINE_BYTES)}"}\n`, exit: 0 }],
    ] as [string, Answer][])("counts %s as the client being unusable", async (_name, answer) => {
        const { runner } = client({ get: answer });
        await expect(runner.getSettings()).resolves.toEqual({ ok: false, error: "unavailable" });
    });

    it.each([
        ["a view where a routes reply belongs", { line: VIEW, exit: 0 }],
        ["a reply of an unknown type", { line: { type: "maybe" }, exit: 0 }],
        ["an 'invalid' with no problems", { line: { type: "invalid", problems: [] }, exit: 0 }],
        [
            "a problem with an unknown code",
            {
                line: {
                    type: "invalid",
                    problems: [{ code: "gremlins", list: null, index: null }],
                },
                exit: 0,
            },
        ],
        [
            "a problem in an unknown list",
            {
                line: {
                    type: "invalid",
                    problems: [{ code: "bad_subnet", list: "__proto__", index: 0 }],
                },
                exit: 0,
            },
        ],
        [
            "a problem pointing past the entries that were sent",
            {
                line: {
                    type: "invalid",
                    problems: [{ code: "bad_subnet", list: "subnets", index: 2 }],
                },
                exit: 0,
            },
        ],
        [
            "a problem with a list and no index",
            {
                line: {
                    type: "invalid",
                    problems: [{ code: "bad_subnet", list: "subnets", index: null }],
                },
                exit: 0,
            },
        ],
        ["a routes reply with status 1", { line: OK, exit: 1 }],
    ] as [string, Answer][])("counts %s as the client being unusable", async (_name, answer) => {
        const { runner } = client({ check: answer, save: answer });
        await expect(runner.checkRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
    });

    it("accepts a problem with the whole input, which names no entry", async () => {
        const whole = {
            type: "invalid",
            problems: [{ code: "no_subnets", list: null, index: null }],
        };
        const { runner } = client({ check: { line: whole, exit: 0 } });
        await expect(runner.checkRoutes({ subnets: [], dns_domains: [] })).resolves.toEqual({
            ok: true,
            value: whole,
        });
    });
});

describe("text from the user's own files", () => {
    // Anything running as the user can write these files, so what they hold
    // is cleaned before the interface sees it, as text from a login is.
    const BACKWARDS = "\u202e";
    const dirty = (text: string) => `${BACKWARDS}${text}\n\tmore\u0007`;

    it("is made plain in a view: the username, the routes and the allowed routes", async () => {
        const view = {
            ...VIEW,
            settings: {
                ...VIEW.settings,
                username: dirty("someone"),
                routes: { subnets: [dirty("203.0.113.0/24")], dns_domains: [dirty("a.example")] },
            },
            allowed_routes: [dirty("198.51.100.0/24"), "x".repeat(MAX_SHOWN_LENGTH + 50)],
        };
        const { runner } = client({ get: { line: view, exit: 0 } });
        await expect(runner.getSettings()).resolves.toEqual({
            ok: true,
            value: {
                ...VIEW,
                settings: {
                    ...VIEW.settings,
                    username: "someone more",
                    routes: { subnets: ["203.0.113.0/24 more"], dns_domains: ["a.example more"] },
                },
                allowed_routes: ["198.51.100.0/24 more", "x".repeat(MAX_SHOWN_LENGTH)],
            },
        });
    });

    it("is made plain in the routes a check or a save answers with", async () => {
        const reply = { type: "ok", routes: { subnets: [dirty("a")], dns_domains: [dirty("b")] } };
        const plain = { type: "ok", routes: { subnets: ["a more"], dns_domains: ["b more"] } };
        const { runner } = client({
            check: { line: reply, exit: 0 },
            save: { line: reply, exit: 0 },
        });
        await expect(runner.checkRoutes(INPUT)).resolves.toEqual({ ok: true, value: plain });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: true, value: plain });
    });

    it("keeps every entry in its place, so a problem still points at the right one", async () => {
        const view = {
            ...VIEW,
            settings: {
                ...VIEW.settings,
                routes: { subnets: [BACKWARDS, "203.0.113.0/24"], dns_domains: [] },
            },
        };
        const { runner } = client({ get: { line: view, exit: 0 } });
        const result = await runner.getSettings();
        expect(result.ok && result.value.settings.routes.subnets).toEqual(["", "203.0.113.0/24"]);
        // No username stays no username.
        const none = client({
            get: { line: { ...VIEW, settings: { ...VIEW.settings, username: null } }, exit: 0 },
        });
        const answer = await none.runner.getSettings();
        expect(answer.ok && answer.value.settings.username).toBeNull();
    });
});

describe("the input of a command", () => {
    it("is one line on standard input, and never on the command line", async () => {
        const typed = {
            subnets: ["203.0.113.0/24", "; rm -rf ~", "--help"],
            dns_domains: ["$(whoami)"],
        };
        const { runner, received } = client({
            check: { line: OK, exit: 0 },
            save: { line: OK, exit: 0 },
        });
        await runner.checkRoutes(typed);
        await runner.saveRoutes(typed);
        expect(received()).toEqual([
            'args:["settings","check-routes","--json"]',
            `input:${JSON.stringify(typed)}`,
            'args:["settings","set-routes","--json"]',
            `input:${JSON.stringify(typed)}`,
            "saved",
        ]);
    });

    it("is nothing at all for get", async () => {
        const { runner, received } = client({ get: { line: VIEW, exit: 0 } });
        await runner.getSettings();
        expect(received()).toEqual(['args:["settings","get","--json"]', "input:not read"]);
    });

    it("holds only the two lists, whatever else came with them", async () => {
        const { runner, received } = client({ check: { line: OK, exit: 0 } });
        await runner.checkRoutes({ ...INPUT, extra: "ignored" } as RouteInput);
        expect(received()[1]).toBe(`input:${JSON.stringify(INPUT)}`);
    });

    it("that is too long for a line is bad input, and starts nothing", async () => {
        const spawned = vi.mocked(spawn);
        const { runner } = client({ check: { line: OK, exit: 0 } });
        spawned.mockClear();
        const long = {
            subnets: Array.from({ length: 200 }, () => "x".repeat(400)),
            dns_domains: [],
        };
        await expect(runner.checkRoutes(long)).resolves.toEqual({ ok: false, error: "bad_input" });
        expect(spawned).not.toHaveBeenCalled();
    });

    it("the client cannot read comes back as bad input, as the contract says", async () => {
        // The mock applies the rule itself when it is given no line it can use.
        const { runner } = client({});
        await expect(runner.checkRoutes(INPUT)).resolves.toEqual({ ok: false, error: "bad_input" });
    });
});

describe("the files behind the commands", () => {
    it("no settings file: get answers with the defaults", async () => {
        const defaults = {
            ...VIEW,
            settings: {
                username: null,
                routes: { subnets: [], dns_domains: [] },
                save_password: false,
            },
        };
        const { runner } = client({ get: { line: defaults, exit: 0 } });
        await expect(runner.getSettings()).resolves.toEqual({ ok: true, value: defaults });
    });

    it("a settings file that cannot be read: get and save fail, a check does not", async () => {
        const unreadable = { line: { error: "unreadable" }, exit: 1 };
        const { runner, received } = client({
            get: unreadable,
            save: unreadable,
            check: { line: OK, exit: 0 },
        });
        await expect(runner.getSettings()).resolves.toEqual({ ok: false, error: "unreadable" });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: false, error: "unreadable" });
        await expect(runner.checkRoutes(INPUT)).resolves.toMatchObject({ ok: true });
        expect(received()).not.toContain("saved");
    });

    it("a policy that is missing: nothing fails, and the view says so", async () => {
        const noPolicy = { ...VIEW, policy_readable: false, allowed_routes: null };
        const { runner } = client({
            get: { line: noPolicy, exit: 0 },
            check: { line: OK, exit: 0 },
        });
        await expect(runner.getSettings()).resolves.toEqual({ ok: true, value: noPolicy });
        await expect(runner.checkRoutes(INPUT)).resolves.toMatchObject({ ok: true });
    });

    it("a save that fails says so, and nothing was saved", async () => {
        const { runner, received } = client({ save: { line: { error: "unwritable" }, exit: 1 } });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: false, error: "unwritable" });
        expect(received()).not.toContain("saved");
    });

    it("a save can refuse, as bad input, routes that a check accepted", async () => {
        // The reply or the settings view would not fit in a line.
        const { runner } = client({
            check: { line: OK, exit: 0 },
            save: { line: { error: "bad_input" }, exit: 1 },
        });
        await expect(runner.checkRoutes(INPUT)).resolves.toMatchObject({ ok: true });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: false, error: "bad_input" });
    });

    it("a save whose entries are not acceptable saves nothing", async () => {
        const { runner, received } = client({ save: { line: INVALID, exit: 0 } });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: true, value: INVALID });
        expect(received()).not.toContain("saved");
    });
});

describe("a client that does not behave", () => {
    it("is given a time limit, and is ended when it runs out", async () => {
        const { runner, pids } = client({ get: { hang: true } }, { timeoutMs: 300 });
        const started = Date.now();
        await expect(runner.getSettings()).resolves.toEqual({ ok: false, error: "unavailable" });
        expect(Date.now() - started).toBeGreaterThanOrEqual(290);
        const [pid = 0] = pids();
        await until(() => !alive(pid), "the client ending");
    });

    it("is given up on when the limit passes, even if it ignores being ended", async () => {
        const real =
            await vi.importActual<typeof import("node:child_process")>("node:child_process");
        const { runner, pids } = client({ save: { hang: true } }, { timeoutMs: 400 });
        vi.mocked(spawn).mockImplementationOnce(((...args: Parameters<typeof real.spawn>) => {
            const child = real.spawn(...args);
            child.kill = () => true;
            return child;
        }) as typeof spawn);
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
        await until(() => pids().length === 1, "the client starting");
        const [stubborn = 0] = pids();
        expect(alive(stubborn)).toBe(true);
        // The save it held is over: the next one is taken, not turned away.
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
        process.kill(stubborn);
        await until(() => !alive(stubborn), "the stubborn client ending");
    });

    it("is ended as soon as it writes more than a line may hold, without waiting out the limit", async () => {
        const { runner, pids } = client(
            { get: { raw: "x".repeat(MAX_LINE_BYTES + 10), stay: true } },
            { timeoutMs: 60_000 },
        );
        const started = Date.now();
        await expect(runner.getSettings()).resolves.toEqual({ ok: false, error: "unavailable" });
        expect(Date.now() - started).toBeLessThan(4000);
        const [pid = 0] = pids();
        await until(() => !alive(pid), "the client ending");
    });

    it("that is missing is unusable, not a crash", async () => {
        const runner = new SettingsRunner({
            command: settingsCommand(
                { isPackaged: true },
                { resourcesPath: "/nowhere/that/exists", platform: process.platform, env: {} },
            ),
        });
        runners.push(runner);
        await expect(runner.getSettings()).resolves.toEqual({ ok: false, error: "unavailable" });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
    });

    it("that cannot be started at all is unusable, not a crash", async () => {
        const { runner } = client({ get: { line: VIEW, exit: 0 } });
        // What Windows does for a file that is there but is not a program.
        vi.mocked(spawn).mockImplementationOnce(() => {
            throw new Error("spawn UNKNOWN");
        });
        await expect(runner.getSettings()).resolves.toEqual({ ok: false, error: "unavailable" });
        // The next call is not affected.
        await expect(runner.getSettings()).resolves.toMatchObject({ ok: true });
    });

    it("is ended when the app stops", async () => {
        const { runner, pids } = client({ get: { hang: true } });
        const waiting = runner.getSettings();
        await until(() => pids().length === 1, "the client starting");
        const [pid = 0] = pids();
        runner.stop();
        await expect(waiting).resolves.toEqual({ ok: false, error: "unavailable" });
        await until(() => !alive(pid), "the client ending");
    });
});

describe("when the app quits", () => {
    it("stops the controller, then the settings clients, then the tray", () => {
        const order: string[] = [];
        const part = (name: string) => () => void order.push(name);
        stopForQuit(
            { dispose: part("controller") },
            { stop: part("settings") },
            { destroy: part("tray") },
        );
        expect(order).toEqual(["controller", "settings", "tray"]);
        // Where there is no tray, the rest still stops.
        stopForQuit({ dispose: part("controller") }, { stop: part("settings") }, null);
        expect(order).toHaveLength(5);
    });
});

describe("one thing at a time", () => {
    it("starts one client for everyone reading the settings at once", async () => {
        const { runner, pids } = client({ get: { line: VIEW, exit: 0 } });
        const answers = await Promise.all(Array.from({ length: 60 }, () => runner.getSettings()));
        expect(pids()).toHaveLength(1);
        expect(answers.every((answer) => answer.ok)).toBe(true);
        // A read after that one is a fresh read, not an old answer kept.
        await runner.getSettings();
        expect(pids()).toHaveLength(2);
    });

    it("never ends a save under way to make room for a check", async () => {
        const { runner, pids } = client({ save: { hang: true }, check: { line: OK, exit: 0 } });
        const saving = runner.saveRoutes(INPUT);
        await until(() => pids().length === 1, "the save starting");
        const [save = 0] = pids();
        await expect(runner.checkRoutes(INPUT)).resolves.toMatchObject({ ok: true });
        const burst = Array.from({ length: 5 }, () => runner.checkRoutes(INPUT));
        await expect(burst.at(-1)).resolves.toMatchObject({ ok: true });
        expect(alive(save)).toBe(true);
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: false, error: "busy" });
        runner.stop();
        await expect(saving).resolves.toEqual({ ok: false, error: "unavailable" });
    });

    it("refuses a second save while one is under way, and takes the next after it", async () => {
        const { runner, received } = client({ save: { line: OK, exit: 0 } });
        const first = runner.saveRoutes(INPUT);
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({ ok: false, error: "busy" });
        await expect(first).resolves.toMatchObject({ ok: true });
        expect(received().filter((entry) => entry === "saved")).toHaveLength(1);
        await expect(runner.saveRoutes(INPUT)).resolves.toMatchObject({ ok: true });
    });

    it("lets a save be tried again after one that failed", async () => {
        const { runner } = client({ save: { hang: true } }, { timeoutMs: 200 });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
        await expect(runner.saveRoutes(INPUT)).resolves.toEqual({
            ok: false,
            error: "unavailable",
        });
    });

    it("drops a check when a newer one starts, so checks cannot pile up", async () => {
        const { runner, pids } = client({ check: { hang: true } });
        const older = runner.checkRoutes(INPUT);
        await until(() => pids().length === 1, "the first check starting");
        const [first = 0] = pids();
        const newer = runner.checkRoutes({ subnets: ["198.51.100.0/24"], dns_domains: [] });
        await expect(older).resolves.toEqual({ ok: false, error: "superseded" });
        await until(() => !alive(first), "the first check's client ending");
        // Twenty more in a burst leave one client, not twenty.
        const burst = Array.from({ length: 20 }, () => runner.checkRoutes(INPUT));
        await pause(400);
        expect(pids().filter(alive)).toHaveLength(1);
        runner.stop();
        await Promise.all([newer, ...burst]);
    });
});

describe("how the client is started", () => {
    it("is the bundled client with fixed arguments, a short environment and no shell", async () => {
        const spawned = vi.mocked(spawn);
        const { runner } = client(
            { get: { line: VIEW, exit: 0 } },
            { env: { ...process.env, UBC_VPN_TEST_MARKER: "must not reach the client" } },
        );
        spawned.mockClear();
        await runner.getSettings();
        const [command, args, options] = spawned.mock.calls.at(-1) as [
            string,
            string[],
            SpawnOptions,
        ];
        expect(args.slice(-3)).toEqual(["settings", "get", "--json"]);
        expect(options.shell).toBe(false);
        expect(options.stdio).toEqual(["pipe", "pipe", "ignore"]);
        expect(Object.keys(options.env ?? {})).not.toContain("UBC_VPN_TEST_MARKER");
        expect(realpathSync(String(options.cwd))).toBe(realpathSync(dirname(command)));
    });

    it("has exactly three things it can be asked", () => {
        expect(SETTINGS_ARGS).toEqual({
            get: ["settings", "get", "--json"],
            check: ["settings", "check-routes", "--json"],
            save: ["settings", "set-routes", "--json"],
        });
    });

    it("cannot be redirected through the environment in an installed app", () => {
        const where = { resourcesPath: "/opt/app/resources", platform: "linux" as const };
        const installed = settingsCommand(
            { isPackaged: true },
            { ...where, env: { UBC_VPN_CLI: "/tmp/evil" } },
        );
        expect(installed).not.toContain("evil");
        expect(installed).toMatch(/bin[\\/]ubc-vpn$/);
    });
});

describe("what the interface may send", () => {
    it("is one object holding the two lists, and comes out as a fresh copy", () => {
        const sent = { subnets: ["203.0.113.0/24"], dns_domains: [] };
        const taken = takeRouteInput([sent]);
        expect(taken).toEqual(sent);
        expect(taken).not.toBe(sent);
        expect(taken.subnets).not.toBe(sent.subnets);
        expect(takeRouteInput([{ subnets: [], dns_domains: [] }])).toEqual({
            subnets: [],
            dns_domains: [],
        });
    });

    it("may be more than the client allows, so the client can say so", () => {
        const many = Array.from({ length: 300 }, (_, i) => `203.0.113.${i % 256}/32`);
        expect(
            takeRouteInput([{ subnets: many, dns_domains: ["x".repeat(300)] }]).subnets,
        ).toHaveLength(300);
    });

    it.each([
        ["nothing", []],
        ["two arguments", [{ subnets: [], dns_domains: [] }, "extra"]],
        ["text", ["203.0.113.0/24"]],
        ["a list", [[]]],
        ["null", [null]],
        ["a list missing", [{ subnets: [] }]],
        ["an extra field", [{ subnets: [], dns_domains: [], path: "/etc/passwd" }]],
        ["a list that is text", [{ subnets: "203.0.113.0/24", dns_domains: [] }]],
        ["an entry that is not text", [{ subnets: [42], dns_domains: [] }]],
        ["an entry that is an object", [{ subnets: [], dns_domains: [{ toString: () => "x" }] }]],
        [
            "too many entries",
            [
                {
                    subnets: Array.from({ length: MAX_ROUTE_ENTRIES + 1 }, () => "x"),
                    dns_domains: [],
                },
            ],
        ],
        [
            "an entry that is too long",
            [{ subnets: [], dns_domains: ["x".repeat(MAX_ROUTE_ENTRY_LENGTH + 1)] }],
        ],
        // A gap is not an entry, though `every` would pass over it.
        ["a list that is all gaps", [{ subnets: new Array(3), dns_domains: [] }]],
        [
            "a list with a gap in it",
            [{ subnets: [], dns_domains: Object.assign(new Array(3), { 0: "a", 2: "c" }) }],
        ],
    ] as [string, unknown[]][])("is refused when it is %s", (_name, args) => {
        expect(() => takeRouteInput(args)).toThrow(/^refused$/);
    });

    it("is refused without a word about what was sent", () => {
        // Electron prints a handler's error to the app's standard error, and
        // the routes someone uses are theirs to keep.
        const MARK = "192.0.2.77";
        for (const args of [
            [{ subnets: [`${MARK}/32`], dns_domains: [], path: MARK }],
            [{ subnets: [`${MARK}/${"9".repeat(MAX_ROUTE_ENTRY_LENGTH)}`], dns_domains: [] }],
            [{ subnets: MARK, dns_domains: [] }],
            [MARK],
        ]) {
            let thrown: unknown;
            try {
                takeRouteInput(args);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(Error);
            const error = thrown as Error;
            expect(error.message).toBe("refused");
            expect(
                `${error.stack} ${JSON.stringify(error)} ${inspect(error, { depth: 8 })}`,
            ).not.toContain(MARK);
        }
    });
});

describe("what counts as each kind of line", () => {
    it("is checked field by field", () => {
        expect(isSettingsView(VIEW)).toBe(true);
        expect(isSettingsView({ ...VIEW, allowed_routes: null })).toBe(true);
        expect(isSettingsView({ ...VIEW, allowed_routes: "all" })).toBe(false);
        expect(isSettingsView({ ...VIEW, policy_readable: "yes" })).toBe(false);
        expect(isSettingsView({ ...VIEW, settings: { ...VIEW.settings, username: 7 } })).toBe(
            false,
        );
        expect(
            isSettingsView({ ...VIEW, settings: { ...VIEW.settings, save_password: null } }),
        ).toBe(false);
        expect(isRoutesReply(OK)).toBe(true);
        expect(isRoutesReply(INVALID)).toBe(true);
        expect(isRoutesReply({ type: "ok" })).toBe(false);
        expect(
            isRoutesReply({
                type: "invalid",
                problems: [{ code: "bad_subnet", list: "subnets", index: -1 }],
            }),
        ).toBe(false);
        expect(
            isRoutesReply({
                type: "invalid",
                problems: [{ code: "toString", list: null, index: null }],
            }),
        ).toBe(false);
        // A list is one of the two names, not anything an object answers to.
        for (const list of ["constructor", "__proto__", "toString", "routes"]) {
            const reply = { type: "invalid", problems: [{ code: "bad_subnet", list, index: 0 }] };
            expect(isRoutesReply(reply), list).toBe(false);
        }
        expect(isSettingsFailure({ error: "unreadable" })).toBe(true);
        expect(isSettingsFailure({ error: "constructor" })).toBe(false);
        expect(isSettingsFailure(null)).toBe(false);
    });
});
