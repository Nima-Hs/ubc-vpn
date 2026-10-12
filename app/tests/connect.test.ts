// Logging in through `ubc-vpn connect --json`, run against a mock client that
// follows the contract in `crates/core/src/login.rs`. Every value here is
// made up: no real password, code, user or host appears.

import { type SpawnOptions, spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import { inspect } from "node:util";
import type { LoginState, Snapshot } from "@shared/api";
import type { LoginErrorCode } from "@shared/protocol/LoginErrorCode";
import { afterEach, describe, expect, it, vi } from "vitest";
import { connectCommand } from "../src/main/channel/cli";
import { ConnectRunner } from "../src/main/channel/connect";
import { MAX_LINE_BYTES } from "../src/main/channel/framing";
import { isCliMessage } from "../src/main/channel/validate";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { isPromptAnswer, MAX_ANSWER_LENGTH } from "../src/main/ipc";
import { alive, type CliStep, type MockCli, mockCli, pause, until } from "./bridge-harness";

// The real `spawn`, watched: some tests read how the client was started.
vi.mock("node:child_process", async (original) => {
    const actual = await original<typeof import("node:child_process")>();
    return { ...actual, spawn: vi.fn(actual.spawn) };
});

/** Obviously fake. Searched for wherever a password must not turn up. */
const PASSWORD = "not-a-real-password-0123456789";
const CODE = "000000";

const PASSWORD_PROMPT = { id: 1, kind: "password", label: "Password" } as const;
const CODE_PROMPT = { id: 2, kind: "code", label: "Enter the code from your device" } as const;

const cleanups: (() => unknown)[] = [];

afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
        await cleanup();
    }
});

interface Harness {
    cli: MockCli;
    runner: ConnectRunner;
    states: LoginState[];
    phase(): LoginState["phase"] | undefined;
}

function login(
    steps: CliStep[],
    options: Parameters<typeof mockCli>[1] & { exitGraceMs?: number; env?: NodeJS.ProcessEnv } = {},
): Harness {
    const { exitGraceMs, env, ...mock } = options;
    const cli = mockCli(steps, mock);
    const states: LoginState[] = [];
    const runner = new ConnectRunner({
        command: cli.command,
        args: cli.args,
        onState: (state) => states.push(state),
        ...(exitGraceMs !== undefined && { exitGraceMs }),
        ...(env !== undefined && { env }),
    });
    cleanups.push(() => runner.stop());
    return { cli, runner, states, phase: () => states.at(-1)?.phase };
}

/** Starts a login and waits for the client's first question. */
async function atPrompt(steps: CliStep[], options?: Parameters<typeof login>[1]): Promise<Harness> {
    const harness = login(steps, options);
    harness.runner.start();
    await until(() => harness.phase() === "prompt", "the first prompt");
    return harness;
}

describe("a login", () => {
    it("relays each question, passes each answer on, and ends when the client is done", async () => {
        const { cli, runner, states, phase } = await atPrompt([
            { prompt: PASSWORD_PROMPT, expect: PASSWORD },
            { prompt: CODE_PROMPT, expect: CODE },
            { done: true },
        ]);
        expect(states).toEqual([
            { phase: "working" },
            { phase: "prompt", prompt: PASSWORD_PROMPT },
        ]);

        expect(runner.answer(1, PASSWORD)).toBe(true);
        expect(phase()).toBe("working");
        await until(() => phase() === "prompt", "the second prompt");
        expect(states.at(-1)).toEqual({ phase: "prompt", prompt: CODE_PROMPT });

        expect(runner.answer(2, CODE)).toBe(true);
        await until(() => phase() === "idle", "the end");
        // What the user typed reached the client, unchanged, once each.
        expect(cli.received().filter((entry) => entry.startsWith("answer"))).toEqual([
            "answer:1:as expected",
            "answer:2:as expected",
        ]);
    });

    it("shows what the gateway says alongside a question", async () => {
        const message = "Login failed. Enter your password again.";
        const { states } = await atPrompt([{ prompt: { ...PASSWORD_PROMPT, message } }]);
        expect(states.at(-1)).toEqual({ phase: "prompt", prompt: { ...PASSWORD_PROMPT, message } });
    });

    it.each(["username", "password", "code", "text"])("can ask for a %s", async (kind) => {
        const { states } = await atPrompt([{ prompt: { id: 9, kind, label: "A question" } }]);
        expect(states.at(-1)).toMatchObject({ phase: "prompt", prompt: { id: 9, kind } });
    });

    it("keeps the gateway's wording to a sensible length", async () => {
        const { states } = await atPrompt([
            { prompt: { id: 1, kind: "text", label: "L".repeat(5000), message: "M".repeat(5000) } },
        ]);
        const state = states.at(-1);
        expect(state?.phase === "prompt" && state.prompt.label.length).toBe(200);
        expect(state?.phase === "prompt" && state.prompt.message?.length).toBe(1000);
    });
});

describe("how a login ends badly", () => {
    const codes: LoginErrorCode[] = [
        "wrong_password",
        "pin_mismatch",
        "gateway_unreachable",
        "route_refused",
        "service_unavailable",
        "internal",
    ];

    it.each(codes)("reports %s with the client's account of it", async (code) => {
        const { runner, states, phase } = await atPrompt([
            { prompt: PASSWORD_PROMPT },
            { error: { code, message: `the client's words about ${code}` } },
        ]);
        runner.answer(1, PASSWORD);
        await until(() => phase() === "failed", "the failure");
        expect(states.at(-1)).toEqual({
            phase: "failed",
            code,
            message: `the client's words about ${code}`,
        });
        // Dismissing it goes back to the start, and a new login can begin.
        runner.cancel();
        expect(phase()).toBe("idle");
        expect(runner.start()).toBe(true);
    });

    it("treats the client's own 'cancelled' as nothing having happened", async () => {
        const { runner, phase, states } = await atPrompt([
            { prompt: PASSWORD_PROMPT },
            { error: { code: "cancelled", message: "cancelled" } },
        ]);
        runner.answer(1, PASSWORD);
        await until(() => phase() === "idle", "idle");
        expect(states.some((state) => state.phase === "failed")).toBe(false);
    });

    it("reports a client that dies mid-way as a failure, not as success", async () => {
        const { runner, states, phase } = await atPrompt([
            { prompt: PASSWORD_PROMPT },
            { exit: 1 },
        ]);
        runner.answer(1, PASSWORD);
        await until(() => phase() === "failed", "the failure");
        expect(states.at(-1)).toEqual({ phase: "failed", code: "internal", message: "" });
    });

    it("reports a client that cannot be started", async () => {
        const states: LoginState[] = [];
        const runner = new ConnectRunner({
            ...connectCommand(
                { isPackaged: true },
                { resourcesPath: "/nowhere/that/exists", platform: process.platform, env: {} },
            ),
            onState: (state) => states.push(state),
        });
        cleanups.push(() => runner.stop());
        expect(() => runner.start()).not.toThrow();
        await until(() => states.at(-1)?.phase === "failed", "the failure");
        expect(states.at(-1)).toEqual({ phase: "failed", code: "internal", message: "" });
    });

    it("reports it when starting the client fails outright, and can try again", () => {
        const spawned = vi.mocked(spawn);
        // What Windows does for a file that is there but is not a program.
        spawned.mockImplementationOnce(() => {
            throw new Error("spawn UNKNOWN");
        });
        const { runner, states } = login([{ done: true }]);
        expect(() => runner.start()).not.toThrow();
        expect(states).toEqual([{ phase: "failed", code: "internal", message: "" }]);
        // Nothing is left half-started.
        expect(runner.start()).toBe(true);
    });

    it.each([
        // No newline: with no limit, the app would wait on this for ever.
        ["a line that never ends", "x".repeat(MAX_LINE_BYTES + 10)],
        ["not JSON", "this is not json\n"],
        ["an unknown line type", '{"type":"surprise"}\n'],
        [
            "a prompt of an unknown kind",
            '{"type":"prompt","id":1,"kind":"retina","label":"Look here"}\n',
        ],
        ["a prompt with no id", '{"type":"prompt","kind":"password","label":"Password"}\n'],
        [
            "a prompt whose id is not a number",
            '{"type":"prompt","id":"1","kind":"password","label":"Password"}\n',
        ],
        ["a prompt with no label", '{"type":"prompt","id":1,"kind":"password"}\n'],
        [
            "a prompt whose message is not text",
            '{"type":"prompt","id":1,"kind":"text","label":"L","message":{"html":"x"}}\n',
        ],
        ["an error with an unknown code", '{"type":"error","code":"gremlins","message":"m"}\n'],
        ["an error with no message", '{"type":"error","code":"internal"}\n'],
        [
            "a line longer than 64 KiB",
            `{"type":"prompt","id":1,"kind":"text","label":"${"x".repeat(MAX_LINE_BYTES)}"}\n`,
        ],
        [
            "a second question before the first is answered",
            `${JSON.stringify({ type: "prompt", ...PASSWORD_PROMPT })}\n${JSON.stringify({ type: "prompt", ...CODE_PROMPT })}\n`,
        ],
    ])("gives up on a client that sends %s", async (_name, raw) => {
        const { cli, runner, states, phase } = login([{ raw }, { hang: true }]);
        runner.start();
        await until(() => phase() === "failed", "the failure");
        expect(states.at(-1)).toEqual({ phase: "failed", code: "internal", message: "" });
        // The client is not left running.
        const [pid = 0] = cli.pids();
        await until(() => !alive(pid), "the client ending");
    });

    it("accepts exactly the lines the contract names", () => {
        expect(isCliMessage({ type: "done" })).toBe(true);
        expect(isCliMessage({ type: "prompt", id: 0, kind: "code", label: "" })).toBe(true);
        expect(isCliMessage({ type: "prompt", id: -1, kind: "code", label: "" })).toBe(false);
        expect(isCliMessage({ type: "prompt", id: 1.5, kind: "code", label: "" })).toBe(false);
        expect(isCliMessage({ type: "prompt", id: 1, kind: "constructor", label: "" })).toBe(false);
        expect(isCliMessage({ type: "error", code: "toString", message: "" })).toBe(false);
        expect(isCliMessage(null)).toBe(false);
        expect(isCliMessage([])).toBe(false);
    });
});

describe("answers", () => {
    it("go only to the prompt that is waiting, and only once", async () => {
        const { cli, runner, phase } = await atPrompt([
            { prompt: PASSWORD_PROMPT, expect: PASSWORD },
            { hang: true },
        ]);
        // Not this prompt.
        expect(runner.answer(2, PASSWORD)).toBe(false);
        expect(phase()).toBe("prompt");
        // This one.
        expect(runner.answer(1, PASSWORD)).toBe(true);
        // Not twice.
        expect(runner.answer(1, PASSWORD)).toBe(false);
        await until(() => cli.received().length > 0, "the answer arriving");
        await pause(100);
        expect(cli.received()).toEqual(["answer:1:as expected"]);
    });

    it("are refused when no login is under way", () => {
        const { cli, runner } = login([{ done: true }]);
        expect(runner.answer(1, PASSWORD)).toBe(false);
        expect(cli.pids()).toEqual([]);
    });

    it("are refused, and nothing is sent, when too long for a line", async () => {
        const { cli, runner, phase } = await atPrompt([
            { prompt: PASSWORD_PROMPT },
            { hang: true },
        ]);
        expect(runner.answer(1, "x".repeat(MAX_LINE_BYTES))).toBe(false);
        // The prompt still waits, and a proper answer is still accepted.
        expect(phase()).toBe("prompt");
        expect(runner.answer(1, PASSWORD)).toBe(true);
        await until(() => cli.received().length > 0, "the answer arriving");
        expect(cli.received()).toEqual(["answer:1:as expected"]);
    });

    it("are checked before they leave the interface's hands", () => {
        expect(isPromptAnswer([1, PASSWORD])).toBe(true);
        expect(isPromptAnswer([0, ""])).toBe(true);
        for (const args of [
            [],
            [1],
            ["1", PASSWORD],
            [1.5, PASSWORD],
            [-1, PASSWORD],
            [2 ** 32, PASSWORD],
            [1, 42],
            [1, null],
            [1, { toString: () => PASSWORD }],
            [1, [PASSWORD]],
            [1, PASSWORD, "extra"],
            [1, "x".repeat(MAX_ANSWER_LENGTH + 1)],
        ]) {
            expect(isPromptAnswer(args), JSON.stringify(args).slice(0, 40)).toBe(false);
        }
    });
});

describe("cancelling", () => {
    it("tells the client, which stops, and goes back to the start", async () => {
        const { cli, runner, phase } = await atPrompt([
            { prompt: PASSWORD_PROMPT },
            { hang: true },
        ]);
        runner.cancel();
        expect(phase()).toBe("idle");
        await until(() => cli.received().includes("cancel"), "the client hearing of it");
        const [pid = 0] = cli.pids();
        await until(() => !alive(pid), "the client ending");
        // An answer that arrives late goes nowhere.
        expect(runner.answer(1, PASSWORD)).toBe(false);
        expect(cli.received()).not.toContain("answer:1:as expected");
    });

    it("closes the client's input as well, as the bridge's is closed", async () => {
        const { cli, runner } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            ignoresCancel: true,
            exitGraceMs: 60_000,
        });
        runner.cancel();
        await until(() => cli.received().includes("input closed"), "its input closing");
    });

    it("kills a client that will not stop", async () => {
        const { cli, runner } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            ignoresCancel: true,
            exitGraceMs: 150,
        });
        const [pid = 0] = cli.pids();
        runner.cancel();
        await until(() => cli.received().includes("input closed"), "its input closing");
        expect(alive(pid)).toBe(true);
        await until(() => !alive(pid), "the client being killed");
    });

    it("ends the client at once when the app stops", async () => {
        const { cli, runner } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            ignoresCancel: true,
            exitGraceMs: 60_000,
        });
        const [pid = 0] = cli.pids();
        runner.stop();
        await until(() => !alive(pid), "the client ending", 3000);
    });

    it("does nothing when there is nothing to cancel", () => {
        const { runner, states } = login([{ done: true }]);
        expect(() => runner.cancel()).not.toThrow();
        expect(states).toEqual([{ phase: "idle" }]);
    });
});

describe("one login at a time", () => {
    it("does not start a second while the first is under way", async () => {
        const spawned = vi.mocked(spawn);
        const { cli, runner } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }]);
        spawned.mockClear();
        expect(runner.start()).toBe(false);
        expect(runner.start()).toBe(false);
        expect(spawned).not.toHaveBeenCalled();
        expect(cli.pids()).toHaveLength(1);
    });
});

describe("how the client is started", () => {
    it("is asked to connect, and is given no routes or anything else", async () => {
        const spawned = vi.mocked(spawn);
        spawned.mockClear();
        const { cli } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }]);
        const [command, args, options] = spawned.mock.calls.at(-1) as [
            string,
            string[],
            SpawnOptions,
        ];
        expect(command).toBe(cli.command);
        expect(args).toEqual(cli.args);
        expect(options.shell).toBe(false);
        expect(options.stdio).toEqual(["pipe", "pipe", "ignore"]);
        // In the app the arguments are these two and nothing more.
        expect(
            connectCommand(
                { isPackaged: true },
                {
                    resourcesPath: "/opt/app/resources",
                    platform: "linux",
                    env: { UBC_VPN_CLI: "/tmp/evil" },
                },
            ),
        ).toMatchObject({ args: ["connect", "--json"] });
    });

    it("is the same bundled client the bridge uses, and cannot be redirected when installed", () => {
        const where = { resourcesPath: "/opt/app/resources", platform: "linux" as const };
        const installed = connectCommand(
            { isPackaged: true },
            { ...where, env: { UBC_VPN_CLI: "/tmp/evil" } },
        );
        expect(installed.command).not.toContain("evil");
        expect(installed.command).toMatch(/bin[\\/]ubc-vpn$/);
    });

    it("gets the short environment and its own folder, like the bridge", async () => {
        const { cli } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            reportStart: true,
            env: {
                ...process.env,
                UBC_VPN_TEST_MARKER: "must not reach the client",
                NODE_OPTIONS: "--no-warnings",
            },
        });
        const entry = (prefix: string) =>
            cli
                .received()
                .find((line) => line.startsWith(prefix))
                ?.slice(4) ?? "";
        const names = entry("env:")
            .split(",")
            .map((name) => name.toUpperCase());
        expect(names).not.toContain("UBC_VPN_TEST_MARKER");
        expect(names).not.toContain("NODE_OPTIONS");
        expect(realpathSync(entry("cwd:"))).toBe(realpathSync(dirname(cli.command)));
    });
});

describe("a password", () => {
    it("is written to the client once and is found nowhere else afterwards", async () => {
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

        const { cli, runner, states, phase } = await atPrompt(
            [
                { prompt: PASSWORD_PROMPT, expect: PASSWORD },
                // The client breaks the rules straight after, so every failure path runs too.
                { raw: "this is not json\n" },
                { hang: true },
            ],
            { stderr: PASSWORD },
        );
        runner.answer(1, PASSWORD);
        await until(() => phase() === "failed", "the failure");

        expect(cli.received()).toContain("answer:1:as expected");
        // Not in what the interface is shown, not held by the runner, not written anywhere.
        expect(JSON.stringify(states)).not.toContain(PASSWORD);
        expect(inspect(runner, { depth: 12, showHidden: true })).not.toContain(PASSWORD);
        expect(writes.join("\n")).not.toContain(PASSWORD);
        expect(writes).toEqual([]);
    });

    it("never becomes part of what the interface is sent", async () => {
        const cli = mockCli([{ prompt: PASSWORD_PROMPT, expect: PASSWORD }, { hang: true }]);
        const demo = createDemoLink(10);
        const controller = new Controller(
            demo,
            (onState) => new ConnectRunner({ command: cli.command, args: cli.args, onState }),
        );
        cleanups.push(() => controller.dispose());
        const sent: Snapshot[] = [];
        controller.subscribe((snapshot) => sent.push(snapshot));

        await controller.connect();
        await until(() => controller.getSnapshot().login.phase === "prompt", "the prompt");
        expect(controller.getSnapshot().login).toEqual({
            phase: "prompt",
            prompt: PASSWORD_PROMPT,
        });

        controller.answerPrompt(1, PASSWORD);
        await until(() => cli.received().includes("answer:1:as expected"), "the answer arriving");
        expect(controller.getSnapshot().login).toEqual({ phase: "working" });
        expect(JSON.stringify(sent)).not.toContain(PASSWORD);
        expect(JSON.stringify(controller.getSnapshot())).not.toContain(PASSWORD);
        expect(inspect(controller, { depth: 12, showHidden: true })).not.toContain(PASSWORD);

        // Putting the window away gives the login up.
        controller.cancelLogin();
        expect(controller.getSnapshot().login).toEqual({ phase: "idle" });
        await until(() => cli.received().includes("cancel"), "the client hearing of it");
    });
});

describe("the controller", () => {
    it("says this build cannot log in when it has been given no way to", async () => {
        const controller = new Controller(createDemoLink(10));
        cleanups.push(() => controller.dispose());
        // The demo link stands in for the real one's "no login yet" answer.
        expect(controller.getSnapshot().login).toEqual({ phase: "idle" });
        expect(() => controller.answerPrompt(1, PASSWORD)).not.toThrow();
        expect(() => controller.cancelLogin()).not.toThrow();
    });

    it("starts one login per press, and stops it when the app quits", async () => {
        const cli = mockCli([{ prompt: PASSWORD_PROMPT }, { hang: true }], { ignoresCancel: true });
        const controller = new Controller(
            createDemoLink(10),
            (onState) =>
                new ConnectRunner({
                    command: cli.command,
                    args: cli.args,
                    onState,
                    exitGraceMs: 60_000,
                }),
        );
        await controller.connect();
        await controller.connect();
        await until(() => controller.getSnapshot().login.phase === "prompt", "the prompt");
        expect(cli.pids()).toHaveLength(1);
        const [pid = 0] = cli.pids();
        controller.dispose();
        await until(() => !alive(pid), "the client ending", 3000);
    });
});
