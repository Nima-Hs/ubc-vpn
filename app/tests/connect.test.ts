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
import { ConnectRunner, plainText } from "../src/main/channel/connect";
import { MAX_LINE_BYTES } from "../src/main/channel/framing";
import { isCliMessage } from "../src/main/channel/validate";
import { Controller } from "../src/main/controller";
import { createDemoLink } from "../src/main/demo/demo-link";
import { isPromptAnswer, MAX_ANSWER_LENGTH, takePromptAnswer } from "../src/main/ipc";
import { alive, type CliStep, type MockCli, mockCli, pause, until } from "./bridge-harness";

// The real `spawn`, watched: some tests read how the client was started.
vi.mock("node:child_process", async (original) => {
    const actual = await original<typeof import("node:child_process")>();
    return { ...actual, spawn: vi.fn(actual.spawn) };
});

/**
 * Every place under `root` that holds `secret`, as text or as the bytes of
 * text. Printing an object would miss a buffer, which prints as numbers.
 */
function holdsBytes(root: unknown, secret: string): string[] {
    const needle = Buffer.from(secret, "utf8");
    const found: string[] = [];
    const seen = new Set<unknown>();
    const walk = (value: unknown, path: string, depth: number) => {
        if (typeof value === "string") {
            if (value.includes(secret)) {
                found.push(path);
            }
            return;
        }
        if (typeof value !== "object" || value === null || seen.has(value) || depth > 6) {
            return;
        }
        seen.add(value);
        if (ArrayBuffer.isView(value)) {
            const bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
            if (bytes.includes(needle)) {
                found.push(path);
            }
            return;
        }
        for (const key of Reflect.ownKeys(value)) {
            let child: unknown;
            try {
                child = (value as Record<PropertyKey, unknown>)[key];
            } catch {
                continue;
            }
            walk(child, `${path}.${String(key)}`, depth + 1);
        }
    };
    walk(root, "runner", 0);
    return found;
}

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
    options: Parameters<typeof mockCli>[1] & {
        exitGraceMs?: number;
        env?: NodeJS.ProcessEnv;
        minStartGapMs?: number;
    } = {},
): Harness {
    // No gap between logins unless a test is about the gap.
    const { exitGraceMs, env, minStartGapMs = 0, ...mock } = options;
    const cli = mockCli(steps, mock);
    const states: LoginState[] = [];
    const runner = new ConnectRunner({
        command: cli.command,
        args: cli.args,
        onState: (state) => states.push(state),
        minStartGapMs,
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
        const { cli, runner, states } = await atPrompt([
            { prompt: { id: 9, kind, label: "A question" } },
            { hang: true },
        ]);
        // The interface sees the app's own id for the prompt, not the client's.
        expect(states.at(-1)).toMatchObject({ phase: "prompt", prompt: { id: 1, kind } });
        // The answer goes back to the client under the client's id.
        expect(runner.answer(1, "an answer")).toBe(true);
        await until(() => cli.received().length > 0, "the answer arriving");
        expect(cli.received()).toEqual(["answer:9:as expected"]);
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
        "busy",
        "not_owner",
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
        expect(states).toEqual([
            { phase: "working" },
            { phase: "failed", code: "internal", message: "" },
        ]);
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

describe("text from the gateway and the client", () => {
    const BEL = String.fromCharCode(7);
    const ESC = String.fromCharCode(27);
    // "Right-to-left override": everything after it is drawn backwards.
    const RLO = String.fromCharCode(0x202e);
    const LRI = String.fromCharCode(0x2066);
    const LINE_SEPARATOR = String.fromCharCode(0x2028);

    it("is made one line of plain characters before it is shown", () => {
        expect(plainText("Password", 200)).toBe("Password");
        expect(plainText("  Enter\tyour\r\n\r\npassword  ", 200)).toBe("Enter your password");
        expect(plainText(`Pass${BEL}word${ESC}[31m`, 200)).toBe("Pass word [31m");
        expect(plainText(`Enter your ${RLO}drowssap`, 200)).toBe("Enter your drowssap");
        expect(plainText(`one${LINE_SEPARATOR}two${LRI}three`, 200)).toBe("one two three");
        // Other languages, accents and emoji are left alone.
        expect(plainText("Mot de passe é 密码 🔑", 200)).toBe("Mot de passe é 密码 🔑");
    });

    it("keeps the joiners that Persian and joined emoji are written with", () => {
        const ZWNJ = String.fromCharCode(0x200c);
        const ZWJ = String.fromCharCode(0x200d);
        // "می‌خواهم": the non-joiner keeps two parts of one word apart.
        const persian = `می${ZWNJ}خواهم`;
        // A family: three people joined into one picture.
        const family = `👨${ZWJ}👩${ZWJ}👧`;
        expect(plainText(persian, 200)).toBe(persian);
        expect(plainText(family, 200)).toBe(family);
    });

    it("is cut between whole characters, never through one", () => {
        const ZWJ = String.fromCharCode(0x200d);
        const family = `👨${ZWJ}👩${ZWJ}👧`;
        // The limit falls inside the emoji: none of it is kept, not a piece.
        expect(plainText(`ab${family}`, 4)).toBe("ab");
        expect(plainText(`ab${family}`, 2 + family.length)).toBe(`ab${family}`);
        // The same for a single character stored as two units, and an accent on a letter.
        expect(plainText("ab🔑", 3)).toBe("ab");
        expect(plainText(`abe${String.fromCharCode(0x301)}`, 3)).toBe("ab");
        for (const limit of [1, 2, 3, 5, 7, 9]) {
            const cut = plainText(`a🔑${family}é`, limit);
            expect(cut.length).toBeLessThanOrEqual(limit);
            // Half of a two-unit character cannot be encoded: this throws on one.
            expect(() => encodeURIComponent(cut)).not.toThrow();
        }
    });

    it("is cut to length after it is cleaned, not before", () => {
        expect(plainText(`${"\n".repeat(500)}abcdef`, 3)).toBe("abc");
    });

    it("is cleaned in a question's label and message", async () => {
        const { states } = await atPrompt([
            {
                prompt: {
                    id: 1,
                    kind: "text",
                    label: `Code\n\n\n${RLO}:`,
                    message: `First line\nSecond${BEL} line`,
                },
            },
        ]);
        expect(states.at(-1)).toEqual({
            phase: "prompt",
            prompt: { id: 1, kind: "text", label: "Code :", message: "First line Second line" },
        });
    });

    it("is cleaned and shortened in a failure's message", async () => {
        const { runner, states, phase } = login([
            { error: { code: "internal", message: `bad\nthing${RLO} ${"m".repeat(5000)}` } },
        ]);
        runner.start();
        await until(() => phase() === "failed", "the failure");
        const state = states.at(-1);
        const message = state?.phase === "failed" ? state.message : "";
        expect(message.startsWith("bad thing m")).toBe(true);
        expect(message).toHaveLength(1000);
    });
});

describe("a client that has been let go", () => {
    it("is not listened to any more, even for lines that arrived with its last", async () => {
        // A line that ends the login and a question, written together.
        const question = JSON.stringify({ type: "prompt", ...PASSWORD_PROMPT });
        for (const ending of ["this is not json", JSON.stringify({ type: "done" })]) {
            const { runner, states, phase } = login([
                { raw: `${ending}\n${question}\n` },
                { hang: true },
            ]);
            runner.start();
            await until(() => phase() !== "working", "the login ending");
            await pause(150);
            expect(
                states.some((state) => state.phase === "prompt"),
                ending,
            ).toBe(false);
            expect(runner.answer(1, PASSWORD)).toBe(false);
        }
    });

    it("cannot end the login that came after it", async () => {
        // Login A will not stop when told and is killed a moment later. By
        // then login B is at its question, and must still be.
        const { cli, runner, states, phase } = login(
            [{ prompt: PASSWORD_PROMPT }, { hang: true }],
            {
                ignoresCancel: true,
                exitGraceMs: 200,
                laterLogins: [[{ prompt: CODE_PROMPT }, { hang: true }]],
            },
        );
        runner.start();
        await until(() => phase() === "prompt", "login A's prompt");
        runner.cancel();
        runner.start();
        await until(() => phase() === "prompt", "login B's prompt");

        const [first = 0] = cli.pids();
        await until(() => !alive(first), "login A's client being killed");
        await pause(150);
        expect(states.at(-1)).toMatchObject({ phase: "prompt", prompt: { kind: "code" } });
        // And B can still be answered.
        const state = states.at(-1);
        expect(runner.answer(state?.phase === "prompt" ? state.prompt.id : -1, CODE)).toBe(true);
    });
});

describe("how often a login can start", () => {
    it("starts the first at once, and shows the user it has begun", async () => {
        const spawned = vi.mocked(spawn);
        spawned.mockClear();
        const { runner, states } = login([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            minStartGapMs: 60_000,
        });
        expect(runner.start()).toBe(true);
        expect(spawned).toHaveBeenCalledTimes(1);
        expect(states).toEqual([{ phase: "working" }]);
    });

    it("holds the next one back until the gap has passed", async () => {
        const spawned = vi.mocked(spawn);
        const { runner, phase } = login([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            minStartGapMs: 600,
        });
        spawned.mockClear();
        runner.start();
        const firstStart = Date.now();
        await until(() => phase() === "prompt", "the first prompt");
        runner.cancel();

        // The user sees it begin straight away; the client is not started yet.
        expect(runner.start()).toBe(true);
        expect(phase()).toBe("working");
        expect(spawned).toHaveBeenCalledTimes(1);
        // Pressing again while it waits changes nothing.
        expect(runner.start()).toBe(false);

        await until(() => spawned.mock.calls.length === 2, "the second start");
        expect(Date.now() - firstStart).toBeGreaterThanOrEqual(590);
        await until(() => phase() === "prompt", "the second prompt");
    });

    it("cannot be made to start clients in a stream", async () => {
        const spawned = vi.mocked(spawn);
        const { runner } = login([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            minStartGapMs: 60_000,
        });
        spawned.mockClear();
        // Forty presses of Connect and Cancel, as fast as they can be made.
        for (let round = 0; round < 40; round++) {
            runner.start();
            runner.cancel();
        }
        await pause(200);
        expect(spawned).toHaveBeenCalledTimes(1);
    });

    it("forgets a held-back start that is cancelled", async () => {
        const spawned = vi.mocked(spawn);
        const { runner, phase } = login([{ prompt: PASSWORD_PROMPT }, { hang: true }], {
            minStartGapMs: 300,
        });
        runner.start();
        runner.cancel();
        spawned.mockClear();
        runner.start();
        runner.cancel();
        expect(phase()).toBe("idle");
        await pause(450);
        expect(spawned).not.toHaveBeenCalled();
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

    it("are refused without a word about what was sent", () => {
        const taken: unknown[][] = [];
        const controller = { answerPrompt: (...args: unknown[]) => void taken.push(args) };
        // A proper answer is handed on, whole.
        takePromptAnswer(controller, [1, PASSWORD]);
        expect(taken).toEqual([[1, PASSWORD]]);

        // Electron prints a handler's error to the app's standard error. A
        // refusal must therefore carry nothing of what it refused.
        const tooLong = PASSWORD.repeat(100);
        for (const args of [
            [1, tooLong],
            [PASSWORD, PASSWORD],
            [1, { secret: PASSWORD }],
            [1, PASSWORD, PASSWORD],
        ]) {
            let thrown: unknown;
            try {
                takePromptAnswer(controller, args);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(Error);
            const error = thrown as Error;
            expect(error.message).toBe("refused");
            expect(
                `${error.stack} ${JSON.stringify(error)} ${inspect(error, { depth: 8 })}`,
            ).not.toContain(PASSWORD);
        }
        expect(taken).toHaveLength(1);
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

describe("an answer meant for one login", () => {
    const promptIn = (states: LoginState[]) => {
        const state = states.at(-1);
        return state?.phase === "prompt" ? state.prompt : undefined;
    };

    it("cannot reach the prompt of another, though the client numbers both the same", async () => {
        // Login A asks for a password as its prompt 1 and is cancelled.
        // Login B asks for a username, also as its prompt 1.
        const { cli, runner, states, phase } = login(
            [{ prompt: PASSWORD_PROMPT }, { hang: true }],
            {
                laterLogins: [
                    [{ prompt: { id: 1, kind: "username", label: "Username" } }, { hang: true }],
                ],
            },
        );
        runner.start();
        await until(() => phase() === "prompt", "login A's prompt");
        const passwordPrompt = promptIn(states);
        runner.cancel();

        runner.start();
        await until(() => phase() === "prompt", "login B's prompt");
        const usernamePrompt = promptIn(states);
        expect(usernamePrompt?.kind).toBe("username");
        expect(usernamePrompt?.id).not.toBe(passwordPrompt?.id);

        // The interface, a step behind, sends the password for A's prompt.
        expect(runner.answer(passwordPrompt?.id ?? -1, PASSWORD)).toBe(false);
        expect(phase()).toBe("prompt");
        await pause(150);
        // Nothing was written to B: the password was not sent as a username.
        expect(cli.received().filter((entry) => entry.startsWith("answer"))).toEqual([]);

        // B's own prompt still takes its own answer.
        expect(runner.answer(usernamePrompt?.id ?? -1, "someone")).toBe(true);
        await until(
            () => cli.received().some((entry) => entry.startsWith("answer")),
            "B's answer arriving",
        );
        expect(cli.received().filter((entry) => entry.startsWith("answer"))).toEqual([
            "answer:1:as expected",
        ]);
    });

    it("is matched by an id the app makes, never used twice", async () => {
        const ids: number[] = [];
        const { runner, states, phase } = login([
            { prompt: { id: 1, kind: "password", label: "Password" } },
            { prompt: { id: 1, kind: "code", label: "Code" } },
            { hang: true },
        ]);
        for (let round = 0; round < 3; round++) {
            runner.start();
            await until(() => phase() === "prompt", "a prompt");
            ids.push(promptIn(states)?.id ?? -1);
            runner.answer(ids.at(-1) ?? -1, "x");
            await until(
                () => phase() === "prompt" && promptIn(states)?.kind === "code",
                "the next",
            );
            ids.push(promptIn(states)?.id ?? -1);
            runner.cancel();
        }
        expect(new Set(ids).size).toBe(6);
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
        // Watch what is handed to the client's standard input.
        const child = vi.mocked(spawn).mock.results.at(-1)?.value as {
            stdin: { write(...args: unknown[]): boolean };
        };
        const written: Buffer[] = [];
        const write = child.stdin.write.bind(child.stdin);
        child.stdin.write = (...args: unknown[]) => {
            if (Buffer.isBuffer(args[0])) {
                written.push(args[0]);
            }
            return write(...args);
        };

        runner.answer(1, PASSWORD);
        await until(() => phase() === "failed", "the failure");

        expect(cli.received()).toContain("answer:1:as expected");
        // The line that carried it was written once, and has been wiped.
        expect(written).toHaveLength(1);
        await until(() => written[0]?.every((byte) => byte === 0) === true, "the line being wiped");
        // Nothing reachable from the runner holds it, as text or as bytes.
        expect(holdsBytes(runner, PASSWORD)).toEqual([]);
        // Not in what the interface is shown, not held by the runner, not written anywhere.
        expect(JSON.stringify(states)).not.toContain(PASSWORD);
        expect(inspect(runner, { depth: 12, showHidden: true })).not.toContain(PASSWORD);
        expect(writes.join("\n")).not.toContain(PASSWORD);
        expect(writes).toEqual([]);
    });

    it("is wiped even when the client was already gone and the write failed", async () => {
        const { runner } = await atPrompt([{ prompt: PASSWORD_PROMPT }, { hang: true }]);
        const child = vi.mocked(spawn).mock.results.at(-1)?.value as {
            stdin: { write(...args: unknown[]): boolean; destroy(): void };
        };
        const written: Buffer[] = [];
        const write = child.stdin.write.bind(child.stdin);
        child.stdin.write = (...args: unknown[]) => {
            if (Buffer.isBuffer(args[0])) {
                written.push(args[0]);
            }
            return write(...args);
        };
        // The client's input is gone, so the write can only fail.
        child.stdin.destroy();
        expect(runner.answer(1, PASSWORD)).toBe(true);

        expect(written).toHaveLength(1);
        expect(written[0]?.includes(Buffer.from(PASSWORD))).toBe(true);
        // Failed or not, the bytes do not stay.
        await until(() => written[0]?.every((byte) => byte === 0) === true, "the line being wiped");
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
        // Stopping tells nobody: by then the window and the tray are going,
        // and a listener that touched them would stop the app from quitting.
        let told = 0;
        controller.subscribe(() => told++);
        controller.dispose();
        expect(told).toBe(0);
        controller.dispose();
        await until(() => !alive(pid), "the client ending", 3000);
    });
});
