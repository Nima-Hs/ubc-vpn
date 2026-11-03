// "Restart to update" with every step it takes passed in: no installer is ever
// started, no administrator prompt shown, and nothing outside a fresh temporary
// folder is touched. The launcher script is run for real only on Windows, without
// elevation, with stand-ins in that temporary folder.

import { type spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ActionResult, LinkState } from "@shared/api";
import type { InstallNotice } from "@shared/updates";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
    createInstall,
    disconnectAndWait,
    type InstallSteps,
    installUpdate,
    type Launched,
    launchedFrom,
    launcherFor,
    launcherScript,
    launchWindows,
    restartToUpdate,
    SETUP_FALLBACK_MS,
    SETUP_LIMIT_MS,
    stageInstaller,
    tunnelDown,
    tunnelUp,
    whenDown,
    windowsLaunch,
} from "../src/main/update/install";
import { readNote } from "../src/main/update/resume";
import type { ReadyInstaller } from "../src/main/update/updater";
import { sha256 } from "./update-harness";

const PROFILE = "0123456789abcdef0123456789abcdef";
const NOW = 1_800_000_000_000;
const installer = Buffer.from("a stand-in for the setup program, never run");
let folder: string;
let ready: ReadyInstaller;

beforeEach(async () => {
    folder = join(await mkdtemp(join(tmpdir(), "upd-install-")), "updates");
    await mkdir(folder);
    const name = "ubc-vpn-setup-0.2.0-x64.exe";
    const path = join(folder, name);
    await writeFile(path, installer);
    ready = {
        version: "0.2.0",
        path,
        entry: { platform: "windows-x64", name, size: installer.length, sha256: sha256(installer) },
    };
});
afterEach(async () => {
    await rm(dirname(folder), { recursive: true, force: true });
});

const runFolders = () => readdirSync(folder).filter((name) => name.startsWith("run-"));

/** The steps, recording what was done; `launched` is what starting the setup program comes to. */
function steps(
    options: { connected?: boolean; down?: "down" | "refused" | "late"; launched?: Launched } = {},
) {
    const done: string[] = [];
    const seen: {
        launchedPath?: string;
        launchedBytes?: Buffer;
        note?: unknown;
        later?: () => void;
        reconnected?: string | null;
    } = {};
    const given: InstallSteps = {
        folder,
        connected: () => options.connected ?? false,
        connectedProfile: () => PROFILE,
        disconnect: async () => {
            done.push("disconnect");
            return options.down ?? "down";
        },
        whenDownLater: (then) => {
            done.push("watch");
            seen.later = then;
        },
        launch: async (path) => {
            done.push("launch");
            seen.launchedPath = path;
            seen.launchedBytes = readFileSync(path);
            seen.note = await readNote(folder);
            return options.launched ?? "started";
        },
        reconnect: (profile) => {
            done.push("reconnect");
            seen.reconnected = profile;
        },
        quit: () => done.push("quit"),
        now: () => NOW,
    };
    return { given, done, seen };
}

describe("restart to update", () => {
    it("disconnects, runs a checked copy in a fresh folder, and quits", async () => {
        const { given, done, seen } = steps({ connected: true });
        await expect(installUpdate(ready, given)).resolves.toBeNull();
        expect(done).toEqual(["disconnect", "launch", "quit"]);
        // A copy, not the downloaded file: in a folder made for this run.
        expect(seen.launchedPath).not.toBe(ready.path);
        expect(dirname(seen.launchedPath ?? "")).toMatch(/[\\/]run-[^\\/]+$/);
        expect(dirname(dirname(seen.launchedPath ?? ""))).toBe(folder);
        expect(seen.launchedBytes).toEqual(installer);
    });

    it("makes a new folder for every run", async () => {
        const first = await stageInstaller(ready.path, ready.entry, folder);
        const second = await stageInstaller(ready.path, ready.entry, folder);
        expect(dirname(first)).not.toBe(dirname(second));
        expect(readFileSync(second)).toEqual(installer);
    });

    it("leaves a note of the version, the time and the connection, before it runs", async () => {
        const { given, seen } = steps({ connected: true });
        await installUpdate(ready, given);
        expect(seen.note).toEqual({ target: "0.2.0", at: NOW, connected: true, profile: PROFILE });
    });

    it("leaves a note even with nothing to reconnect, to learn whether the update took", async () => {
        const { given, done, seen } = steps({ connected: false });
        await expect(installUpdate(ready, given)).resolves.toBeNull();
        expect(done).toEqual(["launch", "quit"]);
        expect(seen.note).toEqual({ target: "0.2.0", at: NOW, connected: false, profile: null });
    });

    it("runs nothing that changed since it was downloaded, and keeps no copy of it", async () => {
        const changed = Buffer.from(installer);
        changed[0] = (changed[0] ?? 0) ^ 1;
        await writeFile(ready.path, changed);
        const { given, done, seen } = steps({ connected: true });
        await expect(installUpdate(ready, given)).resolves.toBe("changed");
        expect(done).toEqual(["disconnect", "reconnect"]);
        expect(seen.reconnected).toBe(PROFILE);
        expect(runFolders()).toEqual([]);
        await expect(readNote(folder)).resolves.toBeNull();
    });

    it("runs nothing that grew or shrank since it was downloaded", async () => {
        for (const bytes of [Buffer.concat([installer, Buffer.from("x")]), installer.subarray(1)]) {
            await writeFile(ready.path, bytes);
            const { given, done } = steps();
            await expect(installUpdate(ready, given)).resolves.toBe("changed");
            expect(done).not.toContain("launch");
        }
    });

    it("when the prompt is cancelled, changes nothing and reconnects that profile", async () => {
        for (let round = 0; round < 3; round++) {
            const { given, done, seen } = steps({ connected: true, launched: "cancelled" });
            await expect(installUpdate(ready, given)).resolves.toBe("cancelled");
            expect(done).toEqual(["disconnect", "launch", "reconnect"]);
            expect(seen.reconnected).toBe(PROFILE);
        }
        // Nothing left on disk but the download, however many times.
        expect(existsSync(join(folder, "resume.json"))).toBe(false);
        expect(runFolders()).toEqual([]);
        expect(readFileSync(ready.path)).toEqual(installer);
    });

    it("says when the setup program could not be started, and cleans up", async () => {
        const { given, done } = steps({ connected: true, launched: "failed" });
        await expect(installUpdate(ready, given)).resolves.toBe("failed");
        expect(done).toEqual(["disconnect", "launch", "reconnect"]);
        expect(runFolders()).toEqual([]);
        const throwing = steps({ connected: false });
        throwing.given.launch = async () => {
            throw new Error("spawn failed");
        };
        await expect(installUpdate(ready, throwing.given)).resolves.toBe("failed");
        expect(throwing.done).toEqual([]);
        expect(runFolders()).toEqual([]);
    });

    it("keeps the copy once the setup program may be using it", async () => {
        const { given } = steps({ connected: false });
        await installUpdate(ready, given);
        expect(runFolders()).toHaveLength(1);
    });

    it("reconnects even when cleaning up fails", async () => {
        // A folder where the note should be can't be written: nothing starts.
        await mkdir(join(folder, "resume.json"));
        await writeFile(join(folder, "resume.json", "inside"), "x");
        const { given, done } = steps({ connected: true });
        await expect(installUpdate(ready, given)).resolves.toBe("failed");
        expect(done).toEqual(["disconnect", "reconnect"]);
    });

    it("installs nothing when the service refuses to disconnect, and touches nothing", async () => {
        const { given, done } = steps({ connected: true, down: "refused" });
        await expect(installUpdate(ready, given)).resolves.toBe("not_disconnected");
        expect(done).toEqual(["disconnect"]);
    });

    it("brings the connection back if a disconnect that ran late finishes after all", async () => {
        const { given, done, seen } = steps({ connected: true, down: "late" });
        await expect(installUpdate(ready, given)).resolves.toBe("not_disconnected");
        expect(done).toEqual(["disconnect", "watch"]);
        seen.later?.();
        expect(done).toEqual(["disconnect", "watch", "reconnect"]);
        expect(seen.reconnected).toBe(PROFILE);
    });
});

describe("one install at a time, and only of a ready update", () => {
    it("does nothing unless the updater hands over an installer", async () => {
        const { given, done } = steps();
        const ended: (InstallNotice | null)[] = [];
        await restartToUpdate(
            { beginInstall: () => null, endInstall: (n) => ended.push(n) },
            given,
        );
        expect(done).toEqual([]);
        expect(ended).toEqual([]);
    });

    it("tells the updater how it ended", async () => {
        const ended: (InstallNotice | null)[] = [];
        const updater = {
            beginInstall: () => ready,
            endInstall: (n: InstallNotice | null) => ended.push(n),
        };
        await restartToUpdate(updater, steps({ launched: "cancelled" }).given);
        await restartToUpdate(updater, steps().given);
        expect(ended).toEqual(["cancelled", null]);
    });

    it("does nothing in a copy that cannot update, which has no folder", async () => {
        const begin = vi.fn(() => ready);
        const makeSteps = vi.fn(() => steps().given);
        const updater = { beginInstall: begin, endInstall: () => {}, folder: () => null };
        await createInstall(updater, makeSteps)();
        expect(makeSteps).not.toHaveBeenCalled();
        expect(begin).not.toHaveBeenCalled();
        const able = { beginInstall: begin, endInstall: () => {}, folder: () => folder };
        await createInstall(able, makeSteps)();
        expect(makeSteps).toHaveBeenCalledWith(folder);
    });
});

const LAUNCHER = {
    systemRoot: "C:\\Windows",
    app: "C:\\Program Files\\UBC VPN\\UBC VPN.exe",
    pid: 4242,
    env: {
        PATH: "C:\\made-up",
        USERPROFILE: "C:\\Users\\someone",
        LOCALAPPDATA: "C:\\Users\\someone\\AppData\\Local",
        ELECTRON_RUN_AS_NODE: "1",
        NODE_OPTIONS: "--inspect",
        UBC_VPN_DEV: "1",
    },
};

describe("how the setup program is started on Windows", () => {
    const script = launcherScript();

    it("asks for elevation, silently, with no relaunch left to the setup program", () => {
        expect(script).toContain("$start.Verb = 'runas'");
        expect(script).toContain("$start.UseShellExecute = $true");
        expect(script).toContain("$start.Arguments = '/S --updated'");
        expect(script).not.toContain("--force-run");
        expect(script).toContain("[System.Diagnostics.Process]::Start($start)");
    });

    it("gives paths only through the environment", () => {
        const path = "C:\\Users\\someone\\AppData\\Local\\UBC VPN\\updates\\run-x\\a'b;$(c).exe";
        const { file, args, env } = windowsLaunch(path, LAUNCHER);
        expect(file).toBe(
            join("C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        );
        expect(args.join(" ")).not.toContain(path);
        expect(args.join(" ")).not.toContain(LAUNCHER.app);
        expect(args).toContain("-NoProfile");
        expect(env.UBC_VPN_INSTALLER).toBe(path);
        expect(env.UBC_VPN_APP).toBe(LAUNCHER.app);
        expect(env.UBC_VPN_APP_PID).toBe("4242");
        expect(env.SystemRoot).toBe("C:\\Windows");
    });

    it("passes on what Windows programs need, and nothing of Electron's or the app's", () => {
        const { env } = windowsLaunch("x.exe", LAUNCHER);
        expect(env).toMatchObject({ PATH: "C:\\made-up", USERPROFILE: "C:\\Users\\someone" });
        for (const name of ["ELECTRON_RUN_AS_NODE", "NODE_OPTIONS", "UBC_VPN_DEV"]) {
            expect(env, name).not.toHaveProperty(name);
        }
    });

    it("reads exit 2 as the prompt cancelled, anything else as failed", () => {
        expect(launchedFrom(2)).toBe("cancelled");
        for (const code of [0, 1, 3, null]) {
            expect(launchedFrom(code)).toBe("failed");
        }
    });

    function fakeSpawn() {
        const child = Object.assign(new EventEmitter(), {
            stdout: Object.assign(new EventEmitter(), { destroy: vi.fn() }),
            unref: vi.fn(),
        });
        const start = vi.fn(() => child);
        return { child, start: start as unknown as typeof spawn, calls: start };
    }

    it("runs the launcher on its own, with the kept environment", async () => {
        const { child, start, calls } = fakeSpawn();
        const launched = launchWindows(LAUNCHER, start)("x.exe");
        const [file, args, options] = calls.mock.calls[0] as unknown as [
            string,
            string[],
            { env: Record<string, string>; detached: boolean; stdio: unknown },
        ];
        const expected = windowsLaunch("x.exe", LAUNCHER);
        expect([file, args]).toEqual([expected.file, expected.args]);
        expect(options.env).toEqual(expected.env);
        expect(options.detached).toBe(true);
        child.stdout.emit("data", "started\r\n");
        await expect(launched).resolves.toBe("started");
        expect(child.unref).toHaveBeenCalled();
        expect(child.stdout.destroy).toHaveBeenCalled();
    });

    it("waits as long as the prompt does, then reads how the launcher ended", async () => {
        for (const [code, outcome] of [
            [2, "cancelled"],
            [1, "failed"],
        ] as const) {
            const { child, start } = fakeSpawn();
            const launched = launchWindows(LAUNCHER, start)("x.exe");
            child.emit("close", code);
            await expect(launched).resolves.toBe(outcome);
        }
        const { child, start } = fakeSpawn();
        const launched = launchWindows(LAUNCHER, start)("x.exe");
        child.emit("error", new Error("no such program"));
        await expect(launched).resolves.toBe("failed");
    });

    it("uses that launcher only on Windows", async () => {
        const windows = fakeSpawn();
        void launcherFor("win32", LAUNCHER, windows.start)("x.exe");
        expect(windows.calls).toHaveBeenCalledTimes(1);
        for (const platform of ["darwin", "linux"] as const) {
            const other = fakeSpawn();
            await expect(launcherFor(platform, LAUNCHER, other.start)("x.exe")).resolves.toBe(
                "failed",
            );
            expect(other.calls).not.toHaveBeenCalled();
        }
    });
});

// The script itself, in real PowerShell. Never elevated: the verb is taken out or
// the start is replaced, and every path is a stand-in in the test's own folder.
describe.runIf(process.platform === "win32")("the launcher script, run for real", () => {
    const POWERSHELL = windowsLaunch("x", { ...LAUNCHER, env: process.env });

    function runScript(script: string, env: Record<string, string>) {
        const result = spawnSync(
            POWERSHELL.file,
            ["-NoProfile", "-NonInteractive", "-Command", script],
            {
                env: { SystemRoot: process.env.SystemRoot ?? "C:\\Windows", ...env },
                encoding: "utf8",
                windowsHide: true,
                timeout: 60_000,
            },
        );
        return { code: result.status, out: result.stdout };
    }
    const START = "[System.Diagnostics.Process]::Start($start)";
    const throwing = (code: number) =>
        `throw ([System.Management.Automation.MethodInvocationException]::new('made up', [System.ComponentModel.Win32Exception]::new(${code})))`;

    it("reads the Windows error 1223 as cancelled, and any other as failed", () => {
        const production = launcherScript();
        expect(production).toContain(START);
        expect(runScript(production.replace(START, throwing(1223)), {}).code).toBe(2);
        expect(runScript(production.replace(START, throwing(5)), {}).code).toBe(1);
    });

    it("finds the error code in the exception a failed start really throws", () => {
        // No verb and no such file, so no prompt can appear: Windows says error 2.
        const script = launcherScript({ verb: "", setupArgs: "", appArgs: "" });
        const env = { UBC_VPN_INSTALLER: join(folder, "no-such-file.exe") };
        expect(runScript(script, env).code).toBe(1);
        expect(runScript(script.replace("-eq 1223", "-eq 2"), env).code).toBe(2);
    });

    async function standIns(
        setupExit: number,
        change: { limitMs?: number; fallbackMs?: number; setupBody?: string } = {},
    ) {
        const { setupBody = "", ...timing } = change;
        const run = join(folder, "run-standin");
        await mkdir(run);
        const setupMark = join(folder, "setup-ran");
        const appMark = join(folder, "app-ran");
        const setup = join(run, "setup.cmd");
        await writeFile(
            setup,
            `@echo off\r\necho ran> "${setupMark}"\r\n${setupBody}exit /b ${setupExit}\r\n`,
        );
        const app = join(folder, "app.mjs");
        await writeFile(
            app,
            `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(appMark)}, "ran");\n`,
        );
        const script = launcherScript({ verb: "", setupArgs: "", appArgs: `"${app}"`, ...timing });
        const env = {
            UBC_VPN_INSTALLER: setup,
            UBC_VPN_APP: process.execPath,
            // No such process: nothing to wait for.
            UBC_VPN_APP_PID: "1",
        };
        return { script, env, run, setupMark, appMark };
    }

    it.each([0, 3])(
        "says started, waits for setup, starts the app once, and deletes its copy (setup exit %i)",
        async (exit) => {
            const { script, env, run, setupMark, appMark } = await standIns(exit);
            const { code, out } = runScript(script, env);
            expect(code).toBe(0);
            expect(out).toContain("started");
            expect(existsSync(setupMark)).toBe(true);
            await expect.poll(() => existsSync(appMark), { timeout: 15_000 }).toBe(true);
            expect(existsSync(run)).toBe(false);
        },
        60_000,
    );

    const WAIT = `$setup.WaitForExit(${SETUP_LIMIT_MS})`;

    it("waits as long as it should, and no longer, by default", () => {
        const production = launcherScript();
        expect(production).toContain(WAIT);
        expect(production).toContain(`Sleep(${SETUP_FALLBACK_MS})`);
        expect(SETUP_LIMIT_MS).toBe(600_000);
        expect(SETUP_FALLBACK_MS).toBe(120_000);
    });

    it("still starts the app when the setup program cannot be waited for, after the fixed time", async () => {
        const { script, env, run, appMark } = await standIns(0, { fallbackMs: 3_000 });
        const broken = script.replace(WAIT, "$setup.NoSuchMethod()");
        expect(broken).not.toBe(script);
        const before = Date.now();
        const { code, out } = runScript(broken, env);
        expect(code).toBe(0);
        expect(out).toContain("started");
        expect(Date.now() - before).toBeGreaterThanOrEqual(3_000);
        await expect.poll(() => existsSync(appMark), { timeout: 15_000 }).toBe(true);
        // Setup may still be using its copy.
        expect(existsSync(run)).toBe(true);
    }, 60_000);

    it("still starts the app when there is no handle to wait on", async () => {
        const { script, env, appMark } = await standIns(0, { fallbackMs: 200 });
        const noHandle = script.replace(START, "$null");
        expect(noHandle).not.toBe(script);
        const { code, out } = runScript(noHandle, env);
        expect(code).toBe(0);
        expect(out).toContain("started");
        await expect.poll(() => existsSync(appMark), { timeout: 15_000 }).toBe(true);
    }, 60_000);

    it("still starts the app when the setup program is running at the limit, and keeps its copy", async () => {
        const { script, env, run, appMark } = await standIns(0, {
            limitMs: 200,
            setupBody: `"%SystemRoot%\\System32\\ping.exe" -n 4 127.0.0.1 >nul\r\n`,
        });
        const { code } = runScript(script, env);
        expect(code).toBe(0);
        await expect.poll(() => existsSync(appMark), { timeout: 15_000 }).toBe(true);
        expect(existsSync(run)).toBe(true);
        // Let the stand-in finish, so its folder can be removed.
        await new Promise((done) => setTimeout(done, 4_000));
    }, 60_000);

    it("starts nothing when there is no app left to start", async () => {
        const { script, env, appMark } = await standIns(3);
        const { code } = runScript(script, { ...env, UBC_VPN_APP: join(folder, "gone.exe") });
        expect(code).toBe(0);
        await new Promise((done) => setTimeout(done, 500));
        expect(existsSync(appMark)).toBe(false);
    }, 60_000);
});

describe("what counts as a connection to take down", () => {
    const up = (state: string): LinkState =>
        ({ link: "ready", conn: { state } }) as unknown as LinkState;

    it("is one that is up or on its way, and those come back afterwards", () => {
        expect(tunnelUp(up("connected"))).toBe(true);
        expect(tunnelUp(up("connecting"))).toBe(true);
        for (const state of ["disconnected", "disconnecting", "failed", "login_needed"]) {
            expect(tunnelUp(up(state)), state).toBe(false);
        }
        expect(tunnelUp({ link: "starting" })).toBe(false);
    });

    it("is gone only when the service says so", () => {
        for (const state of ["disconnected", "failed", "login_needed"]) {
            expect(tunnelDown(up(state)), state).toBe(true);
        }
        for (const state of ["connected", "connecting", "disconnecting"]) {
            expect(tunnelDown(up(state)), state).toBe(false);
        }
        expect(tunnelDown({ link: "unavailable", reason: "not_running" })).toBe(false);
    });
});

describe("disconnecting before an update", () => {
    function link(after: number | null, result: ActionResult = { ok: true }) {
        let disconnected = false;
        const listeners = new Set<() => void>();
        return {
            disconnect: async () => {
                if (after !== null) {
                    setTimeout(() => {
                        disconnected = true;
                        for (const listener of [...listeners]) {
                            listener();
                        }
                    }, after);
                }
                return result;
            },
            isDisconnected: () => disconnected,
            subscribe: (listener: () => void) => {
                listeners.add(listener);
                return () => listeners.delete(listener);
            },
            listeners,
        };
    }

    it("waits until the service says it is disconnected", async () => {
        const fake = link(20);
        await expect(disconnectAndWait(fake, 5_000)).resolves.toBe("down");
        expect(fake.listeners.size).toBe(0);
    });

    it("says it ran late after the limit", async () => {
        const fake = link(null);
        await expect(disconnectAndWait(fake, 50)).resolves.toBe("late");
        expect(fake.listeners.size).toBe(0);
    });

    it("does not wait out the limit when the service refuses at once", async () => {
        const fake = link(null, {
            ok: false,
            error: { kind: "service_unavailable" },
        });
        const started = Date.now();
        await expect(disconnectAndWait(fake, 5_000)).resolves.toBe("refused");
        expect(Date.now() - started).toBeLessThan(2_000);
    });

    it("notices a late disconnect finishing, within its limit, and only once", async () => {
        const fake = link(20);
        await fake.disconnect();
        const then = vi.fn();
        whenDown(fake, then, 5_000);
        await vi.waitFor(() => expect(then).toHaveBeenCalledTimes(1));
        expect(fake.listeners.size).toBe(0);
    });

    it("stops watching after that limit", async () => {
        const fake = link(null);
        const then = vi.fn();
        whenDown(fake, then, 20);
        await vi.waitFor(() => expect(fake.listeners.size).toBe(0));
        expect(then).not.toHaveBeenCalled();
    });
});
