// The update launcher started as the app really starts it: a real `spawn` with
// the options the app uses, from a parent that quits, under Node and under
// Electron. Mocks hid that it could not run at all, so nothing here is faked but
// the two programs it starts, which are stand-ins in a temporary folder. Never
// elevated: the verb is taken out or the start replaced, and that is checked first.

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { windowsLaunch } from "../src/main/update/install";
import { checkedScript, testScript, withoutElevating } from "./update-launcher-guard";

const PARENT = resolve(__dirname, "update-launcher-parent.cjs");
const ELECTRON = resolve(__dirname, "../node_modules/electron/dist/electron.exe");
const SYSTEM_ROOT = process.env.SystemRoot ?? "C:\\Windows";

let base: string;
beforeEach(async () => {
    base = await mkdtemp(join(tmpdir(), "upd-launcher-"));
});
afterEach(async () => {
    // A launcher that is still running holds its folder for a moment.
    await rm(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 500 });
});

interface Told {
    outcome: string;
    code?: number;
    at: number;
}

/** Runs a parent that starts `script`, and waits until it has quit. */
async function fromParent(kind: "Node" | "Electron", path: string, script: string): Promise<Told> {
    const out = join(base, `told-${kind}.json`);
    const spec = join(base, `spec-${kind}.json`);
    const { file, args, options, env } = windowsLaunch(
        path,
        { systemRoot: SYSTEM_ROOT, app: process.execPath, pid: 0, env: process.env },
        checkedScript(script),
    );
    await writeFile(spec, JSON.stringify({ file, args, options, env, out }));
    const { ELECTRON_RUN_AS_NODE: _, ...clean } = process.env;
    const parent = spawn(kind === "Node" ? process.execPath : ELECTRON, [PARENT], {
        stdio: "ignore",
        windowsHide: true,
        env: {
            ...clean,
            UBC_VPN_TEST_LAUNCH: spec,
            // Electron makes a profile for itself; not in the real one.
            APPDATA: join(base, "roaming"),
            LOCALAPPDATA: join(base, "local"),
        },
    });
    await new Promise((done) => parent.on("close", done));
    return JSON.parse(readFileSync(out, "utf8"));
}

/** A setup stand-in that takes seconds, so the launcher must outlive its parent. */
async function standIns() {
    const run = join(base, "run-standin");
    await mkdir(run);
    const setupMark = join(base, "setup-ran");
    const appMark = join(base, "app-ran");
    const setup = join(run, "setup.cmd");
    await writeFile(
        setup,
        `@echo off\r\n"%SystemRoot%\\System32\\ping.exe" -n 4 127.0.0.1 >nul\r\necho ran> "${setupMark}"\r\nexit /b 0\r\n`,
    );
    const app = join(base, "app.mjs");
    await writeFile(
        app,
        `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(appMark)}, String(Date.now()));\n`,
    );
    const script = testScript({ verb: "", setupArgs: "", appArgs: `"${app}"` });
    return { script, setup, run, setupMark, appMark };
}

const throwing = (code: number) =>
    `throw ([System.Management.Automation.MethodInvocationException]::new('made up', [System.ComponentModel.Win32Exception]::new(${code})))`;

const PARENTS = ["Node", "Electron"] as const;

describe.runIf(process.platform === "win32")("the launcher, started as the app starts it", () => {
    it("has Electron to run it, where it matters", () => {
        // A skipped test passes: in CI, a missing Electron must not pass quietly.
        if (process.env.GITHUB_ACTIONS === "true") {
            expect(existsSync(ELECTRON)).toBe(true);
        }
    });

    it.each(PARENTS)(
        "from %s: says started, outlives its parent, and finishes the whole job",
        async (kind) => {
            if (kind === "Electron" && !existsSync(ELECTRON)) {
                return;
            }
            const { script, setup, run, setupMark, appMark } = await standIns();
            const told = await fromParent(kind, setup, script);
            expect(told.outcome).toBe("started");
            // The parent has gone. Setup is still running, and the rest is the launcher's.
            expect(existsSync(setupMark)).toBe(false);
            expect(existsSync(appMark)).toBe(false);
            await expect.poll(() => existsSync(appMark), { timeout: 30_000 }).toBe(true);
            expect(existsSync(setupMark)).toBe(true);
            expect(Number(readFileSync(appMark, "utf8"))).toBeGreaterThan(told.at);
            await expect.poll(() => existsSync(run), { timeout: 15_000 }).toBe(false);
        },
        90_000,
    );

    it.each(PARENTS)(
        "from %s: passes on a cancelled prompt and a failed start",
        async (kind) => {
            if (kind === "Electron" && !existsSync(ELECTRON)) {
                return;
            }
            const missing = join(base, "no-such-file.exe");
            expect(await fromParent(kind, missing, withoutElevating(throwing(1223)))).toMatchObject(
                { outcome: "closed", code: 2 },
            );
            expect(await fromParent(kind, missing, withoutElevating(throwing(5)))).toMatchObject({
                outcome: "closed",
                code: 1,
            });
        },
        90_000,
    );

    it("runs in System32, so it holds no folder the setup program must remove", () => {
        const { options } = windowsLaunch("x.exe", {
            systemRoot: "C:\\Windows",
            app: "app.exe",
            pid: 1,
            env: {},
        });
        expect(options.cwd).toBe(join("C:\\Windows", "System32"));
    });
});
