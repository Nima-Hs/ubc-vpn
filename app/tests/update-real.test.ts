// A real update, on a disposable CI runner only: from an installed app, with the
// launcher as the app starts it, through a real setup program with a higher version.
// It runs real installers and changes Program Files, so it runs only in the
// "update end to end" job of .github/workflows/installer-windows.yml, which sets
// the variable below on a GitHub runner. Everywhere else it is skipped.
//
// What it shows: the launcher outlives an Electron parent; `runas` starts setup;
// setup replaces the running app; the launcher starts the new app; and the new app
// finds its note. Those builds carry a throwaway key, made in that job and thrown
// away, because a build with the placeholder never reads a note.
//
// What it cannot show: the real UAC prompt, which GitHub's runners do not show, so
// neither approving nor cancelling it, nor waiting on a process across it; a real
// signed list, or the download, which this test does not go through.

import { execFileSync, spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { windowsLaunch } from "../src/main/update/install";
import { leaveNote, RESUME_NOTE } from "../src/main/update/resume";

const REAL =
    process.env.UBC_VPN_TEST_REAL_UPDATE === "1" &&
    process.env.GITHUB_ACTIONS === "true" &&
    process.platform === "win32";
const INSTALLED = "C:\\Program Files\\UBC VPN\\UBC VPN.exe";
const MADE_UP_PROFILE = "0123456789abcdef0123456789abcdef";

const programVersion = (): string =>
    execFileSync(
        "powershell.exe",
        [
            "-NoProfile",
            "-Command",
            `(Get-Item -LiteralPath '${INSTALLED}').VersionInfo.ProductVersion`,
        ],
        { encoding: "utf8" },
    ).trim();

const appProcesses = (): string[] =>
    spawnSync("tasklist", ["/FI", "IMAGENAME eq UBC VPN.exe", "/FO", "CSV", "/NH"], {
        encoding: "utf8",
    })
        .stdout.split("\n")
        .filter((line) => line.includes("UBC VPN.exe"));

describe.runIf(REAL)("a real update on a runner", () => {
    it("replaces the running app, starts the new one, and the new one finds its note", async () => {
        const installer = process.env.UBC_VPN_TEST_NEW_INSTALLER as string;
        const version = process.env.UBC_VPN_TEST_NEW_VERSION as string;
        expect(existsSync(installer)).toBe(true);
        expect(programVersion()).not.toContain(version);

        // The old app, running, as it is when the user presses the button.
        spawn(INSTALLED, [], { detached: true, stdio: "ignore" }).unref();
        await expect.poll(() => appProcesses().length > 0, { timeout: 30_000 }).toBe(true);
        await new Promise((done) => setTimeout(done, 10_000));

        const local = process.env.LOCALAPPDATA as string;
        const folder = join(local, "UBC VPN", "updates");
        const run = join(folder, "run-end-to-end");
        mkdirSync(run, { recursive: true });
        const copy = join(run, basename(installer));
        copyFileSync(installer, copy);
        // A profile that does not exist: the note is used up, and no login starts.
        await leaveNote(folder, {
            target: version,
            at: Date.now(),
            connected: true,
            profile: MADE_UP_PROFILE,
        });

        // The production script, `runas` and all: this runner shows no prompt.
        const { file, args, options, env } = windowsLaunch(copy, {
            systemRoot: process.env.SystemRoot ?? "C:\\Windows",
            app: INSTALLED,
            pid: 0,
            env: process.env,
        });
        const out = resolve(process.env.RUNNER_TEMP as string, "told.json");
        const spec = resolve(process.env.RUNNER_TEMP as string, "launch.json");
        writeFileSync(spec, JSON.stringify({ file, args, options, env, out }));
        const { ELECTRON_RUN_AS_NODE: _, ...clean } = process.env;
        const parent = spawn(
            resolve(__dirname, "../node_modules/electron/dist/electron.exe"),
            [resolve(__dirname, "update-launcher-parent.cjs")],
            { stdio: "ignore", env: { ...clean, UBC_VPN_TEST_LAUNCH: spec } },
        );
        await new Promise((done) => parent.on("close", done));
        expect(JSON.parse(readFileSync(out, "utf8")).outcome).toBe("started");

        // The new program, running, with its note used up and the copy gone.
        await expect
            .poll(() => programVersion().includes(version), { timeout: 480_000, interval: 5_000 })
            .toBe(true);
        await expect.poll(() => appProcesses().length > 0, { timeout: 120_000 }).toBe(true);
        await expect
            .poll(() => existsSync(join(folder, RESUME_NOTE)), {
                timeout: 120_000,
                interval: 2_000,
            })
            .toBe(false);
        await expect.poll(() => existsSync(run), { timeout: 30_000 }).toBe(false);
    }, 720_000);
});
