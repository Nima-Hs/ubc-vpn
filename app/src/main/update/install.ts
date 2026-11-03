// "Restart to update": disconnect cleanly, copy the downloaded installer
// into a fresh folder of its own, check it again there, start it behind one
// administrator prompt, and quit; the setup program starts the app again,
// which reconnects if it was connected. The steps are the same on every
// system; only how the setup program is started differs (`launchWindows`).
// No Electron import: everything it touches is passed in, so it is tested
// without running any installer.

import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { copyFile, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { LinkState } from "@shared/api";
import type { InstallNotice } from "@shared/updates";
import { checkInstaller, type UpdateFile, UpdateRefused } from "./list";
import type { ReadyInstaller } from "./updater";

/** What starting the setup program came to. */
export type Launched = "started" | "cancelled" | "failed";

/** Starts the setup program at `path`, silently, behind the system's administrator prompt. */
export type Launcher = (path: string) => Promise<Launched>;

export interface InstallSteps {
    /** The updates folder: the copy goes in a fresh folder inside it. */
    folder: string;
    /** Whether the VPN is connected now, so it is reconnected afterwards. */
    connected(): boolean;
    /** Disconnects through the service; `true` once it is disconnected. */
    disconnect(): Promise<boolean>;
    launch: Launcher;
    /** Connects again, as when the user presses Connect. */
    reconnect(): void;
    quit(): void;
}

/**
 * Copies the installer into a new folder only this run uses, and checks the
 * copy's size and SHA-256 against the list again. The copy is what runs,
 * straight after this, so a file changed since it was downloaded is never
 * started. Returns the copy's path.
 */
export async function stageInstaller(
    source: string,
    entry: UpdateFile,
    folder: string,
): Promise<string> {
    const run = await mkdtemp(join(folder, "run-"));
    const copy = join(run, entry.name);
    await copyFile(source, copy, constants.COPYFILE_EXCL);
    const file = await open(copy, "r");
    let matches = false;
    try {
        await checkInstaller(file, entry);
        matches = true;
    } finally {
        // Closed before it runs: the setup program must not find it open.
        await file.close();
        if (!matches) {
            await rm(run, { recursive: true, force: true });
        }
    }
    return copy;
}

/** The note left for the next start: reconnect once the update is installed. */
const RESUME = "resume.json";

export async function leaveResume(folder: string): Promise<void> {
    await writeFile(join(folder, RESUME), `${JSON.stringify({ reconnect: true })}\n`, {
        mode: 0o600,
    });
}

/** Reads and removes the note; `true` if the app should reconnect. */
export async function takeResume(folder: string): Promise<boolean> {
    const path = join(folder, RESUME);
    try {
        const text = await readFile(path, "utf8");
        return (JSON.parse(text) as { reconnect?: unknown }).reconnect === true;
    } catch {
        return false;
    } finally {
        await rm(path, { force: true });
    }
}

/**
 * Installs `ready`. Returns `null` once the setup program has started and
 * the app has been asked to quit, or why nothing was installed. Whatever
 * stops it, a connection it took down is brought back.
 */
export async function installUpdate(
    ready: ReadyInstaller,
    steps: InstallSteps,
): Promise<InstallNotice | null> {
    const wasConnected = steps.connected();
    if (wasConnected && !(await steps.disconnect())) {
        return "not_disconnected";
    }
    const giveUp = async (notice: InstallNotice): Promise<InstallNotice> => {
        await rm(join(steps.folder, RESUME), { force: true });
        if (wasConnected) {
            steps.reconnect();
        }
        return notice;
    };
    let copy: string;
    try {
        copy = await stageInstaller(ready.path, ready.entry, steps.folder);
        if (wasConnected) {
            await leaveResume(steps.folder);
        }
    } catch (error) {
        return giveUp(error instanceof UpdateRefused ? "changed" : "failed");
    }
    const launched = await steps.launch(copy).catch((): Launched => "failed");
    if (launched !== "started") {
        return giveUp(launched);
    }
    steps.quit();
    return null;
}

/**
 * How Windows is asked: PowerShell's `Start-Process -Verb RunAs`, which
 * shows the UAC prompt. The path is passed in the environment, never in the
 * script, so no character in it can change what runs. `/S` installs
 * silently; `--updated --force-run` has the setup program start the app
 * again afterwards. Exit 2 is ERROR_CANCELLED (1223): the user said no.
 */
export function windowsLaunch(path: string, systemRoot: string) {
    const script = [
        "try {",
        "  Start-Process -FilePath $env:UBC_VPN_INSTALLER -ArgumentList '/S','--updated','--force-run' -Verb RunAs -ErrorAction Stop",
        "  exit 0",
        "} catch {",
        "  if ($_.Exception.InnerException.NativeErrorCode -eq 1223) { exit 2 }",
        "  exit 1",
        "}",
    ].join("\n");
    return {
        file: join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        args: ["-NoProfile", "-NonInteractive", "-Command", script],
        env: { SystemRoot: systemRoot, UBC_VPN_INSTALLER: path },
    };
}

/** What an exit code of the PowerShell step means. */
export function launchedFrom(code: number | null): Launched {
    return code === 0 ? "started" : code === 2 ? "cancelled" : "failed";
}

/** Starts the setup program on Windows. Never called by tests. */
export function launchWindows(systemRoot: string): Launcher {
    return (path) =>
        new Promise((done) => {
            const { file, args, env } = windowsLaunch(path, systemRoot);
            const child = spawn(file, args, { env, stdio: "ignore", windowsHide: true });
            child.on("error", () => done("failed"));
            child.on("exit", (code) => done(launchedFrom(code)));
        });
}

/** What `restartToUpdate` needs of the updater. */
export interface InstallingUpdater {
    beginInstall(): ReadyInstaller | null;
    endInstall(notice: InstallNotice | null): void;
}

/** "Restart to update", from the button: one at a time, and only with an installer ready. */
export async function restartToUpdate(
    updater: InstallingUpdater,
    steps: InstallSteps,
): Promise<void> {
    const ready = updater.beginInstall();
    if (ready === null) {
        return;
    }
    const notice = await installUpdate(ready, steps).catch((): InstallNotice => "failed");
    updater.endInstall(notice);
}

/**
 * Whether there is a connection to take down before installing, and to bring
 * back afterwards: one that is up or on its way. The setup program stops the
 * service, so a connection under way must not be left to it.
 */
export function tunnelUp(state: LinkState): boolean {
    return state.link === "ready" && ["connected", "connecting"].includes(state.conn.state);
}

/** Whether the service says no connection is left: disconnected, or one that ended. */
export function tunnelDown(state: LinkState): boolean {
    return (
        state.link === "ready" &&
        ["disconnected", "failed", "login_needed"].includes(state.conn.state)
    );
}

/** How long a disconnect before an update may take. */
export const DISCONNECT_LIMIT_MS = 30_000;

/**
 * Asks the service to disconnect and waits until it says it has, or the
 * limit passes. `true` once the state is "disconnected".
 */
export function disconnectAndWait(
    link: {
        disconnect(): Promise<unknown>;
        isDisconnected(): boolean;
        subscribe(listener: () => void): () => void;
    },
    limitMs = DISCONNECT_LIMIT_MS,
): Promise<boolean> {
    return new Promise((done) => {
        let finished = false;
        const finish = (result: boolean) => {
            if (!finished) {
                finished = true;
                clearTimeout(timer);
                stop();
                done(result);
            }
        };
        const timer = setTimeout(() => finish(false), limitMs);
        const stop = link.subscribe(() => {
            if (link.isDisconnected()) {
                finish(true);
            }
        });
        void link.disconnect().then(() => {
            if (link.isDisconnected()) {
                finish(true);
            }
        });
    });
}
