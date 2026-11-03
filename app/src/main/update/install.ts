// "Restart to update": disconnect cleanly, copy the downloaded installer into a
// fresh folder of its own, check it again there, start it behind one
// administrator prompt, and quit. A small launcher outlives the app, waits for
// the setup program, and starts the app again, which reconnects the profile
// that was connected. The steps are the same on every system; only how the
// setup program is started differs (`launchWindows`). No Electron import:
// everything it touches is passed in, so it is tested without running any
// installer.

import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { copyFile, mkdtemp, open, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { ActionResult, LinkState } from "@shared/api";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { InstallNotice } from "@shared/updates";
import { checkInstaller, type UpdateFile, UpdateRefused } from "./list";
import { clearNote, leaveNote } from "./resume";
import type { ReadyInstaller } from "./updater";

/** What starting the setup program came to. */
export type Launched = "started" | "cancelled" | "failed";

/** Starts the setup program at `path`, silently, behind the system's administrator prompt. */
export type Launcher = (path: string) => Promise<Launched>;

/** What asking the service to disconnect came to. */
export type Disconnected =
    /** The service says no connection is left. */
    | "down"
    /** The service refused: the connection is as it was. */
    | "refused"
    /** Still going when the limit passed. */
    | "late";

export interface InstallSteps {
    /** The updates folder: the copy goes in a fresh folder inside it. */
    folder: string;
    /** Whether a connection is up or on its way, so it is brought back afterwards. */
    connected(): boolean;
    /** The profile that connection is for, or `null` if the app does not know. */
    connectedProfile(): ProfileId | null;
    disconnect(): Promise<Disconnected>;
    /** A disconnect ran late: watches for it to finish, then brings this profile back. */
    disconnectRanLate(profile: ProfileId | null): void;
    /** The connection an earlier press took down late, which this one takes over. */
    carried?: { profile: ProfileId | null } | undefined;
    launch: Launcher;
    /** Brings back the connection for this profile, and says so if it cannot. */
    reconnect(profile: ProfileId | null): void;
    quit(): void;
    now(): number;
}

/**
 * Copies the installer into a new folder only this run uses, and checks the
 * copy's size and SHA-256 against the list again. That catches a file changed
 * since it was downloaded, up to this moment. It does not protect the copy
 * after this: the setup program opens it only after the administrator prompt,
 * which waits for a person with no time limit, and a program running as the
 * user can replace the file meanwhile. See "What it does not stop" in
 * docs/architecture.md. Returns the copy's path.
 */
export async function stageInstaller(
    source: string,
    entry: UpdateFile,
    folder: string,
): Promise<string> {
    const run = await mkdtemp(join(folder, "run-"));
    const copy = join(run, entry.name);
    let matches = false;
    try {
        await copyFile(source, copy, constants.COPYFILE_EXCL);
        const file = await open(copy, "r");
        try {
            await checkInstaller(file, entry);
            matches = true;
        } finally {
            // Closed before it runs: the setup program must not find it open.
            await file.close();
        }
    } finally {
        if (!matches) {
            await rm(run, { recursive: true, force: true });
        }
    }
    return copy;
}

/**
 * Installs `ready`. Returns `null` once the setup program has started and the
 * app has been asked to quit, or why nothing was installed. Unless the service
 * refused to disconnect, which leaves the connection as it was, a connection it
 * took down is brought back, for the profile it was for.
 */
export async function installUpdate(
    ready: ReadyInstaller,
    steps: InstallSteps,
): Promise<InstallNotice | null> {
    const wasConnected = steps.carried !== undefined || steps.connected();
    const profile = steps.carried?.profile ?? (wasConnected ? steps.connectedProfile() : null);
    if (wasConnected) {
        const down = await steps.disconnect();
        if (down === "refused") {
            return "not_disconnected";
        }
        if (down === "late") {
            steps.disconnectRanLate(profile);
            return "not_disconnected";
        }
    }
    let copy: string | null = null;
    const giveUp = async (notice: InstallNotice): Promise<InstallNotice> => {
        try {
            if (copy !== null) {
                await rm(dirname(copy), { recursive: true, force: true });
            }
            await clearNote(steps.folder);
        } catch {
            // Cleared at a later start; the connection still comes back.
        } finally {
            if (wasConnected) {
                steps.reconnect(profile);
            }
        }
        return notice;
    };
    try {
        copy = await stageInstaller(ready.path, ready.entry, steps.folder);
        await leaveNote(steps.folder, {
            target: ready.version,
            at: steps.now(),
            connected: wasConnected,
            profile,
        });
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

/** How long the launcher waits for the setup program, in milliseconds. */
export const SETUP_LIMIT_MS = 10 * 60 * 1000;
/** How long it waits instead if the setup program cannot be waited for. */
export const SETUP_FALLBACK_MS = 2 * 60 * 1000;
/** How long it waits for the program file to be there, if it is not. */
export const APP_FILE_WAIT_MS = 2 * 60 * 1000;
/** How it tells the user if it cannot start the app. */
const TELL_USER =
    "[void](New-Object -ComObject WScript.Shell).Popup('UBC VPN could not be started after the update. Install it again from the releases page on GitHub.', 0, 'UBC VPN', 48)";
/** Said by the launcher once the setup program has been started. */
const STARTED_LINE = "started";

/**
 * The launcher, as a PowerShell script. It uses .NET directly, because
 * `Start-Process` loses the Windows error code and a cancelled prompt could not
 * be told apart from a failure. The paths come from the environment, never from
 * the script, so no character in them can change what runs. `options` exist so
 * that a test can run it with a stand-in and no elevation.
 *
 * - **Exit 2** is ERROR_CANCELLED (1223): the user said no at the prompt.
 * - **After "started"** it outlives the app, waits for the setup program, then
 *   waits for the app to have quit and starts it again, as the user, whatever
 *   the setup program's exit code says: some of electron-builder's failure paths
 *   `Quit` with no exit code set, so it cannot be trusted. The new app compares
 *   its version with the note to learn whether the update took. The setup program
 *   is not given `--force-run`, so this is the only start.
 * - **Whatever goes wrong after the prompt is approved, the app is started.** If
 *   the setup program cannot be waited for, the launcher waits a fixed time
 *   instead, so that a running setup has a chance to finish. If it is still
 *   running at the limit, the app is started all the same.
 * - **If there is no program to start,** because a failed install took it away,
 *   it waits a little in case the file is on its way, then shows a message: with
 *   no app, nothing else can say so.
 * - **It deletes its copy of the installer** only once the setup program has
 *   ended. Otherwise the copy may be in use, and a later start clears it.
 */
export function launcherScript(
    change: {
        verb?: string;
        setupArgs?: string;
        appArgs?: string;
        limitMs?: number;
        fallbackMs?: number;
        appWaitMs?: number;
        tell?: string;
    } = {},
): string {
    const options = {
        verb: "runas",
        setupArgs: "/S --updated",
        appArgs: "",
        limitMs: SETUP_LIMIT_MS,
        fallbackMs: SETUP_FALLBACK_MS,
        appWaitMs: APP_FILE_WAIT_MS,
        tell: TELL_USER,
        ...change,
    };
    return [
        "$start = [System.Diagnostics.ProcessStartInfo]::new()",
        "$start.FileName = $env:UBC_VPN_INSTALLER",
        `$start.Arguments = '${options.setupArgs}'`,
        `$start.Verb = '${options.verb}'`,
        "$start.UseShellExecute = $true",
        "$start.WindowStyle = 'Hidden'",
        "try { $setup = [System.Diagnostics.Process]::Start($start) } catch {",
        "  if ($_.Exception.InnerException.NativeErrorCode -eq 1223) { exit 2 }",
        "  exit 1",
        "}",
        // From here the prompt has been approved: nothing stops the app being started.
        `try { [Console]::Out.WriteLine('${STARTED_LINE}'); [Console]::Out.Flush() } catch {}`,
        "$ended = $false",
        "try {",
        "  if ($null -eq $setup) { throw 'no handle' }",
        `  $ended = $setup.WaitForExit(${options.limitMs})`,
        "} catch {",
        `  try { [System.Threading.Thread]::Sleep(${options.fallbackMs}) } catch {}`,
        "}",
        "try { [System.Diagnostics.Process]::GetProcessById([int]$env:UBC_VPN_APP_PID).WaitForExit(30000) | Out-Null } catch {}",
        // Setup may have moved the program and not yet copied the new one.
        `$deadline = [DateTime]::UtcNow.AddMilliseconds(${options.appWaitMs})`,
        "while (-not [System.IO.File]::Exists($env:UBC_VPN_APP) -and [DateTime]::UtcNow -lt $deadline) { [System.Threading.Thread]::Sleep(1000) }",
        "$running = $false",
        "try {",
        "  $app = [System.Diagnostics.ProcessStartInfo]::new()",
        "  $app.FileName = $env:UBC_VPN_APP",
        `  $app.Arguments = '${options.appArgs}'`,
        "  $app.UseShellExecute = $false",
        "  $running = $null -ne [System.Diagnostics.Process]::Start($app)",
        "} catch {}",
        // The one thing left that can tell the user: the app is not there to.
        `if (-not $running) { try { ${options.tell} } catch {} }`,
        "if ($ended) { try { [System.IO.Directory]::Delete([System.IO.Path]::GetDirectoryName($env:UBC_VPN_INSTALLER), $true) } catch {} }",
        "exit 0",
    ].join("\n");
}

/**
 * What the launcher, and through it the started app, is given of the app's
 * environment: what Windows programs need, and nothing of Electron's or the
 * app's own, which is not meant for a new start.
 */
const KEPT_ENVIRONMENT = [
    "ALLUSERSPROFILE",
    "APPDATA",
    "COMPUTERNAME",
    "ComSpec",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "PUBLIC",
    "SystemDrive",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "windir",
] as const;

export interface WindowsLauncher {
    systemRoot: string;
    /** The app to start again: the installed program. */
    app: string;
    /** This process, which the launcher waits for. */
    pid: number;
    env: NodeJS.ProcessEnv;
}

/**
 * The first stage, which is what is spawned. A process Node starts with
 * `detached` has no console, and PowerShell then exits at once and runs nothing.
 * One started without it is in a job that ends with the app, so it would not
 * outlive the app. But what that process itself starts is outside the job. So
 * this stage only starts the launcher, which inherits its standard output, and
 * passes on its exit code for as long as the app is there to read it.
 */
export function firstStage(script: string): string {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    return [
        "try {",
        "  $inner = [System.Diagnostics.ProcessStartInfo]::new()",
        "  $inner.FileName = [System.IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')",
        `  $inner.Arguments = '-NoProfile -NonInteractive -EncodedCommand ${encoded}'`,
        "  $inner.UseShellExecute = $false",
        "  $launcher = [System.Diagnostics.Process]::Start($inner)",
        "  $launcher.WaitForExit()",
        "  exit $launcher.ExitCode",
        "} catch { exit 1 }",
    ].join("\n");
}

/** The command that starts the launcher for the installer at `path`, and how. */
export function windowsLaunch(path: string, launcher: WindowsLauncher, script = launcherScript()) {
    const env: Record<string, string> = {};
    for (const name of KEPT_ENVIRONMENT) {
        const value = launcher.env[name];
        if (value !== undefined) {
            env[name] = value;
        }
    }
    return {
        file: join(launcher.systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        args: ["-NoProfile", "-NonInteractive", "-Command", firstStage(script)],
        options: {
            // Not the app's folder, which the setup program must be able to remove.
            cwd: join(launcher.systemRoot, "System32"),
            stdio: ["ignore", "pipe", "ignore"] as ["ignore", "pipe", "ignore"],
            windowsHide: true,
        },
        env: {
            ...env,
            SystemRoot: launcher.systemRoot,
            UBC_VPN_INSTALLER: path,
            UBC_VPN_APP: launcher.app,
            UBC_VPN_APP_PID: String(launcher.pid),
        },
    };
}

/** What an exit code of the launcher means, if it never said "started". */
export function launchedFrom(code: number | null): Launched {
    return code === 2 ? "cancelled" : "failed";
}

/** Starts the launcher on Windows. `start` is passed in by tests; none starts a real one. */
export function launchWindows(launcher: WindowsLauncher, start: typeof spawn = spawn): Launcher {
    return (path) =>
        new Promise((done) => {
            const { file, args, env, options } = windowsLaunch(path, launcher);
            const child = start(file, args, { ...options, env });
            child.on("error", () => done("failed"));
            child.on("close", (code) => done(launchedFrom(code)));
            let said = "";
            child.stdout?.on("data", (chunk) => {
                said = (said + String(chunk)).slice(-64);
                if (said.includes(STARTED_LINE)) {
                    child.stdout?.destroy();
                    child.unref();
                    done("started");
                }
            });
        });
}

/** How the setup program is started on this system. Only Windows can install yet. */
export function launcherFor(
    platform: NodeJS.Platform,
    launcher: WindowsLauncher,
    start: typeof spawn = spawn,
): Launcher {
    return platform === "win32" ? launchWindows(launcher, start) : async () => "failed";
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
 * The button's action: nothing in a copy that cannot update, which has no
 * folder. While a disconnect that ran late is being watched, one more press takes
 * over that connection and the watch ends, so nothing reconnects under the prompt.
 */
export function createInstall(
    updater: InstallingUpdater & { folder(): string | null },
    steps: (folder: string) => Omit<InstallSteps, "disconnectRanLate" | "carried">,
    watchDown: (then: () => void) => () => void,
): () => Promise<void> {
    let late: { profile: ProfileId | null; stop: () => void } | null = null;
    return async () => {
        const folder = updater.folder();
        if (folder === null) {
            return;
        }
        const given = steps(folder);
        const carried = late === null ? undefined : { profile: late.profile };
        late?.stop();
        late = null;
        await restartToUpdate(updater, {
            ...given,
            carried,
            disconnectRanLate: (profile) => {
                const stop = watchDown(() => {
                    late = null;
                    given.reconnect(profile);
                });
                late = { profile, stop };
            },
        });
    };
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
/** How long after that the app still watches for it to finish, to bring the connection back. */
export const LATE_DISCONNECT_LIMIT_MS = 5 * 60 * 1000;

/**
 * Asks the service to disconnect and waits until it says it has, or the limit
 * passes. A refusal is said at once, with no wait.
 */
export function disconnectAndWait(
    link: {
        disconnect(): Promise<ActionResult>;
        isDisconnected(): boolean;
        subscribe(listener: () => void): () => void;
    },
    limitMs = DISCONNECT_LIMIT_MS,
): Promise<Disconnected> {
    return new Promise((done) => {
        let finished = false;
        const finish = (result: Disconnected) => {
            if (!finished) {
                finished = true;
                clearTimeout(timer);
                stop();
                done(result);
            }
        };
        const timer = setTimeout(() => finish("late"), limitMs);
        const stop = link.subscribe(() => {
            if (link.isDisconnected()) {
                finish("down");
            }
        });
        void link
            .disconnect()
            .catch((): ActionResult => ({ ok: false, error: { kind: "service_unavailable" } }))
            .then((result) => {
                if (!result.ok) {
                    finish("refused");
                } else if (link.isDisconnected()) {
                    finish("down");
                }
            });
    });
}

/**
 * Calls `then` if the service says the connection is gone within the limit.
 * Returns what stops the watch.
 */
export function whenDown(
    link: { isDisconnected(): boolean; subscribe(listener: () => void): () => void },
    then: () => void,
    limitMs = LATE_DISCONNECT_LIMIT_MS,
): () => void {
    if (link.isDisconnected()) {
        then();
        return () => {};
    }
    const end = () => {
        clearTimeout(timer);
        stop();
    };
    const timer = setTimeout(end, limitMs);
    const stop = link.subscribe(() => {
        if (link.isDisconnected()) {
            end();
            then();
        }
    });
    return end;
}
