// What keeps the launcher's tests off the desktop they run on. A test that runs
// the launcher script runs real PowerShell, so a script holding the production
// message would show a real dialog, and one holding the elevated start a real
// administrator prompt. That has happened: a mutant showed the message on a
// developer's screen. In CI, nobody would see it, and it would block the launcher.
//
// Every script a test runs goes through `testScript` or `checkedScript`. A script
// that could reach the desktop fails its test here, before anything is started. The
// real message cannot get here by default either: `launcherScript` has no default
// for it, and only `productionScript` passes it.
//
// This sees only the script. It cannot see the options a script is started with, so
// a change to `windowsLaunch`'s options, such as removing `windowsHide`, can still
// put a console on the screen. Mutants of that function, of `launcherScript`, of
// `firstStage` and of this file are for CI only.

import { launcherScript } from "../src/main/update/install";

/** Does nothing, in place of the production message. */
export const NO_MESSAGE = "$null";
/** The call that starts setup. With `runas` still in the script, it would elevate. */
export const SETUP_START = "[System.Diagnostics.Process]::Start($start)";

const SHOWS_SOMETHING =
    /WScript|Popup|MessageBox|MsgBox|mshta|msg\.exe|ShowDialog|System\.Windows\.Forms|Read-Host|Out-GridView/i;

/**
 * Returns `script` if it is safe to run, and otherwise throws: it must show no
 * dialog, and must not be able to elevate.
 */
export function checkedScript(script: string): string {
    const shows = SHOWS_SOMETHING.exec(script);
    if (shows !== null) {
        throw new Error(`a test may not run a script that can show a dialog: ${shows[0]}`);
    }
    if (/no-such-word/i.test(script)) {
        throw new Error("a test may not run a script that can ask for administrator rights");
    }
    return script;
}

/** The launcher script for a test: no message, and checked. */
export function testScript(change: Partial<Parameters<typeof launcherScript>[0]> = {}): string {
    return checkedScript(launcherScript({ tell: NO_MESSAGE, ...change }));
}

/**
 * A script whose start of setup is replaced, for what it does when that start
 * fails. It has no verb to elevate with, and must have that start to replace.
 */
export function withoutElevating(replacement: string): string {
    const script = launcherScript({ tell: NO_MESSAGE, verb: "" });
    if (!script.includes(SETUP_START)) {
        throw new Error("the launcher no longer starts setup the way this replaces");
    }
    return checkedScript(script.replace(SETUP_START, replacement));
}
