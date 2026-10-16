// How UBC VPN starts when the user signs in, and whether it then connects.
// The choice is kept in the user's settings by the command-line client
// (`settings set-startup`); this file turns it into what the OS is asked to
// do, and decides at start whether the window is shown. No Electron import,
// so the rules can be tested on their own.

import { HIDDEN_ARG } from "@shared/profiles";
import type { ConnState } from "@shared/protocol/ConnState";
import type { GlobalSettings } from "@shared/protocol/GlobalSettings";
import type { StartMode } from "@shared/protocol/StartMode";

/** What the app asks the OS to do at sign-in (Electron's login item settings). */
export interface LoginItem {
    openAtLogin: boolean;
    /** Windows only: what the program is started with. */
    args: string[];
}

export { startupSupported } from "@shared/profiles";

/**
 * What to register for a choice. Windows starts the program with `--hidden`
 * to put it in the tray. macOS takes no arguments: there the app sees that
 * it was started at sign-in, and reads the choice from the settings.
 */
export function loginItemFor(start: StartMode, platform: NodeJS.Platform): LoginItem {
    if (start === "off") {
        return { openAtLogin: false, args: [] };
    }
    if (start === "window" || platform === "darwin") {
        return { openAtLogin: true, args: [] };
    }
    return { openAtLogin: true, args: [HIDDEN_ARG] };
}

/**
 * Whether the app starts with its window held back. Only an installed app
 * does: a test or development run keeps its own switches and ignores
 * `--hidden`. Started by hand with `--hidden`, an installed app does the
 * same as at sign-in, which is harmless: the tray and a second start both
 * bring the window back. Without a tray there would be no way back, so then
 * the window is always shown.
 *
 * On macOS a start at sign-in holds the window back until the settings say
 * whether it belongs in the tray; see `showsAfterSettings`.
 */
export function startsInTray(start: {
    packaged: boolean;
    argv: readonly string[];
    /** macOS: whether the OS started it at sign-in. */
    openedAtLogin: boolean;
    platform: NodeJS.Platform;
    trayCreated: boolean;
}): boolean {
    if (!start.packaged || !start.trayCreated) {
        return false;
    }
    return start.platform === "darwin" ? start.openedAtLogin : start.argv.includes(HIDDEN_ARG);
}

/**
 * Whether a window held back at start is shown once the settings are read
 * (`start` is the saved choice, or `null` if they could not be read). Only
 * macOS waits for them; anywhere else `--hidden` already said.
 */
export function showsAfterSettings(platform: NodeJS.Platform, start: StartMode | null): boolean {
    return platform === "darwin" && start !== "tray";
}

/**
 * Whether to connect now, as the app has just started. Only when the user
 * asked for it, and only from a settled "not connected": never on top of a
 * connection that is already up or under way.
 */
export function connectsAtStart(global: GlobalSettings, conn: ConnState | null): boolean {
    return global.auto_connect && conn?.state === "disconnected";
}
