// What the interface and the main process share about the user's profiles
// and the settings every profile shares: how UBC VPN starts, whether it
// connects by itself, and the saved password. Only builds with the Settings
// screen have any of it: see `__SETTINGS__` in `electron.vite.config.ts`.
//
// The main process gets all of it from the command-line client (`profiles`,
// `settings set-startup` and `password forget`, `crates/cli/src/profiles.rs`);
// the lines are the types in `protocol/`. A saved password never crosses:
// only whether one is saved.

import type { SettingsError } from "./api";
import type { ProfileFailureCode } from "./protocol/ProfileFailureCode";
import type { ProfileId } from "./protocol/ProfileId";
import type { ProfilesView } from "./protocol/ProfilesView";
import type { StartMode } from "./protocol/StartMode";

/** Why a change to the profiles or the shared settings was not made. Nothing was changed. */
export type ProfilesError = SettingsError | ProfileFailureCode;

export type ProfilesResult =
    | { ok: true; value: ProfilesView }
    | { ok: false; error: ProfilesError };

/** What the Settings screen can ask for. */
export interface ProfilesApi {
    list(): Promise<ProfilesResult>;
    /** How UBC VPN starts when the user signs in, and whether it then connects. */
    setStartup(start: StartMode, autoConnect: boolean): Promise<ProfilesResult>;
    /** Forgets a profile's saved password; the active profile's when `id` is `null`. */
    forgetPassword(id: ProfileId | null): Promise<ProfilesResult>;
}

export const PROFILES_IPC = {
    list: "profiles:list",
    setStartup: "profiles:set-startup",
    forgetPassword: "profiles:forget-password",
} as const;

export const START_MODES: readonly StartMode[] = ["off", "window", "tray"];

/**
 * Whether this OS can start the app at sign-in through Electron. Linux has
 * no such call: its desktops read autostart files, which are not written yet.
 */
export function startupSupported(platform: string): boolean {
    return platform === "win32" || platform === "darwin";
}

/**
 * The argument a login-item start passes, so that the app starts in the tray.
 * Honoured only by an installed app: see `startsInTray` in `src/main/startup.ts`.
 */
export const HIDDEN_ARG = "--hidden";

/** Demo builds only: what the app would have asked the OS to start at sign-in. */
export interface LoginItemRecord {
    openAtLogin: boolean;
    args: string[];
}

export const DEMO_PROFILES_IPC = {
    loginItem: "demo:login-item",
} as const;
