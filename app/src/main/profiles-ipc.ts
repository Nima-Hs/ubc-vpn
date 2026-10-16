// What the Settings screen can ask the main process for, and the checks on
// each request before anything else happens. Only in builds that have the
// Settings screen: see `__SETTINGS__`.

import { PROFILES_IPC, START_MODES } from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { StartMode } from "@shared/protocol/StartMode";
import type { BrowserWindow } from "electron";
import type { ProfilesService } from "./channel/profiles";
import { isProfileId } from "./channel/validate";
import { handleFromInterface } from "./ipc";
import { type LoginItem, loginItemFor, startupSupported } from "./startup";

/** Where the choice of starting at sign-in goes: the OS, or a record of it. */
export interface LoginItems {
    apply(item: LoginItem): void;
}

/** The arguments of a startup change, or a refusal. */
export function takeStartup(
    args: readonly unknown[],
    platform: NodeJS.Platform,
): [StartMode, boolean] {
    const [start, autoConnect] = args;
    if (
        args.length !== 2 ||
        typeof start !== "string" ||
        !START_MODES.includes(start as StartMode) ||
        typeof autoConnect !== "boolean" ||
        // Where the OS cannot start the app, it is not offered.
        (start !== "off" && !startupSupported(platform))
    ) {
        throw new Error("refused");
    }
    return [start as StartMode, autoConnect];
}

/** The profile a request names: an id, or `null` for the active one. */
export function takeProfile(args: readonly unknown[]): ProfileId | null {
    const [id] = args;
    if (args.length !== 1 || (id !== null && !isProfileId(id))) {
        throw new Error("refused");
    }
    return id;
}

export function registerProfiles(
    window: BrowserWindow,
    devServerUrl: string | undefined,
    profiles: ProfilesService,
    loginItems: LoginItems,
    platform: NodeJS.Platform,
): void {
    handleFromInterface(window, devServerUrl, PROFILES_IPC.list, () => profiles.list());
    handleFromInterface(window, devServerUrl, PROFILES_IPC.setStartup, async (...args) => {
        const [start, autoConnect] = takeStartup(args, platform);
        const result = await profiles.setStartup(start, autoConnect);
        // Registered with the OS only once it is saved, and as it was saved.
        if (result.ok) {
            loginItems.apply(loginItemFor(result.value.global.start, platform));
        }
        return result;
    });
    handleFromInterface(window, devServerUrl, PROFILES_IPC.forgetPassword, (...args) =>
        profiles.forgetPassword(takeProfile(args)),
    );
}
