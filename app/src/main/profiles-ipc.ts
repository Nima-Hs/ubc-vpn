// What the Settings screen can ask the main process for. Each request is
// checked (`profiles-checks.ts`) before anything else happens. Only in builds
// that have the Settings screen: see `__SETTINGS__`.

import { PROFILES_IPC } from "@shared/profiles";
import type { BrowserWindow } from "electron";
import type { ProfilesService } from "./channel/profiles";
import { handleFromInterface } from "./ipc";
import { takeProfile, takeStartup } from "./profiles-checks";
import { type LoginItem, loginItemFor } from "./startup";

/** Where the choice of starting at sign-in goes: the OS, or a record of it. */
export interface LoginItems {
    apply(item: LoginItem): void;
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
