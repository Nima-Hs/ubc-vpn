// What the Settings screen can ask the main process for. Each request is
// checked (`checks.ts`) before anything else happens. Only in builds
// that have the Settings screen: see `__SETTINGS__`.

import { PROFILES_IPC, type ProfilesResult } from "@shared/profiles";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { BrowserWindow } from "electron";
import type { ProfilesService } from "../channel/profiles";
import { handleFromInterface } from "../ipc";
import { type LoginItem, loginItemFor } from "../startup";
import { takeId, takeName, takeProfile, takeRename, takeStartup, takeUpdate } from "./checks";

/** Where the choice of starting at sign-in goes: the OS, or a record of it. */
export interface LoginItems {
    apply(item: LoginItem): void;
}

/**
 * The profiles service, telling `onView` every view it answers with, so
 * the window and the tray menu always show the profiles as they are, after
 * a change made in either.
 */
export function watchProfiles(
    profiles: ProfilesService,
    onView: (view: ProfilesView) => void,
): ProfilesService {
    const tell = async (result: Promise<ProfilesResult>): Promise<ProfilesResult> => {
        const answer = await result;
        if (answer.ok) {
            onView(answer.value);
        }
        return answer;
    };
    return {
        list: () => tell(profiles.list()),
        setStartup: (start, autoConnect) => tell(profiles.setStartup(start, autoConnect)),
        forgetPassword: (id) => tell(profiles.forgetPassword(id)),
        create: (name) => tell(profiles.create(name)),
        rename: (id, name) => tell(profiles.rename(id, name)),
        update: (id, change) => tell(profiles.update(id, change)),
        remove: (id) => tell(profiles.remove(id)),
        switchTo: (id) => tell(profiles.switchTo(id)),
        // Its answer is not a view; whoever asked reads the profiles again.
        setTunnel: (mode) => profiles.setTunnel(mode),
        stop: () => profiles.stop(),
    };
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
    handleFromInterface(window, devServerUrl, PROFILES_IPC.create, (...args) =>
        profiles.create(takeName(args)),
    );
    handleFromInterface(window, devServerUrl, PROFILES_IPC.rename, (...args) =>
        profiles.rename(...takeRename(args)),
    );
    handleFromInterface(window, devServerUrl, PROFILES_IPC.update, (...args) =>
        profiles.update(...takeUpdate(args)),
    );
    handleFromInterface(window, devServerUrl, PROFILES_IPC.remove, (...args) =>
        profiles.remove(takeId(args)),
    );
    handleFromInterface(window, devServerUrl, PROFILES_IPC.switchTo, (...args) =>
        profiles.switchTo(takeId(args)),
    );
}
