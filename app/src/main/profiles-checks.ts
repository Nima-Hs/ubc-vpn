// The checks on what the Settings screen sends, before anything else
// happens. No Electron import, so they can be tested on their own.

import { START_MODES, startupSupported } from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { StartMode } from "@shared/protocol/StartMode";
import { isProfileId } from "./channel/validate";

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
