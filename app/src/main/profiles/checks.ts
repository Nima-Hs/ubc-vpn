// The checks on what the Settings screen sends, before anything else
// happens. No Electron import, so they can be tested on their own.

import { START_MODES, startupSupported } from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { StartMode } from "@shared/protocol/StartMode";
import { isProfileId } from "../channel/validate";

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

/**
 * The longest name or username the screen may send. The client's own rules
 * are stricter (a name is 1 to 64 characters); this only keeps a request
 * from being huge before the client says so.
 */
export const MAX_SENT_TEXT = 256;

const isText = (value: unknown): value is string =>
    typeof value === "string" && value.length <= MAX_SENT_TEXT;

/** A name for a new profile, or a refusal. */
export function takeName(args: readonly unknown[]): string {
    const [name] = args;
    if (args.length !== 1 || !isText(name)) {
        throw new Error("refused");
    }
    return name;
}

/** A profile and a new name for it, or a refusal. */
export function takeRename(args: readonly unknown[]): [ProfileId, string] {
    const [id, name] = args;
    if (args.length !== 2 || !isProfileId(id) || !isText(name)) {
        throw new Error("refused");
    }
    return [id, name];
}

/** A profile and what to change in it, or a refusal. */
export function takeUpdate(
    args: readonly unknown[],
): [ProfileId, { username?: string | null; save_password?: boolean }] {
    const [id, change] = args;
    if (
        args.length !== 2 ||
        !isProfileId(id) ||
        typeof change !== "object" ||
        change === null ||
        Array.isArray(change)
    ) {
        throw new Error("refused");
    }
    const fields = Object.keys(change);
    const { username, save_password: savePassword } = change as Record<string, unknown>;
    if (
        fields.length === 0 ||
        fields.some((field) => field !== "username" && field !== "save_password") ||
        (fields.includes("username") && username !== null && !isText(username)) ||
        (fields.includes("save_password") && typeof savePassword !== "boolean")
    ) {
        throw new Error("refused");
    }
    return [
        id,
        {
            ...(fields.includes("username") && { username: username as string | null }),
            ...(fields.includes("save_password") && { save_password: savePassword as boolean }),
        },
    ];
}

/** A profile named by its id, never the active one by `null`. */
export function takeId(args: readonly unknown[]): ProfileId {
    const [id] = args;
    if (args.length !== 1 || !isProfileId(id)) {
        throw new Error("refused");
    }
    return id;
}

/** The profile a request names: an id, or `null` for the active one. */
export function takeProfile(args: readonly unknown[]): ProfileId | null {
    const [id] = args;
    if (args.length !== 1 || (id !== null && !isProfileId(id))) {
        throw new Error("refused");
    }
    return id;
}
