// Every word the Settings screen shows. Kept apart from `copy.ts` because only
// builds with the Settings screen carry it: see `__SETTINGS__`.
//
// The rules are `copy.ts`'s: sentence case, plain words, no exclamation
// marks; a problem says what happened, then what to do next.

import type { ProfilesError } from "./profiles";
import type { StartMode } from "./protocol/StartMode";

export const SETTINGS = {
    title: "Settings",
    body: "Changes are saved as you make them.",
    loading: "Reading your settings…",
    tryAgain: "Try again",

    startup: {
        heading: "Start UBC VPN when you sign in",
        options: {
            off: { label: "Don't start it", hint: "Open UBC VPN yourself when you need it." },
            window: { label: "Start it and open the window", hint: undefined },
            tray: {
                label: "Start it in the tray",
                hint: "The window stays closed. Open it from the UBC VPN icon in the tray.",
            },
        } satisfies Record<StartMode, { label: string; hint: string | undefined }>,
        notHere: "Starting at sign-in is not available on Linux yet.",
    },

    autoConnect: {
        label: "Connect when UBC VPN starts",
        withPassword:
            "Off unless you turn it on. With your saved password, each start sends one MFA request for you to approve.",
        withoutPassword:
            "Off unless you turn it on. Each start opens the window and asks for your password, then sends one MFA request.",
    },

    password: {
        heading: "Saved password",
        saved: (where: string) =>
            `Your password is saved in ${where}, so Connect asks only for MFA.`,
        notSaved: "No password is saved. You type it each time you connect.",
        noKeyring:
            "This computer has no keyring UBC VPN can use, so your password is asked for each time.",
        forget: "Forget saved password",
        ask: "Forget your saved password? You'll type it the next time you connect.",
        yes: "Forget password",
        no: "Keep it",
        forgotten: "Your saved password is forgotten.",
    },
} as const;

export const PROFILES = {
    heading: "Profiles",
    body: "Each profile has its own username, routes and saved password. Connect uses the one in use.",
    inUse: "In use",
    noUsername: "No username yet",
    use: (name: string) => `Use ${name}`,
    edit: (name: string) => `Edit ${name}`,
    done: "Done",
    name: "Name",
    rename: "Rename",
    username: "CWL username",
    usernameHint:
        "As you type it at UBC's login, for example name@app. Changing it forgets the saved password.",
    saveUsername: "Save username",
    savePassword: "Save password",
    savePasswordHint: (where: string) =>
        `Kept in ${where} after a login that works, so Connect asks only for MFA.`,
    delete: "Delete profile",
    deleteAsk: (name: string) =>
        `Delete “${name}”? Its username, routes and saved password are deleted too.`,
    deleteYes: "Delete profile",
    deleteNo: "Keep it",
    lastOne: "The only profile can't be deleted.",
    add: "Add profile",
    newName: "New profile's name",
    newNameHint: "Up to 64 characters, different from your other profiles.",
    routesNote: "Routes are on the Routes screen, for the profile in use.",
    switcher: "Profile",
    nextConnect: "Takes effect the next time you connect.",
} as const;

/** "Save password" beside the password question. */
export const LOGIN_SAVE = {
    label: "Save password",
    hint: (where: string) =>
        `Saved in ${where} once this login works. Next time, Connect asks only for MFA.`,
} as const;

/** Why a change to a profile was refused, said beside what was changed. */
export function describeProfileRefusal(
    error: ProfilesError,
    /** Whether the keyring can be used at all, for saying why saving stays off. */
    keyring: "available" | "unavailable" = "available",
): string {
    switch (error) {
        case "keyring_not_cleared":
            // Turning saving back on is refused while an old saved password
            // that was set aside could not be removed.
            return keyring === "unavailable"
                ? "The keyring can't be used, so saving stays off."
                : "UBC VPN couldn't remove the old saved password, so saving stays off.";
        case "bad_name":
            return "Use a name of 1 to 64 characters, without line breaks or hidden characters.";
        case "name_taken":
            return "Another profile has that name. Choose a different one.";
        case "too_many_profiles":
            return "You have 32 profiles, the most there can be. Delete one to add another.";
        case "last_profile":
            return PROFILES.lastOne;
        case "bad_username":
            return "Use your CWL username as you type it at UBC's login, with no spaces.";
        default:
            return describeProfilesError(error, "change");
    }
}

/** Where the OS keeps a saved password, as the user knows it. */
export function whereKept(platform: string): string {
    switch (platform) {
        case "win32":
            return "Windows Credential Manager";
        case "darwin":
            return "your macOS Keychain";
        default:
            return "your keyring";
    }
}

/** Why the settings could not be read, or a change was not made. Nothing was changed. */
export function describeProfilesError(error: ProfilesError, doing: "read" | "change"): string {
    switch (error) {
        case "unreadable":
            return "Your settings file is damaged, so it has been left as it is. If you edited it by hand, undo the change.";
        case "unwritable":
            return "Your settings could not be saved, and the old ones are unchanged. Check that your disk is not full, then try again.";
        case "busy":
            return "A change is already being saved. Wait for it to finish.";
        case "unavailable":
            return doing === "read"
                ? "UBC VPN could not read your settings. Try again. If it keeps happening, install UBC VPN again."
                : "UBC VPN could not save the change, and nothing was changed. Try again.";
        case "unknown_profile":
            return "That profile no longer exists. The list has been read again.";
        case "superseded":
        case "bad_input":
        case "bad_name":
        case "name_taken":
        case "too_many_profiles":
        case "last_profile":
        case "bad_username":
        case "id_taken":
        case "keyring_not_cleared":
            // Said by `describeProfileRefusal` where it can happen; plainly here.
            return "The change was not made. Try again.";
    }
}
