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
            // Not something this screen sends yet; said plainly if it happens.
            return "The change was not made. Try again.";
    }
}
