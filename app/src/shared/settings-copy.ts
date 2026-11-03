// Every word the Settings screen shows. Kept apart from `copy.ts` because only
// builds with the Settings screen carry it: see `__SETTINGS__`.
//
// The rules are `copy.ts`'s: sentence case, plain words, no exclamation
// marks; a problem says what happened, then what to do next.

import type { ProfilesError } from "./profiles";
import type { StartMode } from "./protocol/StartMode";
import type { AfterUpdateNotice, InstallNotice, UpdateStatus } from "./updates";

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

export const UPDATES = {
    heading: "Updates",
    automatic: {
        label: "Automatic updates",
        hint: "On unless you turn it off. New versions download in the background and install when you restart UBC VPN to update. When off, UBC VPN only tells you a new version is out.",
    },
    checkNow: "Check for updates now",
    lastChecked: (when: string) => `Last checked ${when}.`,
    neverChecked: "Not checked yet.",
    restart: "Restart to update",
    restartHint:
        "UBC VPN disconnects, installs the update, starts again, and reconnects the profile that was connected.",
} as const;

/** Where updates stand, in a sentence; `null` when there is nothing to say yet. */
export function describeUpdate(status: UpdateStatus): string | null {
    switch (status.phase) {
        case "unavailable":
            return "This copy of UBC VPN can't update itself. Install new versions from the releases page on GitHub.";
        case "idle":
            return null;
        case "checking":
            return "Checking for updates…";
        case "up_to_date":
            return "UBC VPN is up to date.";
        case "available":
            return `Version ${status.version} is available. Turn on Automatic updates to download it.`;
        case "downloading":
            return `Downloading version ${status.version}…`;
        case "ready":
            return `Version ${status.version} is downloaded and ready to install.`;
        case "installing":
            return `Installing version ${status.version}. Approve the administrator prompt to go on. It names an unknown publisher because UBC VPN's installer is not signed.`;
        case "failed":
            switch (status.reason) {
                case "offline":
                    return "UBC VPN couldn't reach GitHub to check for updates. Check your internet connection, then try again.";
                case "github":
                    return "GitHub's answer couldn't be read, so nothing was downloaded. Try again later.";
                case "refused":
                    return "An update failed UBC VPN's safety checks, so it wasn't used and nothing was installed. Try again later.";
                case "disk":
                    return "The update couldn't be saved. Check that your disk isn't full, then try again.";
            }
    }
}

/** Why the last "Restart to update" installed nothing. */
export function describeInstallNotice(notice: InstallNotice): string {
    switch (notice) {
        case "cancelled":
            return "The update wasn't installed because the administrator prompt was cancelled. Nothing was changed, and UBC VPN reconnects the profile that was connected.";
        case "failed":
            return "The update couldn't be started, and nothing was changed. Try again, or install it from the releases page on GitHub.";
        case "changed":
            return "The downloaded update changed on disk, so it wasn't installed. UBC VPN downloads it again at the next check.";
        case "not_disconnected":
            return "UBC VPN couldn't disconnect first, so the update wasn't installed. Try again.";
    }
}

/** What the app has to say after an update it started. */
export function describeAfterUpdate(notice: AfterUpdateNotice): string {
    switch (notice) {
        case "unfinished":
            return "The update didn't finish, so UBC VPN is still on the version it had.";
        case "stale":
            return "UBC VPN found a note from an update over a day old. It didn't reconnect, and nothing else happened.";
        case "profile_gone":
            return "The profile you were connected with no longer exists, so UBC VPN didn't reconnect.";
        case "reconnect_unknown":
            return "UBC VPN doesn't know which profile you were connected with, so it didn't reconnect. Choose a profile and connect.";
        case "reconnect_unavailable":
            return "UBC VPN couldn't reach what it needs to reconnect, so it didn't. Connect when you're ready.";
        case "reconnect_busy":
            return "UBC VPN couldn't reconnect because a login was still ending. Connect again in a moment.";
    }
}

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
        "Your CWL username and department, for example name.dept, without the @ part. Changing it forgets the saved password.",
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
            return "Use your CWL username and department, for example name.dept, with no spaces.";
        case "username_has_method":
            return "Leave the @ part out of the username. The Duo method adds it.";
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
        case "username_has_method":
        case "keyring_not_cleared":
            // Said by `describeProfileRefusal` where it can happen; plainly here.
            return "The change was not made. Try again.";
    }
}
