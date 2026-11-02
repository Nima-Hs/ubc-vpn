import { isAbsolute, join, resolve } from "node:path";

/** The variable a development build or a test may use to say where its profile goes. */
export const PROFILE_OVERRIDE = "UBC_VPN_PROFILE";

/**
 * The folder the installed command-line client keeps the user's
 * `settings.json` in, inside the per-user settings folder of each OS. Kept
 * the same as the platform crate's table (`crates/platform`).
 */
const SETTINGS_FOLDER: Partial<Record<NodeJS.Platform, string>> = {
    win32: "UBC VPN",
    darwin: "UBC VPN",
};
const SETTINGS_FOLDER_ELSEWHERE = "ubc-vpn";

/**
 * Where the app keeps its own profile: Chromium's caches, preferences and
 * the like. Never Electron's own choice, which is named after the product
 * and on Windows and macOS is the very folder that holds the user's
 * `settings.json`. That file is the client's: the app never creates, reads
 * or writes it, and keeps its own files out of its way.
 *
 * - An installed app uses a sub-folder named `app` of the client's settings
 *   folder, on every OS.
 * - An app that is not installed never writes into the installed product's
 *   folders at all. It uses the folder the variable names, or one beside
 *   the real one whose name no other part of the product uses.
 *
 * An installed app ignores the variable, like the others.
 */
export function profileFolder(
    app: {
        readonly isPackaged: boolean;
        getPath(name: "appData" | "home"): string;
    },
    process: {
        readonly platform: NodeJS.Platform;
        readonly env: Record<string, string | undefined>;
    },
): string {
    const settings = SETTINGS_FOLDER[process.platform] ?? SETTINGS_FOLDER_ELSEWHERE;
    if (app.isPackaged) {
        return join(settingsParent(app, process), settings, "app");
    }
    const chosen = process.env[PROFILE_OVERRIDE];
    return chosen !== undefined && chosen !== ""
        ? resolve(chosen)
        : join(app.getPath("appData"), "UBC VPN App Dev");
}

/**
 * The folder the client's settings folder is in. On Windows and macOS that
 * is where Electron says. On Linux the client follows the XDG rule exactly:
 * `XDG_CONFIG_HOME` if it is an absolute path, and `~/.config` otherwise.
 * Electron may take a relative value as given, so the rule is applied here,
 * and the two cannot end up in different places.
 */
function settingsParent(
    app: { getPath(name: "appData" | "home"): string },
    process: {
        readonly platform: NodeJS.Platform;
        readonly env: Record<string, string | undefined>;
    },
): string {
    if (process.platform === "win32" || process.platform === "darwin") {
        return app.getPath("appData");
    }
    const config = process.env.XDG_CONFIG_HOME;
    return config !== undefined && isAbsolute(config)
        ? config
        : join(app.getPath("home"), ".config");
}
