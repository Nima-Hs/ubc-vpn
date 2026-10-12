import { isAbsolute, join, resolve } from "node:path";

/**
 * Where the command-line client sits inside an installed app.
 *
 * PROVISIONAL. The installers do not exist yet; the packaging work settles
 * where the binary really goes, and this is the one place to change.
 */
const BUNDLED_CLI = ["bin", "ubc-vpn"] as const;

/** The variable a development build may use to point at a locally built client. */
export const CLI_OVERRIDE = "UBC_VPN_CLI";

/**
 * The program and arguments that start the bridge.
 *
 * The program is always an absolute path: the bundled client, never whatever
 * `ubc-vpn` a search of PATH would find. An installed app ignores the
 * override, because otherwise anything able to set the app's environment
 * could have it run, and trust, a different client.
 */
export function bridgeCommand(app: {
    isPackaged: boolean;
    resourcesPath: string;
    platform: NodeJS.Platform;
    env: Record<string, string | undefined>;
}): { command: string; args: readonly string[] } {
    const override = app.isPackaged ? undefined : app.env[CLI_OVERRIDE];
    const command =
        override !== undefined && override !== ""
            ? resolve(override)
            : join(
                  app.resourcesPath,
                  ...BUNDLED_CLI.slice(0, -1),
                  `${BUNDLED_CLI.at(-1)}${app.platform === "win32" ? ".exe" : ""}`,
              );
    if (!isAbsolute(command)) {
        throw new Error("the command-line client's path must be absolute");
    }
    return { command, args: ["bridge"] };
}
