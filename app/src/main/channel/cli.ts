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
export function bridgeCommand(
    // Electron's own `app` and Node's own `process`, passed whole, so the
    // caller has nothing to fill in and so nothing to get wrong.
    app: { readonly isPackaged: boolean },
    process: {
        readonly resourcesPath: string;
        readonly platform: NodeJS.Platform;
        readonly env: Record<string, string | undefined>;
    },
): { command: string; args: readonly string[] } {
    const override = app.isPackaged ? undefined : process.env[CLI_OVERRIDE];
    const command =
        override !== undefined && override !== ""
            ? resolve(override)
            : join(
                  process.resourcesPath,
                  ...BUNDLED_CLI.slice(0, -1),
                  `${BUNDLED_CLI.at(-1)}${process.platform === "win32" ? ".exe" : ""}`,
              );
    if (!isAbsolute(command)) {
        throw new Error("the command-line client's path must be absolute");
    }
    return { command, args: ["bridge"] };
}

/**
 * The program and arguments that log in and connect. The same client as the
 * bridge, found the same way. The app passes it no routes and no address:
 * the client reads the user's settings and the service's policy itself.
 */
export function connectCommand(...where: Parameters<typeof bridgeCommand>): {
    command: string;
    args: readonly string[];
} {
    return { command: bridgeCommand(...where).command, args: ["connect", "--json"] };
}
