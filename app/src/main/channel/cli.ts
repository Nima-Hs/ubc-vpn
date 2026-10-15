import { isAbsolute, join, resolve } from "node:path";

/**
 * Where the command-line client sits inside an installed app.
 *
 * The Windows setup program puts it in resources\bin, beside the service and
 * the libraries both load (app/electron-builder.yml).
 */
const BUNDLED_CLI = ["bin", "ubc-vpn"] as const;

/** The variable a development build may use to point at a locally built client. */
export const CLI_OVERRIDE = "UBC_VPN_CLI";

/**
 * The variable that has a development build talk to a dev-mode service: one
 * run as an ordinary user, with pretend routing and a pretend gateway, whose
 * files and channel are never the installed product's. It is on only when
 * set to exactly `1`.
 */
export const DEV_SWITCH = "UBC_VPN_DEV";

/** What the client is told, before anything else, to use dev mode. */
export const DEV_FLAG = "--dev";

/**
 * The program and arguments that start the bridge, and whether this run is
 * in dev mode. Every start of the client is decided here and nowhere else.
 *
 * The program is always an absolute path: the bundled client, never whatever
 * `ubc-vpn` a search of PATH would find. An installed app ignores both
 * variables, because otherwise anything able to set the app's environment
 * could have it run, and trust, a different client, or turn it away from
 * the real service to a pretend one.
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
): { command: string; args: readonly string[]; dev: boolean } {
    const override = app.isPackaged ? undefined : process.env[CLI_OVERRIDE];
    const dev = !app.isPackaged && process.env[DEV_SWITCH] === "1";
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
    return { command, args: [...(dev ? [DEV_FLAG] : []), "bridge"], dev };
}

/**
 * The program that reads and writes the user's settings: the same client,
 * found the same way. Its arguments are fixed, in `settings.ts`; nothing the
 * user typed is ever among them.
 */
export function settingsCommand(...where: Parameters<typeof bridgeCommand>): {
    command: string;
    leadingArgs: readonly string[];
    dev: boolean;
} {
    const { command, dev } = bridgeCommand(...where);
    return { command, leadingArgs: dev ? [DEV_FLAG] : [], dev };
}

/**
 * The program and arguments that log in and connect. The same client as the
 * bridge, found the same way. The app passes it no routes and no address:
 * the client reads the user's settings and the service's policy itself.
 */
export function connectCommand(...where: Parameters<typeof bridgeCommand>): {
    command: string;
    args: readonly string[];
    dev: boolean;
} {
    const { command, dev } = bridgeCommand(...where);
    return { command, args: [...(dev ? [DEV_FLAG] : []), "connect", "--json"], dev };
}
