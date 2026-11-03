// What the Settings screen can ask about updates, and the updater the
// installed app runs. Each request is checked before anything happens.

import { homedir } from "node:os";
import { UPDATES_IPC } from "@shared/updates";
import type { BrowserWindow } from "electron";
import { handleFromInterface } from "../ipc";
import { updatesFolder } from "./download";
import { TRUSTED_KEYS } from "./keys";
import { Updater, updatePlatform } from "./updater";

/**
 * Whether this run may update itself: an installed app, from a release
 * build, not the demo. `packaged` alone is not enough, as an environment
 * variable can make any run claim it.
 */
export function mayUpdate(run: { packaged: boolean; release: boolean; demo: boolean }): boolean {
    return run.packaged && run.release && !run.demo;
}

/** The updater for this run. Only an installed app ever reaches the network. */
export function createUpdater(version: string, packaged: boolean): Updater {
    return new Updater({
        fetch: (url, init) => fetch(url, init),
        version,
        platform: updatePlatform(process.platform, process.arch),
        // Worked out only for an installed app: no other run touches the folder.
        folder: packaged ? updatesFolder(process.platform, process.env, homedir()) : null,
        keys: TRUSTED_KEYS,
        packaged,
        now: () => Date.now(),
        schedule: (run, firstMs, thenMs) => {
            let repeat: NodeJS.Timeout | undefined;
            const first = setTimeout(() => {
                run();
                repeat = setInterval(run, thenMs);
            }, firstMs);
            return () => {
                clearTimeout(first);
                clearInterval(repeat);
            };
        },
    });
}

/** Takes no arguments: anything sent with the request is refused. */
export function takeNothing(args: readonly unknown[]): void {
    if (args.length !== 0) {
        throw new Error("refused");
    }
}

export function registerUpdates(
    window: BrowserWindow,
    devServerUrl: string | undefined,
    updater: Updater,
): void {
    handleFromInterface(window, devServerUrl, UPDATES_IPC.get, (...args) => {
        takeNothing(args);
        return updater.view();
    });
    handleFromInterface(window, devServerUrl, UPDATES_IPC.checkNow, (...args) => {
        takeNothing(args);
        void updater.check();
    });
    updater.subscribe((view) => {
        if (!window.isDestroyed()) {
            window.webContents.send(UPDATES_IPC.changed, view);
        }
    });
}
