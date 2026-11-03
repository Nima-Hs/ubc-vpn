// What "Restart to update" does with its files when they misbehave, with the
// file functions watched. Only a fresh temporary folder is touched.

import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type InstallSteps, installUpdate, stageInstaller } from "../src/main/update/install";
import type { ReadyInstaller } from "../src/main/update/updater";
import { sha256 } from "./update-harness";

const watched = vi.hoisted(() => ({
    closed: 0,
    opened: 0,
    failRemoving: false,
}));

vi.mock("node:fs/promises", async (actual) => {
    const real = await actual<typeof import("node:fs/promises")>();
    return {
        ...real,
        open: async (...args: Parameters<typeof real.open>) => {
            const file = await real.open(...args);
            watched.opened += 1;
            const close = file.close.bind(file);
            file.close = async () => {
                watched.closed += 1;
                return close();
            };
            return file;
        },
        rm: async (...args: Parameters<typeof real.rm>) => {
            if (watched.failRemoving) {
                throw new Error("in use");
            }
            return real.rm(...args);
        },
    };
});

const installer = Buffer.from("a stand-in for the setup program, never run");
let folder: string;
let ready: ReadyInstaller;

beforeEach(async () => {
    watched.closed = 0;
    watched.opened = 0;
    watched.failRemoving = false;
    folder = join(await mkdtemp(join(tmpdir(), "upd-files-")), "updates");
    await mkdir(folder);
    const name = "ubc-vpn-setup-0.2.0-x64.exe";
    const path = join(folder, name);
    await writeFile(path, installer);
    ready = {
        version: "0.2.0",
        path,
        entry: { platform: "windows-x64", name, size: installer.length, sha256: sha256(installer) },
    };
});
afterEach(async () => {
    watched.failRemoving = false;
    const { rm } = await import("node:fs/promises");
    await rm(dirname(folder), { recursive: true, force: true });
});

describe("the copy of the installer", () => {
    it("is closed before it is run", async () => {
        await stageInstaller(ready.path, ready.entry, folder);
        expect(watched.opened).toBeGreaterThan(0);
        expect(watched.closed).toBe(watched.opened);
    });

    it("the connection still comes back when removing it fails", async () => {
        watched.failRemoving = true;
        const done: string[] = [];
        const steps: InstallSteps = {
            folder,
            connected: () => true,
            connectedProfile: () => null,
            disconnect: async () => "down",
            disconnectRanLate: () => {},
            launch: async () => "cancelled",
            reconnect: () => done.push("reconnect"),
            quit: () => done.push("quit"),
            now: () => 1,
        };
        await expect(installUpdate(ready, steps)).resolves.toBe("cancelled");
        expect(done).toEqual(["reconnect"]);
    });
});
