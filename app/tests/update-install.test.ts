// "Restart to update" with every step it takes passed in: no installer is
// ever started, no administrator prompt shown, and nothing outside a fresh
// temporary folder is touched.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { InstallNotice } from "@shared/updates";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
    disconnectAndWait,
    type InstallSteps,
    installUpdate,
    type Launched,
    launchedFrom,
    leaveResume,
    restartToUpdate,
    takeResume,
    windowsLaunch,
} from "../src/main/update/install";
import type { ReadyInstaller } from "../src/main/update/updater";
import { sha256 } from "./update-harness";

const installer = Buffer.from("a stand-in for the setup program, never run");
let folder: string;
let ready: ReadyInstaller;

beforeEach(async () => {
    folder = join(await mkdtemp(join(tmpdir(), "upd-install-")), "updates");
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
    await rm(dirname(folder), { recursive: true, force: true });
});

/** The steps, recording what was done; `launched` is what starting the setup program comes to. */
function steps(options: { connected?: boolean; disconnects?: boolean; launched?: Launched } = {}) {
    const done: string[] = [];
    const seen: { launchedPath?: string; launchedBytes?: Buffer; resumeAtLaunch?: boolean } = {};
    const given: InstallSteps = {
        folder,
        connected: () => options.connected ?? false,
        disconnect: async () => {
            done.push("disconnect");
            return options.disconnects ?? true;
        },
        launch: async (path) => {
            done.push("launch");
            seen.launchedPath = path;
            seen.launchedBytes = readFileSync(path);
            seen.resumeAtLaunch = existsSync(join(folder, "resume.json"));
            return options.launched ?? "started";
        },
        reconnect: () => done.push("reconnect"),
        quit: () => done.push("quit"),
    };
    return { given, done, seen };
}

describe("restart to update", () => {
    it("disconnects, runs a checked copy in a fresh folder, and quits", async () => {
        const { given, done, seen } = steps({ connected: true });
        await expect(installUpdate(ready, given)).resolves.toBeNull();
        expect(done).toEqual(["disconnect", "launch", "quit"]);
        // A copy, not the downloaded file: in a folder made for this run.
        expect(seen.launchedPath).not.toBe(ready.path);
        expect(dirname(seen.launchedPath ?? "")).toMatch(/[\\/]run-[^\\/]+$/);
        expect(dirname(dirname(seen.launchedPath ?? ""))).toBe(folder);
        expect(seen.launchedBytes).toEqual(installer);
        // The next start reconnects.
        expect(seen.resumeAtLaunch).toBe(true);
        await expect(takeResume(folder)).resolves.toBe(true);
    });

    it("leaves nothing to reconnect when the VPN was not connected", async () => {
        const { given, done, seen } = steps({ connected: false });
        await expect(installUpdate(ready, given)).resolves.toBeNull();
        expect(done).toEqual(["launch", "quit"]);
        expect(seen.resumeAtLaunch).toBe(false);
    });

    it("checks the installer again right before it runs, and runs nothing that changed", async () => {
        const changed = Buffer.from(installer);
        changed[0] = (changed[0] ?? 0) ^ 1;
        await writeFile(ready.path, changed);
        const { given, done } = steps({ connected: true });
        await expect(installUpdate(ready, given)).resolves.toBe("changed");
        expect(done).toEqual(["disconnect", "reconnect"]);
        // No copy left behind, and no note to reconnect at the next start.
        expect(readdirSync(folder).filter((name) => name.startsWith("run-"))).toEqual([]);
        expect(existsSync(join(folder, "resume.json"))).toBe(false);
    });

    it("runs nothing that grew or shrank since it was downloaded", async () => {
        for (const bytes of [Buffer.concat([installer, Buffer.from("x")]), installer.subarray(1)]) {
            await writeFile(ready.path, bytes);
            const { given, done } = steps();
            await expect(installUpdate(ready, given)).resolves.toBe("changed");
            expect(done).not.toContain("launch");
        }
    });

    it("when the administrator prompt is cancelled, changes nothing and reconnects", async () => {
        const { given, done } = steps({ connected: true, launched: "cancelled" });
        await expect(installUpdate(ready, given)).resolves.toBe("cancelled");
        expect(done).toEqual(["disconnect", "launch", "reconnect"]);
        expect(existsSync(join(folder, "resume.json"))).toBe(false);
        // The downloaded installer is still there for another try.
        expect(readFileSync(ready.path)).toEqual(installer);
    });

    it("says when the setup program could not be started, and reconnects", async () => {
        const { given, done } = steps({ connected: true, launched: "failed" });
        await expect(installUpdate(ready, given)).resolves.toBe("failed");
        expect(done).toEqual(["disconnect", "launch", "reconnect"]);
        const throwing = steps({ connected: false });
        throwing.given.launch = async () => {
            throw new Error("spawn failed");
        };
        await expect(installUpdate(ready, throwing.given)).resolves.toBe("failed");
        expect(throwing.done).toEqual([]);
    });

    it("installs nothing when the VPN cannot be disconnected", async () => {
        const { given, done } = steps({ connected: true, disconnects: false });
        await expect(installUpdate(ready, given)).resolves.toBe("not_disconnected");
        expect(done).toEqual(["disconnect"]);
    });
});

describe("one install at a time, and only of a ready update", () => {
    it("does nothing unless the updater hands over an installer", async () => {
        const { given, done } = steps();
        const ended: (InstallNotice | null)[] = [];
        await restartToUpdate(
            { beginInstall: () => null, endInstall: (n) => ended.push(n) },
            given,
        );
        expect(done).toEqual([]);
        expect(ended).toEqual([]);
    });

    it("tells the updater how it ended", async () => {
        const ended: (InstallNotice | null)[] = [];
        const updater = {
            beginInstall: () => ready,
            endInstall: (n: InstallNotice | null) => ended.push(n),
        };
        await restartToUpdate(updater, steps({ launched: "cancelled" }).given);
        await restartToUpdate(updater, steps().given);
        expect(ended).toEqual(["cancelled", null]);
    });
});

describe("the note to reconnect after an update", () => {
    it("is read once, and anything else reads as no", async () => {
        await leaveResume(folder);
        await expect(takeResume(folder)).resolves.toBe(true);
        await expect(takeResume(folder)).resolves.toBe(false);
        await writeFile(join(folder, "resume.json"), "{not json");
        await expect(takeResume(folder)).resolves.toBe(false);
        await writeFile(join(folder, "resume.json"), JSON.stringify({ reconnect: "yes" }));
        await expect(takeResume(folder)).resolves.toBe(false);
        expect(existsSync(join(folder, "resume.json"))).toBe(false);
    });
});

describe("starting the setup program on Windows", () => {
    it("asks for elevation silently, with the path only in the environment", () => {
        const path = "C:\\Users\\someone\\AppData\\Local\\UBC VPN\\updates\\run-x\\a'b;$(c).exe";
        const { file, args, env } = windowsLaunch(path, "C:\\Windows");
        expect(file).toBe(
            join("C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        );
        expect(env).toEqual({ SystemRoot: "C:\\Windows", UBC_VPN_INSTALLER: path });
        const script = args.at(-1) ?? "";
        expect(args.join(" ")).not.toContain(path);
        expect(script).toContain("-FilePath $env:UBC_VPN_INSTALLER");
        expect(script).toContain("-Verb RunAs");
        expect(script).toContain("'/S','--updated','--force-run'");
        expect(args).toContain("-NoProfile");
    });

    it("reads exit 0 as started, 2 as the prompt cancelled, anything else as failed", () => {
        expect(launchedFrom(0)).toBe("started");
        expect(launchedFrom(2)).toBe("cancelled");
        expect(launchedFrom(1)).toBe("failed");
        expect(launchedFrom(null)).toBe("failed");
    });
});

describe("disconnecting before an update", () => {
    function link(disconnectsAfter: number | null) {
        let disconnected = false;
        const listeners = new Set<() => void>();
        return {
            disconnect: async () => {
                if (disconnectsAfter !== null) {
                    setTimeout(() => {
                        disconnected = true;
                        for (const listener of listeners) {
                            listener();
                        }
                    }, disconnectsAfter);
                }
            },
            isDisconnected: () => disconnected,
            subscribe: (listener: () => void) => {
                listeners.add(listener);
                return () => listeners.delete(listener);
            },
            listeners,
        };
    }

    it("waits until the service says it is disconnected", async () => {
        const fake = link(20);
        await expect(disconnectAndWait(fake, 5_000)).resolves.toBe(true);
        expect(fake.listeners.size).toBe(0);
    });

    it("gives up after the limit", async () => {
        const fake = link(null);
        await expect(disconnectAndWait(fake, 50)).resolves.toBe(false);
        expect(fake.listeners.size).toBe(0);
    });
});
