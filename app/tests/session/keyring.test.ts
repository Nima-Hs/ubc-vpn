// The installed client, started just as the app starts it, in a desktop
// session with a real Secret Service. Only `packaging/linux/tests/keyring-session.sh`
// runs this, on a throwaway CI runner, after the package is installed: the
// session's bus, its keyring and the home folder are all made up for the run,
// and nothing here knows a real account or password.
//
// `ProfilesRunner` and `startClient` are the app's own, not a copy, so the
// environment the client gets is the one `bridgeEnv` gives it.

import { spawn } from "node:child_process";
import {
    chmodSync,
    existsSync,
    mkdirSync,
    mkdtempSync,
    readdirSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startClient } from "../../src/main/channel/bridge";
import { ProfilesRunner } from "../../src/main/channel/profiles";

function required(name: string): string {
    const value = process.env[name];
    if (value === undefined || value === "") {
        throw new Error(`${name} is not set: run this through keyring-session.sh`);
    }
    return value;
}

const client = required("UBC_VPN_SESSION_CLIENT");
const session = {
    DBUS_SESSION_BUS_ADDRESS: required("DBUS_SESSION_BUS_ADDRESS"),
    XDG_RUNTIME_DIR: required("XDG_RUNTIME_DIR"),
};
const home = required("HOME");

/** The client as the app runs it, with this as the app's own environment. */
const profiles = (env: Record<string, string | undefined>) =>
    new ProfilesRunner({ command: client, env: { ...env, HOME: home }, timeoutMs: 30_000 });

/** What the app would be told about the keyring, and what comes of turning saving on and off. */
async function savingIsUsable(env: Record<string, string | undefined>): Promise<void> {
    const runner = profiles(env);
    const listed = await runner.list();
    if (!listed.ok) {
        throw new Error(`the client could not list the profiles: ${listed.error}`);
    }
    expect(listed.value.keyring).toBe("available");
    const id = listed.value.global.active_profile;
    const saved = (result: Awaited<ReturnType<typeof runner.list>>) => {
        if (!result.ok) {
            throw new Error(`the client refused: ${result.error}`);
        }
        return result.value.profiles.find((profile) => profile.id === id)?.save_password;
    };
    expect(saved(await runner.update(id, { save_password: true }))).toBe(true);
    expect(saved(await runner.list())).toBe(true);
    expect(saved(await runner.update(id, { save_password: false }))).toBe(false);
    expect(saved(await runner.list())).toBe(false);
}

/** Saving cannot be turned on, and the client says why. */
async function noKeyring(env: Record<string, string | undefined>): Promise<void> {
    const runner = profiles(env);
    const listed = await runner.list();
    if (!listed.ok) {
        throw new Error(`the client could not list the profiles: ${listed.error}`);
    }
    expect(listed.value.keyring).toBe("unavailable");
    const id = listed.value.global.active_profile;
    expect(await runner.update(id, { save_password: true })).toEqual({
        ok: false,
        error: "keyring_not_cleared",
    });
}

describe("the installed client in a desktop session", () => {
    it("finds the keyring with the session's environment, as the app is given it", async () => {
        await savingIsUsable({
            ...session,
            // What else a desktop gives an app, which must make no difference.
            DISPLAY: ":0",
            XDG_SESSION_TYPE: "wayland",
            SECRET_TOKEN: "made-up-secret",
        });
    });

    it("finds it with the bus's address alone", async () => {
        await savingIsUsable({ DBUS_SESSION_BUS_ADDRESS: session.DBUS_SESSION_BUS_ADDRESS });
    });

    it("finds it with the runtime folder alone", async () => {
        await savingIsUsable({ XDG_RUNTIME_DIR: session.XDG_RUNTIME_DIR });
    });

    // The control: without this, the tests above could pass with no bus at all.
    it("has no keyring with neither", async () => {
        await noKeyring({});
    });
});

describe("what those two variables cannot do", () => {
    let scratch: string;
    let planted: string;
    let listeners: Server[];
    let touched: string[];

    /** Listens where a redirected client would connect, and notes whether one did. */
    const listen = (path: string) =>
        new Promise<void>((done, fail) => {
            const server = createServer((socket) => {
                touched.push(path);
                socket.destroy();
            });
            server.once("error", fail);
            server.listen(path, done);
            listeners.push(server);
        });

    beforeAll(async () => {
        scratch = mkdtempSync(join(tmpdir(), "uvt-planted-"));
        planted = join(scratch, "run");
        listeners = [];
        touched = [];
        const uid = process.getuid?.() ?? 0;
        // Everywhere a client that read the variable might look.
        const dev = join(planted, `ubc-vpn-dev-${uid}`);
        const product = join(planted, "ubc-vpn");
        mkdirSync(dev, { recursive: true, mode: 0o700 });
        mkdirSync(product, { mode: 0o700 });
        chmodSync(planted, 0o700);
        await listen(join(dev, "service.sock"));
        await listen(join(product, "service.sock"));
        await listen(join(planted, "service.sock"));
    });

    afterAll(() => {
        for (const server of listeners) {
            server.close();
        }
    });

    /** Runs the client once, as the app does, and waits for it to end. */
    const run = (args: string[], env: Record<string, string>) =>
        new Promise<string>((done) => {
            const child = startClient(client, args, { ...env, HOME: home });
            child.stdin.end();
            let said = "";
            child.stdout.on("data", (chunk: Buffer) => {
                said += chunk.toString();
            });
            child.once("close", (status) => done(`${status}: ${said}`));
        });

    it("does not make the client look for the service in the runtime folder", async () => {
        for (const args of [
            ["status"],
            ["profiles", "list", "--json"],
            ["settings", "get", "--json"],
        ]) {
            // A client that looked there and turned the socket down would never
            // connect to it, but would still answer differently.
            const answer = await run(args, { XDG_RUNTIME_DIR: planted });
            expect(answer, args.join(" ")).toBe(await run(args, {}));
        }
        expect(touched).toEqual([]);
    });

    it("does not make the client keep anything in the runtime folder", async () => {
        const before = readdirSync(planted, { recursive: true }).map(String).sort();
        const runner = profiles({ XDG_RUNTIME_DIR: planted });
        const listed = await runner.list();
        expect(listed.ok).toBe(true);
        expect(readdirSync(planted, { recursive: true }).map(String).sort()).toEqual(before);
        // The settings stay in the home folder.
        expect(existsSync(join(home, ".config", "ubc-vpn"))).toBe(true);
    });

    it("cannot make the client run a program as the bus", async () => {
        // The library would run this for an address of this form: it is
        // refused before the client starts, and the marker proves it.
        const marker = join(scratch, "the-program-ran");
        const program = join(scratch, "program");
        writeFileSync(program, `#!/bin/sh\ntouch "${marker}"\n`, { mode: 0o700 });
        // The check itself: the program does leave its mark, so that no mark
        // below is the client's doing.
        await new Promise<void>((done, fail) => {
            const check = spawn(program, [], { stdio: "ignore" });
            check.once("error", fail);
            check.once("close", () => done());
        });
        expect(existsSync(marker)).toBe(true);
        rmSync(marker);

        await noKeyring({ DBUS_SESSION_BUS_ADDRESS: `unixexec:path=${program}` });
        expect(existsSync(marker)).toBe(false);
        // A list does not get one through behind a bus that does not answer.
        const list = `unix:path=${join(scratch, "nothing")};unixexec:path=${program}`;
        await noKeyring({ DBUS_SESSION_BUS_ADDRESS: list });
        expect(existsSync(marker)).toBe(false);
    });
});
