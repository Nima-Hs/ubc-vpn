// packaging/update/sign.mjs, which the release workflow will run, checked
// against the app's own reader with a throwaway key made here.

import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifyUpdateList } from "../src/main/update/list";
import { makeKey, sha256 } from "./update-harness";

const SCRIPT = resolve(__dirname, "../../packaging/update/sign.mjs");
const key = makeKey();
const pem = key.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
// The secret part of the key, as it would appear if printed in any form.
const secretX = key.privateKey.export({ format: "jwk" }).d as string;
const secretForms = [
    pem.split("\n")[1] as string,
    secretX,
    Buffer.from(secretX, "base64url").toString("base64"),
];
const installer = Buffer.from("a stand-in for the Windows setup program");

let folder: string;
let installerPath: string;

beforeAll(async () => {
    folder = await mkdtemp(join(tmpdir(), "upd-sign-"));
    installerPath = join(folder, "ubc-vpn-setup-0.2.0-x64.exe");
    await writeFile(installerPath, installer);
});
afterAll(async () => {
    await rm(folder, { recursive: true, force: true });
});

function run(args: string[], input: string) {
    return spawnSync(process.execPath, [SCRIPT, ...args], { input, encoding: "utf8" });
}

function expectNoSecret(output: string): void {
    for (const form of secretForms) {
        expect(output).not.toContain(form);
    }
}

describe("signing an update list", () => {
    it("writes a list the app trusts, with the installer's real size and checksum", () => {
        const result = run(["--version", "0.2.0", "--file", `windows-x64=${installerPath}`], pem);
        expect(result.status, result.stderr).toBe(0);
        expect(verifyUpdateList(Buffer.from(result.stdout), [key.trusted])).toEqual({
            version: "0.2.0",
            files: [
                {
                    platform: "windows-x64",
                    name: "ubc-vpn-setup-0.2.0-x64.exe",
                    size: installer.length,
                    sha256: sha256(installer),
                },
            ],
        });
        expect(result.stderr).toContain(key.id);
        expectNoSecret(result.stdout + result.stderr);
    });

    it("reads the key from a file descriptor and writes the list to a file", async () => {
        const out = join(folder, "upd-list.json");
        const child = spawn(
            process.execPath,
            [
                SCRIPT,
                "--version",
                "0.2.0",
                "--file",
                `windows-x64=${installerPath}`,
                "--key-fd",
                "3",
                "--out",
                out,
            ],
            { stdio: ["ignore", "pipe", "pipe", "pipe"] },
        );
        let printed = "";
        child.stdout?.on("data", (chunk) => {
            printed += chunk;
        });
        child.stderr?.on("data", (chunk) => {
            printed += chunk;
        });
        const keyPipe = child.stdio[3] as NodeJS.WritableStream;
        keyPipe.end(pem);
        const status = await new Promise((done) => child.on("close", done));
        expect(status, printed).toBe(0);
        expect(verifyUpdateList(await readFile(out), [key.trusted]).version).toBe("0.2.0");
        expectNoSecret(printed);
    });

    it("refuses an option it does not take, without repeating what was given", () => {
        const result = run(["--key", pem], pem);
        expect(result.status).toBe(2);
        expectNoSecret(result.stdout + result.stderr);
    });

    it("refuses a key that is not Ed25519, or no key", () => {
        const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
        const ec = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
        const args = ["--version", "0.2.0", "--file", `windows-x64=${installerPath}`];
        expect(run(args, ec).status).toBe(1);
        expect(run(args, "").status).toBe(1);
    });

    it("keeps to the app's limits on the version and the number of installers", async () => {
        const file = `windows-x64=${installerPath}`;
        const long = `0.2.0-${"a".repeat(59)}`;
        expect(long.length).toBe(65);
        expect(run(["--version", long, "--file", file], pem).status).toBe(2);
        const many: string[] = [];
        for (let at = 0; at < 17; at++) {
            many.push("--file", `p${at}=${installerPath}`);
        }
        expect(run(["--version", "0.2.0", ...many], pem).status).toBe(2);
        expect(run(["--version", "0.2.0", ...many.slice(2)], pem).status).toBe(0);
        const empty = join(folder, "upd-empty.exe");
        await writeFile(empty, "");
        expect(run(["--version", "0.2.0", "--file", `windows-x64=${empty}`], pem).status).toBe(1);
    });

    it("refuses a version, a platform or a file the app would not accept", () => {
        const file = `windows-x64=${installerPath}`;
        expect(run(["--version", "v0.2.0", "--file", file], pem).status).toBe(2);
        expect(run(["--version", "0.2.0", "--file", `Windows=${installerPath}`], pem).status).toBe(
            1,
        );
        expect(run(["--version", "0.2.0", "--file", `windows-x64=${folder}`], pem).status).toBe(1);
        expect(run(["--version", "0.2.0", "--file", file, "--file", file], pem).status).toBe(1);
        expect(run(["--version", "0.2.0"], pem).status).toBe(2);
    });
});
