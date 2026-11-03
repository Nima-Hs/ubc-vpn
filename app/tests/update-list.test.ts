import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PLACEHOLDER_KEY, releaseKeyProblems, TRUSTED_KEYS } from "../src/main/update/keys";
import {
    APP_ID,
    checkInstaller,
    chooseUpdate,
    MAX_INSTALLER_BYTES,
    MAX_LIST_BYTES,
    type UpdateFile,
    type UpdateList,
    UpdateRefused,
    verifyUpdateList,
} from "../src/main/update/list";
import { EndlessMeter } from "./endless-fake";
import { listBody, makeKey, sha256, signList } from "./update-harness";

const key = makeKey();
const installer = Buffer.from("not really an installer");

function refusal(run: () => unknown): string {
    try {
        run();
    } catch (error) {
        expect(error).toBeInstanceOf(UpdateRefused);
        return (error as Error).message;
    }
    throw new Error("was not refused");
}

/** The same 32 bytes in base64, with the unused bits of the last digit set: not canonical. */
function nonCanonical(canonical: string): string {
    const digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const last = canonical.length - 2;
    const digit = digits.indexOf(canonical.charAt(last));
    return `${canonical.slice(0, last)}${digits.charAt(digit | 1)}=`;
}

function withFile(change: Record<string, unknown>): Record<string, unknown> {
    const body = listBody("0.2.0", installer);
    const [file] = body.files as Record<string, unknown>[];
    return { ...body, files: [{ ...file, ...change }] };
}

describe("trusting an update list", () => {
    it("accepts a list signed with a trusted key and returns what it says", () => {
        const list = verifyUpdateList(signList(listBody("0.2.0", installer), key), [key.trusted]);
        expect(list).toEqual({
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
    });

    it("finds the signing key among several, so the key can be rotated", () => {
        const next = makeKey();
        const keys = [key.trusted, next.trusted];
        expect(verifyUpdateList(signList(listBody("0.2.0", installer), next), keys).version).toBe(
            "0.2.0",
        );
    });

    it("refuses a list whose signed bytes were changed", () => {
        const good = JSON.parse(signList(listBody("0.2.0", installer), key).toString());
        const forged = JSON.stringify(listBody("9.0.0", installer));
        const tampered = Buffer.from(
            JSON.stringify({ ...good, list: Buffer.from(forged).toString("base64") }),
        );
        expect(refusal(() => verifyUpdateList(tampered, [key.trusted]))).toMatch(/signature/);
    });

    it("refuses a signature by a key it does not trust, even one claiming a trusted id", () => {
        const stranger = makeKey();
        const body = listBody("0.2.0", installer);
        expect(refusal(() => verifyUpdateList(signList(body, stranger), [key.trusted]))).toMatch(
            /trusted key/,
        );
        const claimed = signList(body, stranger, { keyId: key.id });
        expect(refusal(() => verifyUpdateList(claimed, [key.trusted]))).toMatch(/signature/);
    });

    it("refuses a signature made by the right key for any other purpose", () => {
        const body = listBody("0.2.0", installer);
        for (const context of ["", "ubc-vpn update list v2\n"]) {
            const signed = signList(body, key, { context });
            expect(refusal(() => verifyUpdateList(signed, [key.trusted]))).toMatch(/signature/);
        }
    });

    it("reads a built-in key only as plain base64 of 32 bytes", () => {
        const signed = signList(listBody("0.2.0", installer), key);
        const raw = Buffer.from(key.trusted.publicKey, "base64");
        const odd = nonCanonical(key.trusted.publicKey);
        expect(Buffer.from(odd, "base64")).toEqual(raw);
        for (const publicKey of [raw.toString("base64url"), `${key.trusted.publicKey}AA==`, odd]) {
            const odd = { label: "odd", publicKey };
            expect(refusal(() => verifyUpdateList(signed, [odd]))).toMatch(/trusted key/);
        }
    });

    it("trusts nothing while only the placeholder key is built in", () => {
        const placeholder = { label: "placeholder", publicKey: PLACEHOLDER_KEY };
        const signed = signList(listBody("0.2.0", installer), key);
        expect(refusal(() => verifyUpdateList(signed, [placeholder]))).toMatch(/trusted key/);
    });

    it("refuses a correctly signed list for another product", () => {
        const signed = signList({ ...listBody("0.2.0", installer), app: "io.example.other" }, key);
        expect(refusal(() => verifyUpdateList(signed, [key.trusted]))).toMatch(/another product/);
        const missing = { ...listBody("0.2.0", installer), app: undefined };
        expect(refusal(() => verifyUpdateList(signList(missing, key), [key.trusted]))).toMatch(
            /another product/,
        );
    });

    it("refuses a list larger than a list may be, before checking anything else", () => {
        const padded = { ...listBody("0.2.0", installer), note: "x".repeat(MAX_LIST_BYTES) };
        const signed = signList(padded, key);
        expect(signed.length).toBeGreaterThan(MAX_LIST_BYTES);
        expect(refusal(() => verifyUpdateList(signed, [key.trusted]))).toMatch(/larger/);
    });

    it("refuses an installer larger than an update may be, and allows one at the limit", () => {
        const verify = (size: number) =>
            verifyUpdateList(signList(withFile({ size }), key), [key.trusted]);
        expect(verify(MAX_INSTALLER_BYTES).files[0]?.size).toBe(MAX_INSTALLER_BYTES);
        expect(refusal(() => verify(MAX_INSTALLER_BYTES + 1))).toMatch(/larger/);
    });

    it("refuses entries that cannot be right", () => {
        for (const change of [
            { name: "../ubc-vpn-setup.exe" },
            { name: "folder/ubc-vpn-setup.exe" },
            { name: "folder\\ubc-vpn-setup.exe" },
            { name: ".hidden.exe" },
            { name: ".." },
            { name: "" },
            { platform: "Windows x64" },
            { size: 0 },
            { size: 1.5 },
            { size: "12" },
            { sha256: "A".repeat(64) },
            { sha256: "a".repeat(63) },
        ]) {
            const signed = signList(withFile(change), key);
            expect(() => verifyUpdateList(signed, [key.trusted]), JSON.stringify(change)).toThrow(
                UpdateRefused,
            );
        }
    });

    it("refuses a list that names a system twice, or is not in this format", () => {
        const body = listBody("0.2.0", installer);
        const twice = {
            ...body,
            files: [...(body.files as unknown[]), ...(body.files as unknown[])],
        };
        expect(refusal(() => verifyUpdateList(signList(twice, key), [key.trusted]))).toMatch(
            /twice/,
        );
        for (const wrong of [
            signList({ ...body, format: 2 }, key),
            signList(body, key, { envelope: { format: 2 } }),
            signList({ ...body, version: "v0.2.0" }, key),
            signList("not json", key),
            signList(body, key, { envelope: { signature: "not base64!" } }),
            Buffer.from("not json"),
        ]) {
            expect(() => verifyUpdateList(wrong, [key.trusted])).toThrow(UpdateRefused);
        }
    });

    it("is bound to this app's id, the one the installer is built with", () => {
        const yml = readFileSync(resolve(__dirname, "../electron-builder.yml"), "utf8");
        expect(yml).toMatch(new RegExp(`^appId: ${APP_ID.replaceAll(".", "\\.")}$`, "m"));
    });
});

describe("choosing an update", () => {
    const file: UpdateFile = { platform: "windows-x64", name: "a.exe", size: 1, sha256: "0" };
    const list = (version: string): UpdateList => ({ version, files: [file] });

    it("takes this system's installer from a newer list", () => {
        expect(chooseUpdate(list("0.2.0"), "0.1.0", "windows-x64")).toEqual(file);
        expect(chooseUpdate(list("0.1.0"), "0.1.0-rc.1", "windows-x64")).toEqual(file);
    });

    it("never downgrades or reinstalls", () => {
        expect(chooseUpdate(list("0.1.0"), "0.2.0", "windows-x64")).toBeNull();
        expect(chooseUpdate(list("0.2.0"), "0.2.0", "windows-x64")).toBeNull();
        expect(chooseUpdate(list("0.2.0-rc.1"), "0.2.0", "windows-x64")).toBeNull();
    });

    it("has nothing when the list has nothing for this system", () => {
        expect(chooseUpdate(list("0.2.0"), "0.1.0", "macos-arm64")).toBeNull();
    });
});

describe("checking a downloaded installer", () => {
    let folder: string;
    const entry: UpdateFile = {
        platform: "windows-x64",
        name: "ubc-vpn-setup-0.2.0-x64.exe",
        size: installer.length,
        sha256: sha256(installer),
    };

    beforeAll(async () => {
        folder = await mkdtemp(join(tmpdir(), "upd-check-"));
    });
    afterAll(async () => {
        await rm(folder, { recursive: true, force: true });
    });

    async function check(bytes: Uint8Array): Promise<void> {
        const path = join(folder, "upd-installer.exe");
        await writeFile(path, bytes);
        const file = await open(path, "r");
        try {
            await checkInstaller(file, entry);
        } finally {
            await file.close();
        }
    }

    it("accepts the exact file the list names", async () => {
        await expect(check(installer)).resolves.toBeUndefined();
    });

    it("refuses a file with other contents of the same size", async () => {
        const changed = Buffer.from(installer);
        changed[0] = (changed[0] ?? 0) ^ 1;
        await expect(check(changed)).rejects.toThrow(/checksum/);
    });

    it("reads at most one byte past the size, however long the file is", async () => {
        const meter = new EndlessMeter();
        const endless = {
            read: async (buffer: Buffer, offset: number, length: number) => {
                meter.take(length);
                buffer.fill(0, offset, offset + length);
                return { bytesRead: length };
            },
        };
        await expect(checkInstaller(endless, entry)).rejects.toThrow(/size/);
        expect(meter.served).toBe(entry.size + 1);
    });

    it("refuses a file that is longer or shorter", async () => {
        await expect(check(Buffer.concat([installer, Buffer.from("x")]))).rejects.toThrow(/size/);
        await expect(check(installer.subarray(1))).rejects.toThrow(/size/);
    });
});

describe("the release key check", () => {
    const real = makeKey().trusted;

    it("fails with the placeholder, a malformed key, a repeated key, or none", () => {
        const placeholder = { label: "p", publicKey: PLACEHOLDER_KEY };
        expect(releaseKeyProblems([placeholder])).toEqual([
            "the update key is still the placeholder",
        ]);
        expect(releaseKeyProblems([real, placeholder])).not.toEqual([]);
        expect(releaseKeyProblems([{ label: "short", publicKey: "AAAA" }])).not.toEqual([]);
        // One the verifier would never match must not pass either.
        const odd = { label: "odd", publicKey: nonCanonical(real.publicKey) };
        expect(releaseKeyProblems([odd])).not.toEqual([]);
        expect(releaseKeyProblems([real, real])).not.toEqual([]);
        expect(releaseKeyProblems([])).not.toEqual([]);
    });

    it("passes real keys", () => {
        expect(releaseKeyProblems([real])).toEqual([]);
        expect(releaseKeyProblems([real, makeKey().trusted])).toEqual([]);
    });

    it("is what `pnpm check:release` runs on the keys built into the app", () => {
        const run = spawnSync(
            process.execPath,
            ["--disable-warning=MODULE_TYPELESS_PACKAGE_JSON", "scripts/check-release-keys.mjs"],
            { cwd: resolve(__dirname, ".."), encoding: "utf8" },
        );
        const ready = releaseKeyProblems(TRUSTED_KEYS).length === 0;
        expect(run.status, run.stderr).toBe(ready ? 0 : 1);
    });
});
