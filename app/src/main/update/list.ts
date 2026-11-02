// The signed update list: what it holds, and how the app decides to trust
// it. The format is described in docs/architecture.md, "Updates", and
// written by packaging/update/sign.mjs. No Electron import, so the rules can
// be tested on their own.

import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import type { TrustedKey } from "./keys";
import { isNewer, parseVersion } from "./semver";

/** The product a list is for: the app's `appId` in electron-builder.yml. */
export const APP_ID = "io.github.nima-hs.ubc-vpn";
/** The list format this app reads. */
export const LIST_FORMAT = 1;
/**
 * Signed in front of the list, so a signature made with the key for any
 * other purpose can never pass as one over a list.
 */
export const SIGNING_CONTEXT = "ubc-vpn update list v1\n";
/** The most a list may weigh, signature and all. */
export const MAX_LIST_BYTES = 64 * 1024;
/** The most an installer may weigh: well above any installer we build. */
export const MAX_INSTALLER_BYTES = 512 * 1024 * 1024;

/** What `checkInstaller` reads: an open file, such as Node's `FileHandle`. */
export interface OpenFile {
    read(
        buffer: Buffer,
        offset: number,
        length: number,
        position: number,
    ): Promise<{ bytesRead: number }>;
}

/** One installer in a list. */
export interface UpdateFile {
    /** Which system it installs on, such as `windows-x64`. */
    platform: string;
    /** The release asset's file name. */
    name: string;
    size: number;
    /** Lowercase hex. */
    sha256: string;
}

/** A list whose signature, product and contents have been checked. */
export interface UpdateList {
    version: string;
    files: UpdateFile[];
}

/** Why a list or an installer was not trusted. The text names no secret and no path. */
export class UpdateRefused extends Error {
    override name = "UpdateRefused";
}

function refuse(reason: string): never {
    throw new UpdateRefused(reason);
}

/** A key's id, as a list names it: the first 16 hex digits of its SHA-256. */
export function keyId(raw: Uint8Array): string {
    return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

/** Decodes base64, refusing anything that does not re-encode the same. */
function strictBase64(text: unknown): Buffer {
    if (typeof text !== "string") {
        refuse("the list is not in the expected form");
    }
    const bytes = Buffer.from(text, "base64");
    if (bytes.toString("base64") !== text) {
        refuse("the list is not in the expected form");
    }
    return bytes;
}

function findKey(id: unknown, keys: readonly TrustedKey[]): KeyObject {
    for (const key of keys) {
        // Only exact base64 of 32 bytes is a key; the placeholder is not.
        const raw = Buffer.from(key.publicKey, "base64");
        if (raw.length === 32 && raw.toString("base64") === key.publicKey && keyId(raw) === id) {
            return createPublicKey({
                key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
                format: "jwk",
            });
        }
    }
    return refuse("the list is not signed with a trusted key");
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

const PLATFORM = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
// A plain file name: never a path, never hidden, never `.` or `..`.
const FILE_NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;

function readFile(value: unknown): UpdateFile {
    if (!isRecord(value)) {
        return refuse("the list is not in the expected form");
    }
    const { platform, name, size, sha256 } = value;
    if (typeof platform !== "string" || platform.length > 32 || !PLATFORM.test(platform)) {
        refuse("the list names a system it cannot be for");
    }
    if (typeof name !== "string" || !FILE_NAME.test(name)) {
        refuse("the list names a file it cannot be for");
    }
    if (typeof size !== "number" || !Number.isInteger(size) || size < 1) {
        refuse("the list gives a size that cannot be right");
    }
    if (size > MAX_INSTALLER_BYTES) {
        refuse("the installer is larger than an update may be");
    }
    if (typeof sha256 !== "string" || !SHA256.test(sha256)) {
        refuse("the list gives a checksum that cannot be right");
    }
    return { platform, name, size, sha256 };
}

/**
 * Checks a list as downloaded and returns what it says, or throws
 * `UpdateRefused`. In order: its size, its signature by one of `keys` over
 * the exact bytes signed, and only then what it holds: that it is for this
 * app, in this format, for a version, with well-formed installers, at most
 * one per system. Fields this app does not know are ignored, so a later
 * format can add some.
 */
export function verifyUpdateList(bytes: Uint8Array, keys: readonly TrustedKey[]): UpdateList {
    if (bytes.length > MAX_LIST_BYTES) {
        refuse("the list is larger than a list may be");
    }
    let envelope: unknown;
    try {
        envelope = JSON.parse(Buffer.from(bytes).toString("utf8"));
    } catch {
        refuse("the list is not in the expected form");
    }
    if (!isRecord(envelope) || envelope.format !== LIST_FORMAT) {
        refuse("the list is not in a format this app reads");
    }
    const signed = strictBase64(envelope.list);
    const signature = strictBase64(envelope.signature);
    const key = findKey(envelope.key, keys);
    const message = Buffer.concat([Buffer.from(SIGNING_CONTEXT, "utf8"), signed]);
    if (signature.length !== 64 || !verify(null, message, key, signature)) {
        refuse("the list's signature is not valid");
    }

    let list: unknown;
    try {
        list = JSON.parse(signed.toString("utf8"));
    } catch {
        refuse("the list is not in the expected form");
    }
    if (!isRecord(list) || list.format !== LIST_FORMAT) {
        refuse("the list is not in a format this app reads");
    }
    if (list.app !== APP_ID) {
        refuse("the list is for another product");
    }
    const { version, files } = list;
    if (typeof version !== "string" || parseVersion(version) === null) {
        refuse("the list gives a version that cannot be right");
    }
    if (!Array.isArray(files) || files.length > 16) {
        refuse("the list is not in the expected form");
    }
    const read = files.map(readFile);
    if (new Set(read.map((file) => file.platform)).size !== read.length) {
        refuse("the list names a system twice");
    }
    return { version, files: read };
}

/**
 * The installer to update to from `current` on `platform`, or `null` when
 * there is none: the list is for this version or an older one, or has
 * nothing for this system.
 */
export function chooseUpdate(
    list: UpdateList,
    current: string,
    platform: string,
): UpdateFile | null {
    if (!isNewer(list.version, current)) {
        return null;
    }
    return list.files.find((file) => file.platform === platform) ?? null;
}

/**
 * Checks an installer on disk against its entry in a list: exactly `size`
 * bytes with that SHA-256. Reads at most one byte past the size, so a file
 * that keeps growing cannot hold it up. Throws `UpdateRefused` if not.
 */
export async function checkInstaller(file: OpenFile, expected: UpdateFile): Promise<void> {
    const hash = createHash("sha256");
    const chunk = Buffer.alloc(1024 * 1024);
    let total = 0;
    let position = 0;
    while (total <= expected.size) {
        const want = Math.min(chunk.length, expected.size + 1 - total);
        const { bytesRead } = await file.read(chunk, 0, want, position);
        if (bytesRead === 0) {
            break;
        }
        hash.update(chunk.subarray(0, bytesRead));
        total += bytesRead;
        position += bytesRead;
    }
    if (total !== expected.size) {
        refuse("the installer is not the size the list gives");
    }
    if (hash.digest("hex") !== expected.sha256) {
        refuse("the installer's checksum does not match the list");
    }
}
