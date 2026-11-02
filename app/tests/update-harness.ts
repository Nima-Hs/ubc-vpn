// Signed update lists for tests, made with a throwaway key generated here.
// No real key is in the repository; these keys live only while a test runs.

import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import type { TrustedKey } from "../src/main/update/keys";
import { APP_ID, keyId, LIST_FORMAT, SIGNING_CONTEXT } from "../src/main/update/list";

export interface TestKey {
    privateKey: KeyObject;
    trusted: TrustedKey;
    id: string;
}

export function makeKey(): TestKey {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const x = publicKey.export({ format: "jwk" }).x as string;
    const raw = Buffer.from(x, "base64url");
    return {
        privateKey,
        trusted: { label: "test key", publicKey: raw.toString("base64") },
        id: keyId(raw),
    };
}

export function sha256(bytes: Uint8Array): string {
    return createHash("sha256").update(bytes).digest("hex");
}

/** The list a release of `version` would carry for one Windows installer. */
export function listBody(version: string, installer: Uint8Array): Record<string, unknown> {
    return {
        format: LIST_FORMAT,
        app: APP_ID,
        version,
        files: [
            {
                platform: "windows-x64",
                name: `ubc-vpn-setup-${version}-x64.exe`,
                size: installer.length,
                sha256: sha256(installer),
            },
        ],
    };
}

/** Signs `body` as the release workflow would; the options make it wrong on purpose. */
export function signList(
    body: unknown,
    key: TestKey,
    options: { context?: string; keyId?: string; envelope?: Record<string, unknown> } = {},
): Buffer {
    const list = Buffer.from(typeof body === "string" ? body : JSON.stringify(body), "utf8");
    const message = Buffer.concat([Buffer.from(options.context ?? SIGNING_CONTEXT, "utf8"), list]);
    return Buffer.from(
        JSON.stringify({
            format: LIST_FORMAT,
            key: options.keyId ?? key.id,
            list: list.toString("base64"),
            signature: sign(null, message, key.privateKey).toString("base64"),
            ...options.envelope,
        }),
        "utf8",
    );
}
