// The public keys an update list may be signed with. Only public keys belong
// here: the private key is the owner's, kept as a secret of the release
// workflow, and never appears in the repository. See docs/architecture.md,
// "Updates".
//
// This file imports nothing, so `scripts/check-release-keys.mjs` can load
// it with Node alone.

/** One trusted key: Ed25519, its 32 raw bytes in base64. */
export interface TrustedKey {
    /** Where the key came from, for people reading this file. */
    label: string;
    publicKey: string;
}

/**
 * Stands in for the real key until the owner adds it. It is not a key: the
 * verifier trusts nothing with it, and `pnpm check:release` fails while it
 * is here, so a release cannot ship it.
 */
export const PLACEHOLDER_KEY = "PLACEHOLDER-NOT-A-KEY-REPLACE-BEFORE-RELEASE";

/**
 * To rotate the key, add the new one here and release; once that version
 * is out, sign with the new key; later, remove the old one.
 */
export const TRUSTED_KEYS: readonly TrustedKey[] = [
    { label: "placeholder until the owner adds the release key", publicKey: PLACEHOLDER_KEY },
];

/**
 * A key's 32 raw bytes, or `null` unless the text is exactly their base64:
 * re-encoding the bytes must give the same text back. The verifier and the
 * release check both use this, so a key the check passes is one the app
 * trusts. The placeholder is never one.
 */
export function rawKey(text: string): Buffer | null {
    const raw = Buffer.from(text, "base64");
    return raw.length === 32 && raw.toString("base64") === text ? raw : null;
}

/**
 * What stops a release from shipping these keys: the placeholder, a key
 * that is not 32 bytes of base64, a key listed twice, or no key at all.
 * Empty when they can ship.
 */
export function releaseKeyProblems(keys: readonly TrustedKey[]): string[] {
    const problems: string[] = [];
    if (keys.length === 0) {
        problems.push("no update key is trusted");
    }
    const seen = new Set<string>();
    for (const key of keys) {
        if (key.publicKey === PLACEHOLDER_KEY) {
            problems.push("the update key is still the placeholder");
        } else if (rawKey(key.publicKey) === null) {
            problems.push(`"${key.label}" is not a 32-byte key in base64`);
        } else if (seen.has(key.publicKey)) {
            problems.push(`"${key.label}" is listed twice`);
        }
        seen.add(key.publicKey);
    }
    return problems;
}
