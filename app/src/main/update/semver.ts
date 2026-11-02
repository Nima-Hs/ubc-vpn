// Version numbers as Semantic Versioning 2.0.0 defines them, for deciding
// whether an update is newer than the app. No Electron import, so the rules
// can be tested on their own.

/** A version, split into the parts that decide its order. */
export interface Version {
    major: bigint;
    minor: bigint;
    patch: bigint;
    /** The pre-release identifiers, empty for a release. */
    pre: readonly (bigint | string)[];
}

/** Longer than any version this project will use; past it, nothing is parsed. */
export const MAX_VERSION_LENGTH = 64;

// The grammar from semver.org: numbers without leading zeros, and
// pre-release identifiers that are numbers without leading zeros or contain
// a letter or hyphen. Build metadata is allowed and plays no part in order.
const NUMBER = "0|[1-9]\\d*";
const PRE_ID = `(?:${NUMBER}|\\d*[a-zA-Z-][0-9a-zA-Z-]*)`;
const VERSION = new RegExp(
    `^(${NUMBER})\\.(${NUMBER})\\.(${NUMBER})` +
        `(?:-(${PRE_ID}(?:\\.${PRE_ID})*))?` +
        "(?:\\+[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*)?$",
);

/** Reads a version, or returns `null` if the text is not one. */
export function parseVersion(text: string): Version | null {
    if (text.length > MAX_VERSION_LENGTH) {
        return null;
    }
    const match = VERSION.exec(text);
    if (match === null) {
        return null;
    }
    const [, major = "", minor = "", patch = "", pre] = match;
    return {
        major: BigInt(major),
        minor: BigInt(minor),
        patch: BigInt(patch),
        pre:
            pre === undefined
                ? []
                : pre.split(".").map((id) => (/^\d+$/.test(id) ? BigInt(id) : id)),
    };
}

function sign(a: bigint, b: bigint): number {
    return a < b ? -1 : a > b ? 1 : 0;
}

function comparePre(a: readonly (bigint | string)[], b: readonly (bigint | string)[]): number {
    // A release comes after every pre-release of the same version.
    if (a.length === 0 || b.length === 0) {
        return Math.sign(b.length - a.length);
    }
    for (let at = 0; at < Math.min(a.length, b.length); at++) {
        const x = a[at] as bigint | string;
        const y = b[at] as bigint | string;
        if (x === y) {
            continue;
        }
        // Numbers come before words; numbers compare as numbers, words by
        // their ASCII order.
        if (typeof x === "bigint" && typeof y === "bigint") {
            return sign(x, y);
        }
        if (typeof x === "bigint") {
            return -1;
        }
        if (typeof y === "bigint") {
            return 1;
        }
        return x < y ? -1 : 1;
    }
    // Equal so far: the one with more identifiers comes after.
    return Math.sign(a.length - b.length);
}

/** Orders two versions: negative if `a` comes first, positive if after, 0 if the same. */
export function compareVersions(a: Version, b: Version): number {
    return (
        sign(a.major, b.major) ||
        sign(a.minor, b.minor) ||
        sign(a.patch, b.patch) ||
        comparePre(a.pre, b.pre)
    );
}

/**
 * Whether `candidate` is newer than `current`. An older version, the same
 * version, and anything that is not a version are all "no": an update is
 * never a downgrade or a reinstall.
 */
export function isNewer(candidate: string, current: string): boolean {
    const next = parseVersion(candidate);
    const now = parseVersion(current);
    return next !== null && now !== null && compareVersions(next, now) > 0;
}
