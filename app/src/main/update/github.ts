// Talking to GitHub for updates: HTTPS to GitHub's own hosts only, with
// every redirect checked before it is followed, and every body read up to a
// limit. No Electron import, and the fetch itself is passed in, so the rules
// are tested against a fake that never touches the network.

import { UpdateRefused } from "./list";
import { parseVersion } from "./semver";

/** The repository whose releases are this app's updates. */
export const REPOSITORY = "Nima-Hs/ubc-vpn";
export const LATEST_RELEASE_URL = `https://api.github.com/repos/${REPOSITORY}/releases/latest`;
/** The release asset that holds the signed update list. */
export const LIST_ASSET = "update-list.json";

/**
 * The only hosts the updater talks to: GitHub's API, its website, where
 * release downloads start, and the hosts it redirects downloads to.
 */
export const GITHUB_HOSTS: ReadonlySet<string> = new Set([
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
]);

/** Where a release's assets are downloaded from, on github.com. */
const DOWNLOAD_PATH = `/${REPOSITORY}/releases/download/`;
/** More than GitHub uses: a download is redirected once. */
export const MAX_REDIRECTS = 5;
/** The most a release's description from the API may weigh. */
export const MAX_RELEASE_BYTES = 1024 * 1024;

/** How a request is made: `fetch`, or a fake for tests. */
export type Fetch = (url: string, init: RequestInit) => Promise<Response>;

/** A body that stopped arriving for longer than its idle limit. */
export class Stalled extends Error {
    override name = "Stalled";
}

/** Why GitHub's answer could not be used; not a refusal of anything signed. */
export class GitHubError extends Error {
    override name = "GitHubError";
}

/** The URL, if it is HTTPS to one of GitHub's hosts on the usual port, with no user name. */
export function githubUrl(text: string, base?: string): URL | null {
    let url: URL;
    try {
        url = new URL(text, base);
    } catch {
        return null;
    }
    const plain =
        url.protocol === "https:" &&
        url.port === "" &&
        url.username === "" &&
        url.password === "" &&
        GITHUB_HOSTS.has(url.hostname);
    return plain ? url : null;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/**
 * Gets `url`, following redirects by hand so that each one is checked
 * first: a redirect anywhere but HTTPS to GitHub is refused, and so is a
 * fetch that followed one by itself.
 */
export async function getFromGitHub(
    fetch: Fetch,
    url: string,
    headers: Record<string, string>,
    /** Ends the request, the body included, when it fires. */
    signal?: AbortSignal,
): Promise<Response> {
    let next = githubUrl(url);
    for (let hops = 0; next !== null; hops++) {
        if (hops > MAX_REDIRECTS) {
            throw new UpdateRefused("GitHub redirected too many times");
        }
        const init: RequestInit = { redirect: "manual", headers };
        if (signal !== undefined) {
            init.signal = signal;
        }
        const response = await fetch(next.href, init);
        if (response.redirected) {
            throw new UpdateRefused("a redirect was followed without being checked");
        }
        if (!REDIRECTS.has(response.status)) {
            return response;
        }
        const location = response.headers.get("location");
        await response.body?.cancel();
        next = location === null ? null : githubUrl(location, next.href);
    }
    throw new UpdateRefused("an address is not HTTPS to GitHub");
}

/** Reads a body whole, refusing it as soon as it passes `limit` bytes. */
export async function readLimited(
    response: Response,
    limit: number,
    idleMs = DEFAULT_IDLE_MS,
): Promise<Buffer> {
    const chunks: Uint8Array[] = [];
    let total = 0;
    await eachChunk(
        response,
        (chunk) => {
            total += chunk.length;
            if (total > limit) {
                throw new UpdateRefused("GitHub sent more than expected");
            }
            chunks.push(chunk);
        },
        idleMs,
    );
    return Buffer.concat(chunks);
}

/** The longest a body may go without sending anything. */
export const DEFAULT_IDLE_MS = 60_000;

/**
 * Hands each chunk of a body to `use`, which may throw to stop. Gives up
 * with `Stalled` when no chunk comes for `idleMs`.
 */
export async function eachChunk(
    response: Response,
    use: (chunk: Uint8Array) => void | Promise<void>,
    idleMs = DEFAULT_IDLE_MS,
): Promise<void> {
    if (response.body === null) {
        return;
    }
    const reader = response.body.getReader();
    try {
        for (;;) {
            let timer: NodeJS.Timeout | undefined;
            const idle = new Promise<never>((_, fail) => {
                timer = setTimeout(() => fail(new Stalled("the download stalled")), idleMs);
            });
            const { done, value } = await Promise.race([reader.read(), idle]).finally(() =>
                clearTimeout(timer),
            );
            if (done) {
                return;
            }
            await use(value);
        }
    } finally {
        await reader.cancel().catch(() => {});
    }
}

/** One downloadable file of a release. */
export interface Asset {
    url: string;
    size: number;
}

/** What the updater needs of a release. */
export interface Release {
    /** The tag without its `v`. */
    version: string;
    assets: ReadonlyMap<string, Asset>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reads the API's description of a release. Only a published release
 * tagged `v` and a version counts, and only assets downloaded from this
 * repository's releases on github.com.
 */
export function parseRelease(body: Buffer): Release {
    let release: unknown;
    try {
        release = JSON.parse(body.toString("utf8"));
    } catch {
        throw new GitHubError("the release is not JSON");
    }
    if (!isRecord(release) || release.draft !== false || !Array.isArray(release.assets)) {
        throw new GitHubError("not a published release");
    }
    const tag = release.tag_name;
    const version = typeof tag === "string" && tag.startsWith("v") ? tag.slice(1) : "";
    if (parseVersion(version) === null) {
        throw new GitHubError("the release's tag is not a version");
    }
    const assets = new Map<string, Asset>();
    for (const asset of release.assets) {
        if (!isRecord(asset)) {
            continue;
        }
        const { name, size, browser_download_url: link } = asset;
        const url = typeof link === "string" ? githubUrl(link) : null;
        if (
            typeof name === "string" &&
            typeof size === "number" &&
            Number.isSafeInteger(size) &&
            url !== null &&
            url.hostname === "github.com" &&
            url.pathname.startsWith(DOWNLOAD_PATH)
        ) {
            assets.set(name, { url: url.href, size });
        }
    }
    return { version, assets };
}
