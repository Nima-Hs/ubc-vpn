// When the app checks for updates, and what it does with what it finds. No
// Electron import: the fetch, the clock, the timers and the folder are
// passed in, so the whole flow is tested against fakes.

import type { UpdateFailure, UpdateStatus, UpdateView } from "@shared/updates";
import { prepareFolder, saveInstaller } from "./download";
import {
    type Fetch,
    GitHubError,
    getFromGitHub,
    LATEST_RELEASE_URL,
    LIST_ASSET,
    MAX_RELEASE_BYTES,
    parseRelease,
    readLimited,
} from "./github";
import { releaseKeyProblems, type TrustedKey } from "./keys";
import {
    chooseUpdate,
    MAX_LIST_BYTES,
    type UpdateFile,
    UpdateRefused,
    verifyUpdateList,
} from "./list";

/** The first check waits this long after start, so it does not slow the start down. */
export const FIRST_CHECK_MS = 30_000;
/** How often the app checks after that. */
export const CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;

/** The platform name an update list gives this system, or `null` for none yet. */
export function updatePlatform(platform: NodeJS.Platform, arch: string): string | null {
    if (platform === "win32" && arch === "x64") {
        return "windows-x64";
    }
    if (platform === "darwin" && arch === "arm64") {
        return "macos-arm64";
    }
    // Linux's names are chosen with its installer.
    return null;
}

export interface UpdaterOptions {
    fetch: Fetch;
    /** The app's own version. */
    version: string;
    /** From `updatePlatform`. */
    platform: string | null;
    /** From `updatesFolder`. */
    folder: string | null;
    keys: readonly TrustedKey[];
    /** Only an installed app updates itself. */
    packaged: boolean;
    now: () => number;
    schedule: (run: () => void, firstMs: number, thenMs: number) => () => void;
}

/** A downloaded installer that passed every check. */
export interface ReadyInstaller {
    version: string;
    entry: UpdateFile;
    path: string;
}

class Failed extends Error {
    constructor(readonly reason: UpdateFailure) {
        super(reason);
    }
}

export class Updater {
    private status: UpdateStatus;
    private lastChecked: number | null = null;
    private automatic = true;
    private busy = false;
    private ready: ReadyInstaller | null = null;
    /** What was found while downloads were off, to fetch if they are turned on. */
    private pending: { version: string; entry: UpdateFile; url: string } | null = null;
    private readonly listeners = new Set<(view: UpdateView) => void>();
    private stop: (() => void) | null = null;

    constructor(private readonly options: UpdaterOptions) {
        this.status = this.canUpdate() ? { phase: "idle" } : { phase: "unavailable" };
    }

    /** Whether this copy can update itself at all. Nothing else reaches the network. */
    canUpdate(): boolean {
        const { packaged, platform, folder, keys } = this.options;
        return (
            packaged &&
            platform !== null &&
            folder !== null &&
            releaseKeyProblems(keys).length === 0
        );
    }

    /** Starts checking: once soon, then every few hours. */
    start(): void {
        if (this.canUpdate() && this.stop === null) {
            this.stop = this.options.schedule(
                () => void this.check(),
                FIRST_CHECK_MS,
                CHECK_INTERVAL_MS,
            );
        }
    }

    dispose(): void {
        this.stop?.();
        this.stop = null;
        this.listeners.clear();
    }

    view(): UpdateView {
        return { status: this.status, lastChecked: this.lastChecked };
    }

    /** The installer to run, once one is downloaded and checked. */
    readyInstaller(): ReadyInstaller | null {
        return this.ready;
    }

    subscribe(listener: (view: UpdateView) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    /** Whether updates are downloaded by themselves, as the settings say. */
    setAutomatic(automatic: boolean): void {
        this.automatic = automatic;
        if (automatic && this.pending !== null && !this.busy) {
            const found = this.pending;
            void this.run(() => this.download(found.version, found.entry, found.url));
        }
    }

    /** Checks now, unless this copy cannot update or a check or download is under way. */
    check(): Promise<void> {
        if (!this.canUpdate() || this.busy) {
            return Promise.resolve();
        }
        return this.run(() => this.checkOnce());
    }

    private async run(work: () => Promise<void>): Promise<void> {
        this.busy = true;
        try {
            await work();
        } catch (error) {
            this.publish({ phase: "failed", reason: reasonFor(error) });
        } finally {
            this.busy = false;
        }
    }

    private headers(accept: string): Record<string, string> {
        return { accept, "user-agent": `ubc-vpn-app/${this.options.version}` };
    }

    private async checkOnce(): Promise<void> {
        const { fetch, version, platform, keys } = this.options;
        const keep = this.ready;
        this.publish({ phase: "checking" });
        const answer = await getFromGitHub(
            fetch,
            LATEST_RELEASE_URL,
            this.headers("application/vnd.github+json"),
        );
        // No release yet.
        if (answer.status === 404) {
            await answer.body?.cancel();
            return this.found({ phase: "up_to_date" });
        }
        if (answer.status !== 200) {
            await answer.body?.cancel();
            throw new GitHubError(`GitHub answered ${answer.status}`);
        }
        const release = parseRelease(await readLimited(answer, MAX_RELEASE_BYTES));
        const listAsset = release.assets.get(LIST_ASSET);
        if (listAsset === undefined) {
            throw new UpdateRefused("the release has no update list");
        }
        const listAnswer = await getFromGitHub(
            fetch,
            listAsset.url,
            this.headers("application/octet-stream"),
        );
        if (listAnswer.status !== 200) {
            await listAnswer.body?.cancel();
            throw new GitHubError(`GitHub answered ${listAnswer.status}`);
        }
        const list = verifyUpdateList(await readLimited(listAnswer, MAX_LIST_BYTES), keys);
        // The list must be the release's own, not one carried over from another.
        if (list.version !== release.version) {
            throw new UpdateRefused("the list is for another release");
        }
        const entry = platform === null ? null : chooseUpdate(list, version, platform);
        if (entry === null) {
            return this.found({ phase: "up_to_date" });
        }
        if (keep !== null && keep.version === list.version && sameFile(keep.entry, entry)) {
            return this.found({ phase: "ready", version: keep.version });
        }
        const asset = release.assets.get(entry.name);
        if (asset === undefined || asset.size !== entry.size) {
            throw new UpdateRefused("the release does not have the installer the list names");
        }
        this.pending = { version: list.version, entry, url: asset.url };
        if (!this.automatic) {
            return this.found({ phase: "available", version: list.version });
        }
        this.lastChecked = this.options.now();
        await this.download(list.version, entry, asset.url);
    }

    private async download(version: string, entry: UpdateFile, url: string): Promise<void> {
        const folder = this.options.folder;
        if (folder === null) {
            return;
        }
        this.publish({ phase: "downloading", version });
        this.ready = null;
        const answer = await getFromGitHub(
            this.options.fetch,
            url,
            this.headers("application/octet-stream"),
        );
        if (answer.status !== 200) {
            await answer.body?.cancel();
            throw new GitHubError(`GitHub answered ${answer.status}`);
        }
        let path: string;
        try {
            await prepareFolder(folder);
            path = await saveInstaller(answer, entry, folder);
        } catch (error) {
            await answer.body?.cancel().catch(() => {});
            // A refusal, or the network failing mid-way, is said as such;
            // anything else is the disk's.
            throw error instanceof UpdateRefused || error instanceof TypeError
                ? error
                : new Failed("disk");
        }
        this.pending = null;
        this.ready = { version, entry, path };
        this.publish({ phase: "ready", version });
    }

    private found(status: UpdateStatus): void {
        this.lastChecked = this.options.now();
        if (status.phase !== "available") {
            this.pending = null;
        }
        this.publish(status);
    }

    private publish(status: UpdateStatus): void {
        this.status = status;
        const view = this.view();
        for (const listener of this.listeners) {
            listener(view);
        }
    }
}

function sameFile(a: UpdateFile, b: UpdateFile): boolean {
    return (
        a.name === b.name && a.size === b.size && a.sha256 === b.sha256 && a.platform === b.platform
    );
}

/** What the user is told about an error. Nothing of its text reaches the window. */
function reasonFor(error: unknown): UpdateFailure {
    if (error instanceof Failed) {
        return error.reason;
    }
    if (error instanceof UpdateRefused) {
        return "refused";
    }
    if (error instanceof GitHubError) {
        return "github";
    }
    // `fetch` rejects with a TypeError when the network cannot be used.
    return "offline";
}
