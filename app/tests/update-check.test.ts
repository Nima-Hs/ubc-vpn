// The updater against a fake GitHub: no request ever leaves this process,
// no installer is run, and files go only to a fresh temporary folder.
// The keys are throwaway ones made here.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describeUpdate } from "@shared/settings-copy";
import type { UpdateStatus } from "@shared/updates";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { prepareFolder, updatesFolder } from "../src/main/update/download";
import {
    type Fetch,
    GITHUB_HOSTS,
    githubUrl,
    LATEST_RELEASE_URL,
    MAX_REDIRECTS,
    MAX_RELEASE_BYTES,
} from "../src/main/update/github";
import { mayUpdate, takeNothing } from "../src/main/update/ipc";
import { PLACEHOLDER_KEY } from "../src/main/update/keys";
import { MAX_LIST_BYTES } from "../src/main/update/list";
import {
    CHECK_INTERVAL_MS,
    FIRST_CHECK_MS,
    Updater,
    type UpdaterOptions,
    updatePlatform,
} from "../src/main/update/updater";
import { ENDLESS_CAP_BYTES, ENDLESS_CAP_ITEMS, EndlessMeter } from "./endless-fake";
import { listBody, makeKey, signList, type TestKey } from "./update-harness";

const key = makeKey();
const DOWNLOADS = "https://github.com/Nima-Hs/ubc-vpn/releases/download";
const ASSETS = "https://release-assets.githubusercontent.com/made-up";
const NOW = 1_800_000_000_000;

/** One answer of the fake GitHub: a body, or a redirect, or a failure. */
type Answer = {
    status?: number;
    body?: Uint8Array | string | ReadableStream<Uint8Array>;
    location?: string;
    redirected?: boolean;
};

/**
 * A body that never ends, in chunks of `size` bytes. Past `cap` bytes the stream
 * fails, so a limit that has gone fails its test and fills neither memory nor disk.
 */
function endless(size: number, cap = ENDLESS_CAP_BYTES) {
    const meter = new EndlessMeter(cap);
    const stream = new ReadableStream<Uint8Array>(
        {
            pull(controller) {
                meter.take(size);
                controller.enqueue(new Uint8Array(size).fill(0x20));
            },
        },
        { highWaterMark: 0 },
    );
    return { stream, meter };
}

class FakeGitHub {
    readonly asked: string[] = [];
    readonly answers = new Map<string, Answer | (() => never)>();
    /** A redirect loop with no limit ends here, not when memory does. */
    private readonly requests = new EndlessMeter(ENDLESS_CAP_ITEMS);

    readonly fetch: Fetch = async (url, init) => {
        this.requests.take(1);
        this.asked.push(url);
        expect(init.redirect).toBe("manual");
        const answer = this.answers.get(url);
        if (answer === undefined) {
            return new Response("not here", { status: 404 });
        }
        if (typeof answer === "function") {
            return answer();
        }
        const headers: Record<string, string> =
            answer.location === undefined ? {} : { location: answer.location };
        const response = new Response(answer.body ?? null, {
            status: answer.status ?? 200,
            headers,
        });
        if (answer.redirected) {
            Object.defineProperty(response, "redirected", { value: true });
        }
        return response;
    };

    /** A release of `version` with its signed list and installer, as the release workflow makes it. */
    release(
        version: string,
        installer: Uint8Array,
        options: { signer?: TestKey; list?: Record<string, unknown>; tag?: string } = {},
    ): void {
        const name = `ubc-vpn-setup-${version}-x64.exe`;
        const list = signList(options.list ?? listBody(version, installer), options.signer ?? key);
        this.answers.set(LATEST_RELEASE_URL, {
            body: JSON.stringify({
                tag_name: options.tag ?? `v${version}`,
                draft: false,
                assets: [
                    {
                        name: "update-list.json",
                        size: list.length,
                        browser_download_url: `${DOWNLOADS}/v${version}/update-list.json`,
                    },
                    {
                        name,
                        size: installer.length,
                        browser_download_url: `${DOWNLOADS}/v${version}/${name}`,
                    },
                ],
            }),
        });
        this.answers.set(`${DOWNLOADS}/v${version}/update-list.json`, { body: list });
        // Downloads are redirected once, as GitHub does.
        this.answers.set(`${DOWNLOADS}/v${version}/${name}`, {
            status: 302,
            location: `${ASSETS}/${name}?token=made-up`,
        });
        this.answers.set(`${ASSETS}/${name}?token=made-up`, { body: installer });
    }

    installerUrl(version: string): string {
        return `${ASSETS}/ubc-vpn-setup-${version}-x64.exe?token=made-up`;
    }
}

let folder: string;
let github: FakeGitHub;
const installer = Buffer.from("a stand-in for the next setup program");

beforeEach(async () => {
    folder = join(await mkdtemp(join(tmpdir(), "upd-check-")), "updates");
    github = new FakeGitHub();
});
afterEach(async () => {
    await rm(join(folder, ".."), { recursive: true, force: true });
});

/** An updater against the fake GitHub, told by default that Automatic updates are on. */
function updater(change: Partial<UpdaterOptions> = {}, automatic: boolean | null = true): Updater {
    const subject = new Updater({
        fetch: github.fetch,
        version: "0.1.0",
        platform: "windows-x64",
        folder,
        keys: [key.trusted],
        packaged: true,
        now: () => NOW,
        schedule: () => () => {},
        ...change,
    });
    if (automatic !== null) {
        subject.setAutomatic(automatic);
    }
    return subject;
}

async function checked(change: Partial<UpdaterOptions> = {}): Promise<[Updater, UpdateStatus]> {
    const subject = updater(change);
    await subject.check();
    return [subject, subject.view().status];
}

/** The body the fake GitHub answers `url` with, as set up. */
function answerBody(url: string): unknown {
    const answer = github.answers.get(url);
    return typeof answer === "function" ? undefined : answer?.body;
}

function hosts(): string[] {
    return github.asked.map((url) => new URL(url).hostname);
}

describe("checking for an update", () => {
    it("downloads a newer installer the signed list names, and keeps it ready", async () => {
        github.release("0.2.0", installer);
        const [subject, status] = await checked();
        expect(status).toEqual({ phase: "ready", version: "0.2.0" });
        const ready = subject.readyInstaller();
        expect(ready?.path).toBe(join(folder, "ubc-vpn-setup-0.2.0-x64.exe"));
        expect(readFileSync(ready?.path ?? "")).toEqual(installer);
        expect(readdirSync(folder)).toEqual(["ubc-vpn-setup-0.2.0-x64.exe"]);
        expect(subject.view().lastChecked).toBe(NOW);
        expect(github.asked[0]).toBe(LATEST_RELEASE_URL);
        expect(hosts().every((host) => GITHUB_HOSTS.has(host))).toBe(true);
    });

    it("with automatic updates off, only says one exists, and downloads once turned on", async () => {
        github.release("0.2.0", installer);
        const subject = updater();
        subject.setAutomatic(false);
        await subject.check();
        expect(subject.view().status).toEqual({ phase: "available", version: "0.2.0" });
        expect(github.asked).not.toContain(github.installerUrl("0.2.0"));
        expect(existsSync(folder)).toBe(false);
        const seen: UpdateStatus[] = [];
        subject.subscribe((view) => seen.push(view.status));
        subject.setAutomatic(true);
        await expect.poll(() => subject.view().status.phase).toBe("ready");
        expect(seen[0]).toEqual({ phase: "downloading", version: "0.2.0" });
    });

    it("does not download the same version again", async () => {
        github.release("0.2.0", installer);
        const subject = updater();
        await subject.check();
        const before = github.asked.length;
        await subject.check();
        expect(subject.view().status).toEqual({ phase: "ready", version: "0.2.0" });
        expect(github.asked.slice(before)).not.toContain(github.installerUrl("0.2.0"));
    });

    it("is up to date with no release, the same version, or an older one", async () => {
        expect((await checked())[1]).toEqual({ phase: "up_to_date" });
        for (const version of ["0.1.0", "0.0.9", "0.1.0-rc.9"]) {
            github = new FakeGitHub();
            github.release(version, installer);
            const [subject, status] = await checked();
            expect(status, version).toEqual({ phase: "up_to_date" });
            expect(subject.readyInstaller()).toBeNull();
            expect(github.asked).not.toContain(github.installerUrl(version));
        }
    });

    it("refuses a list it cannot trust, and downloads nothing", async () => {
        github.release("0.2.0", installer, { signer: makeKey() });
        const [subject, status] = await checked();
        expect(status).toEqual({ phase: "failed", reason: "refused" });
        expect(subject.readyInstaller()).toBeNull();
        expect(github.asked).not.toContain(github.installerUrl("0.2.0"));
    });

    it("refuses a list for another release than the one it came with", async () => {
        // Release v0.3.0 carrying 0.2.0's signed list and installer, as if copied over.
        github.release("0.2.0", installer, { tag: "v0.3.0" });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
        expect(github.asked).not.toContain(github.installerUrl("0.2.0"));
    });

    it("refuses an installer whose checksum is not the list's, and keeps none of it", async () => {
        github.release("0.2.0", installer);
        const swapped = Buffer.from(installer);
        swapped[3] = (swapped[3] ?? 0) ^ 0xff;
        github.answers.set(github.installerUrl("0.2.0"), { body: swapped });
        const [subject, status] = await checked();
        expect(status).toEqual({ phase: "failed", reason: "refused" });
        expect(subject.readyInstaller()).toBeNull();
        expect(readdirSync(folder)).toEqual([]);
    });

    it("stops a download that passes the size the list gives, and keeps none of it", async () => {
        github.release("0.2.0", installer);
        // A download that never ends: it must be cut off near the size, not read whole.
        const { stream, meter } = endless(64 * 1024);
        github.answers.set(github.installerUrl("0.2.0"), { body: stream });
        const [subject, status] = await checked();
        expect(meter.served).toBeLessThanOrEqual(4 * 64 * 1024);
        expect(status).toEqual({ phase: "failed", reason: "refused" });
        expect(subject.readyInstaller()).toBeNull();
        expect(readdirSync(folder)).toEqual([]);
    });

    it("refuses a release description larger than one may be, before reading it", async () => {
        github.release("0.2.0", installer);
        const release = JSON.parse(String(answerBody(LATEST_RELEASE_URL)));
        const padded = JSON.stringify({ ...release, body: "x".repeat(MAX_RELEASE_BYTES) });
        github.answers.set(LATEST_RELEASE_URL, { body: padded });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
        expect(github.asked).toEqual([LATEST_RELEASE_URL]);
    });

    it("refuses a list larger than a list may be", async () => {
        github.release("0.2.0", installer);
        const url = `${DOWNLOADS}/v0.2.0/update-list.json`;
        github.answers.set(url, { body: Buffer.alloc(MAX_LIST_BYTES + 1, 0x20) });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
    });

    it("refuses a release whose asset is not the size the list gives", async () => {
        github.release("0.2.0", installer, {
            list: listBody("0.2.0", Buffer.concat([installer, Buffer.from("x")])),
        });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
        expect(github.asked).not.toContain(github.installerUrl("0.2.0"));
    });

    it("says when GitHub cannot be reached, or answers with something else", async () => {
        github.answers.set(LATEST_RELEASE_URL, () => {
            throw new TypeError("fetch failed");
        });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "offline" });
        github.answers.set(LATEST_RELEASE_URL, { status: 500, body: "oops" });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "github" });
        github.answers.set(LATEST_RELEASE_URL, { body: "{not json" });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "github" });
        expect(updater().view().lastChecked).toBeNull();
    });
});

describe("talking only to GitHub, over HTTPS", () => {
    it("follows a redirect only to HTTPS on GitHub's hosts", async () => {
        for (const location of [
            "http://release-assets.githubusercontent.com/made-up/x.exe",
            "https://downloads.example.test/x.exe",
            "https://github.com.example.test/x.exe",
            "https://release-assets.githubusercontent.com:8443/x.exe",
            "https://someone@release-assets.githubusercontent.com/x.exe",
            "file:///C:/made-up/x.exe",
        ]) {
            github = new FakeGitHub();
            github.release("0.2.0", installer);
            github.answers.set(`${DOWNLOADS}/v0.2.0/ubc-vpn-setup-0.2.0-x64.exe`, {
                status: 302,
                location,
            });
            github.answers.set(location, { body: installer });
            const [subject, status] = await checked();
            expect(status, location).toEqual({ phase: "failed", reason: "refused" });
            expect(github.asked, location).not.toContain(location);
            expect(subject.readyInstaller()).toBeNull();
        }
    });

    it("refuses a redirect it did not check, and too many redirects", async () => {
        github.release("0.2.0", installer);
        github.answers.set(github.installerUrl("0.2.0"), { body: installer, redirected: true });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });

        github = new FakeGitHub();
        github.release("0.2.0", installer);
        const loop = `${ASSETS}/loop`;
        github.answers.set(github.installerUrl("0.2.0"), { status: 302, location: loop });
        github.answers.set(loop, { status: 307, location: loop });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
        // The download's first address and the installer's took two of the hops.
        expect(github.asked.filter((url) => url === loop).length).toBe(MAX_REDIRECTS - 1);
    });

    it("uses only assets of this repository's releases on github.com", async () => {
        for (const link of [
            "https://github.com/someone-else/ubc-vpn/releases/download/v0.2.0/update-list.json",
            "http://github.com/Nima-Hs/ubc-vpn/releases/download/v0.2.0/update-list.json",
            "https://objects.githubusercontent.com/Nima-Hs/ubc-vpn/releases/download/v0.2.0/update-list.json",
        ]) {
            const body = JSON.stringify({
                tag_name: "v0.2.0",
                draft: false,
                assets: [{ name: "update-list.json", size: 10, browser_download_url: link }],
            });
            github.answers.set(LATEST_RELEASE_URL, { body });
            github.answers.set(link, { body: signList(listBody("0.2.0", installer), key) });
            expect((await checked())[1], link).toEqual({ phase: "failed", reason: "refused" });
            expect(github.asked, link).not.toContain(link);
        }
    });

    it("reads only HTTPS addresses on GitHub's hosts", () => {
        expect(githubUrl("https://api.github.com/repos")).not.toBeNull();
        for (const text of [
            "http://api.github.com/repos",
            "https://api.github.com:444/repos",
            "https://user:pass@api.github.com/repos",
            "https://api.github.com.example.test/repos",
            "https://example.test/https://api.github.com/",
            "not a url",
        ]) {
            expect(githubUrl(text), text).toBeNull();
        }
    });
});

describe("when the app checks", () => {
    it("checks soon after start, then every four hours", () => {
        const asked: number[][] = [];
        const schedule = (_run: () => void, first: number, then: number) => {
            asked.push([first, then]);
            return () => {};
        };
        updater({ schedule }).start();
        expect(asked).toEqual([[FIRST_CHECK_MS, CHECK_INTERVAL_MS]]);
        expect(CHECK_INTERVAL_MS).toBe(4 * 60 * 60 * 1000);
    });

    it("never reaches the network in a copy that cannot update", async () => {
        github.release("0.2.0", installer);
        const placeholder = [{ label: "placeholder", publicKey: PLACEHOLDER_KEY }];
        for (const change of [
            { packaged: false },
            { keys: placeholder },
            { platform: null },
            { folder: null },
        ]) {
            let scheduled = false;
            const subject = updater({
                ...change,
                schedule: () => {
                    scheduled = true;
                    return () => {};
                },
            });
            subject.start();
            await subject.check();
            expect(subject.view().status, JSON.stringify(change)).toEqual({ phase: "unavailable" });
            expect(scheduled).toBe(false);
        }
        expect(github.asked).toEqual([]);
    });

    it("names this system as update lists do", () => {
        expect(updatePlatform("win32", "x64")).toBe("windows-x64");
        // macOS and Linux follow once the app can install their packages (#330).
        expect(updatePlatform("darwin", "arm64")).toBeNull();
        expect(updatePlatform("win32", "arm64")).toBeNull();
        expect(updatePlatform("linux", "x64")).toBeNull();
    });
});

describe("where installers are kept", () => {
    it("is a folder of the app's own in the user's local profile", () => {
        expect(
            updatesFolder("win32", { LOCALAPPDATA: "C:\\Users\\someone\\AppData\\Local" }, ""),
        ).toBe("C:\\Users\\someone\\AppData\\Local\\UBC VPN\\updates");
        expect(updatesFolder("win32", {}, "C:\\Users\\someone")).toBeNull();
        expect(updatesFolder("win32", { LOCALAPPDATA: "relative" }, "")).toBeNull();
        // Each system's own paths, whichever system the test runs on.
        expect(updatesFolder("darwin", {}, "/Users/someone")).toBe(
            "/Users/someone/Library/Caches/UBC VPN/updates",
        );
        expect(updatesFolder("linux", { XDG_CACHE_HOME: "/cache" }, "/home/someone")).toBe(
            "/cache/ubc-vpn/updates",
        );
        expect(updatesFolder("linux", { XDG_CACHE_HOME: "cache" }, "/home/someone")).toBe(
            "/home/someone/.cache/ubc-vpn/updates",
        );
    });

    it.skipIf(process.platform === "win32")(
        "is refused on macOS and Linux when others can write to it",
        async () => {
            const { chmod } = await import("node:fs/promises");
            await prepareFolder(folder);
            await chmod(folder, 0o777);
            await expect(prepareFolder(folder)).rejects.toThrow(/alone/);
        },
    );

    it("is emptied before a download, so nothing left there is used", async () => {
        github.release("0.2.0", installer);
        await prepareFolder(folder);
        const { writeFileSync } = await import("node:fs");
        writeFileSync(join(folder, "ubc-vpn-setup-0.2.0-x64.exe"), "left behind");
        writeFileSync(join(folder, "ubc-vpn-setup-0.2.0-x64.exe.part"), "left behind");
        const [subject] = await checked();
        expect(readFileSync(subject.readyInstaller()?.path ?? "")).toEqual(installer);
        expect(readdirSync(folder)).toEqual(["ubc-vpn-setup-0.2.0-x64.exe"]);
    });
});

describe("what the interface may ask, and is told", () => {
    it("asks with no arguments", () => {
        expect(() => takeNothing([])).not.toThrow();
        expect(() => takeNothing([1])).toThrow("refused");
        expect(() => takeNothing([undefined])).toThrow("refused");
    });

    it("has words for every state, without exclamation marks", () => {
        const statuses: UpdateStatus[] = [
            { phase: "unavailable" },
            { phase: "checking" },
            { phase: "up_to_date" },
            { phase: "available", version: "0.2.0" },
            { phase: "downloading", version: "0.2.0" },
            { phase: "ready", version: "0.2.0" },
            ...(["offline", "github", "refused", "disk"] as const).map(
                (reason): UpdateStatus => ({ phase: "failed", reason }),
            ),
        ];
        const said = statuses.map((status) => describeUpdate(status) ?? "");
        expect(new Set(said).size).toBe(statuses.length);
        for (const text of said) {
            expect(text).toMatch(/^[A-Z]/);
            expect(text).not.toContain("!");
        }
        expect(describeUpdate({ phase: "idle" })).toBeNull();
    });
});

describe("what the settings allow", () => {
    it("downloads nothing until the settings say Automatic updates are on", async () => {
        github.release("0.2.0", installer);
        // The settings could not be read: off is respected, as is unknown.
        const subject = updater({}, null);
        await subject.check();
        expect(subject.view().status).toEqual({ phase: "available", version: "0.2.0" });
        expect(github.asked).not.toContain(github.installerUrl("0.2.0"));
        subject.setAutomatic(true);
        await expect.poll(() => subject.view().status.phase).toBe("ready");
    });

    it("tries a failed download once, not again with every view of the settings", async () => {
        github.release("0.2.0", installer);
        const swapped = Buffer.from(installer);
        swapped[0] = (swapped[0] ?? 0) ^ 1;
        github.answers.set(github.installerUrl("0.2.0"), { body: swapped });
        const subject = updater({}, false);
        await subject.check();
        subject.setAutomatic(true);
        await expect.poll(() => subject.view().status.phase).toBe("failed");
        // More views of the settings, all saying on.
        subject.setAutomatic(true);
        subject.setAutomatic(true);
        await new Promise((done) => setTimeout(done, 20));
        const fetched = () =>
            github.asked.filter((url) => url === github.installerUrl("0.2.0")).length;
        expect(fetched()).toBe(1);
        // Nor when the setting is turned off and on again.
        subject.setAutomatic(false);
        subject.setAutomatic(true);
        await new Promise((done) => setTimeout(done, 20));
        expect(fetched()).toBe(1);
        // The next check tries again.
        await subject.check();
        expect(fetched()).toBe(2);
    });
});

describe("one thing at a time", () => {
    it("starts no second check or download while one is under way", async () => {
        github.release("0.2.0", installer);
        let release: () => void = () => {};
        const held = new Promise<void>((done) => {
            release = done;
        });
        const slow: Fetch = async (url, init) => {
            if (url === github.installerUrl("0.2.0")) {
                await held;
            }
            return github.fetch(url, init);
        };
        const subject = updater({ fetch: slow }, false);
        await subject.check();
        subject.setAutomatic(true);
        await expect.poll(() => subject.view().status.phase).toBe("downloading");
        await subject.check();
        subject.setAutomatic(false);
        subject.setAutomatic(true);
        release();
        await expect.poll(() => subject.view().status.phase).toBe("ready");
        expect(github.asked.filter((url) => url === LATEST_RELEASE_URL).length).toBe(1);
        expect(github.asked.filter((url) => url === github.installerUrl("0.2.0")).length).toBe(1);
    });
});

describe("one thing at a time, when the setting changes during a check", () => {
    it("does not start a download beside a check under way", async () => {
        github.release("0.2.0", installer);
        let hold = false;
        let release: () => void = () => {};
        const held = new Promise<void>((done) => {
            release = done;
        });
        const slow: Fetch = async (url, init) => {
            if (hold && url === LATEST_RELEASE_URL) {
                await held;
            }
            return github.fetch(url, init);
        };
        const subject = updater({ fetch: slow }, false);
        await subject.check();
        expect(subject.view().status.phase).toBe("available");
        hold = true;
        const second = subject.check();
        await expect.poll(() => subject.view().status.phase).toBe("checking");
        subject.setAutomatic(true);
        release();
        await second;
        await expect.poll(() => subject.view().status.phase).toBe("ready");
        expect(github.asked.filter((url) => url === github.installerUrl("0.2.0")).length).toBe(1);
    });
});

describe("limits on what GitHub sends", () => {
    it("stops reading a release description at its limit, while it streams", async () => {
        const { stream, meter } = endless(64 * 1024);
        github.answers.set(LATEST_RELEASE_URL, { body: stream });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
        expect(meter.served).toBeLessThanOrEqual(MAX_RELEASE_BYTES + 64 * 1024);
    });

    it("cuts an installer off at one chunk past the size the list gives", async () => {
        github.release("0.2.0", installer);
        // Each chunk is a write to disk, so this one stops much sooner.
        const { stream, meter } = endless(4, 64 * 1024);
        github.answers.set(github.installerUrl("0.2.0"), { body: stream });
        expect((await checked())[1]).toEqual({ phase: "failed", reason: "refused" });
        expect(meter.served).toBeLessThanOrEqual(installer.length + 4);
    });

    it("gives up on a body that goes quiet", async () => {
        github.release("0.2.0", installer);
        const quiet = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new Uint8Array(1));
            },
        });
        github.answers.set(github.installerUrl("0.2.0"), { body: quiet });
        const timeouts = { checkMs: 5_000, downloadMs: 5_000, idleMs: 50 };
        expect((await checked({ timeouts }))[1]).toEqual({ phase: "failed", reason: "offline" });
        expect(readdirSync(folder)).toEqual([]);
    });

    it("gives every request a time limit", async () => {
        github.release("0.2.0", installer);
        const signals: (AbortSignal | null | undefined)[] = [];
        const watching: Fetch = (url, init) => {
            signals.push(init.signal);
            return github.fetch(url, init);
        };
        await checked({ fetch: watching });
        expect(signals.length).toBeGreaterThanOrEqual(3);
        expect(signals.every((signal) => signal instanceof AbortSignal)).toBe(true);
    });

    it("follows no redirect to GitHub's other content hosts", async () => {
        for (const host of ["raw.githubusercontent.com", "gist.githubusercontent.com"]) {
            const location = `https://${host}/made-up/x.exe`;
            github = new FakeGitHub();
            github.release("0.2.0", installer);
            github.answers.set(github.installerUrl("0.2.0"), { status: 302, location });
            github.answers.set(location, { body: installer });
            expect((await checked())[1], host).toEqual({ phase: "failed", reason: "refused" });
            expect(github.asked).not.toContain(location);
        }
    });

    it.skipIf(process.platform === "win32")(
        "refuses an updates folder that is a link to somewhere else",
        async () => {
            const { mkdir, symlink } = await import("node:fs/promises");
            const elsewhere = join(folder, "..", "elsewhere");
            await mkdir(elsewhere, { mode: 0o700 });
            await symlink(elsewhere, folder);
            await expect(prepareFolder(folder)).rejects.toThrow(/alone/);
        },
    );
});

describe("which runs may update", () => {
    it("needs a release build as well as an installed app", () => {
        expect(mayUpdate({ packaged: true, release: true, demo: false })).toBe(true);
        // ELECTRON_FORCE_IS_PACKAGED makes any run claim to be installed.
        expect(mayUpdate({ packaged: true, release: false, demo: false })).toBe(false);
        expect(mayUpdate({ packaged: false, release: true, demo: false })).toBe(false);
        expect(mayUpdate({ packaged: true, release: true, demo: true })).toBe(false);
    });

    it("is a release build only when built for the installer", () => {
        const root = join(__dirname, "..");
        const config = readFileSync(join(root, "electron.vite.config.ts"), "utf8");
        expect(config).toContain('__RELEASE__: JSON.stringify(mode === "release")');
        const scripts: Record<string, string> = JSON.parse(
            readFileSync(join(root, "package.json"), "utf8"),
        ).scripts;
        expect(scripts["build:release"]).toBe("electron-vite build --mode release");
        expect(scripts["package:win"]).toContain("pnpm build:release");
        // Every other build, the tests' included, is not one.
        for (const [name, script] of Object.entries(scripts)) {
            if (name !== "build:release") {
                expect(script.includes("--mode release"), name).toBe(false);
            }
        }
    });
});
