// What "Restart to update" leaves for the next start, and what that start does
// with it. The note says which version was being installed, when, and which
// connection to bring back. It holds no secret. No Electron import: everything
// else is passed in, so the rules are tested on their own.

import { constants } from "node:fs";
import { open, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { LinkState } from "@shared/api";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { AfterUpdateNotice } from "@shared/updates";
import { isProfileId } from "../channel/validate";
import { parseVersion } from "./semver";

export const RESUME_NOTE = "resume.json";
/** Far more than a note needs. Past this it is not read. */
export const MAX_NOTE_BYTES = 1024;
/** A note older than this connects nothing: whoever left it has moved on. */
export const STALE_NOTE_MS = 24 * 60 * 60 * 1000;
/** How long a start waits for the service before it says it could not reconnect. */
export const SERVICE_WAIT_MS = 60_000;
/**
 * Copies older than this are cleared at start. It is longer than the launcher
 * waits for the setup program, and Windows refuses to delete a program that is
 * still running, so a copy in use is never removed.
 */
export const OLD_COPY_MS = 15 * 60 * 1000;

export interface ResumeNote {
    /** The version being installed. */
    target: string;
    /** When, in milliseconds since 1970. */
    at: number;
    /** Whether a connection was taken down for it. */
    connected: boolean;
    /** The profile that connection was for, or `null` if the app does not know. */
    profile: ProfileId | null;
}

export async function leaveNote(folder: string, note: ResumeNote): Promise<void> {
    await writeFile(join(folder, RESUME_NOTE), `${JSON.stringify(note)}\n`, { mode: 0o600 });
}

/** Removes the note, or whatever is in its place. Never fails. */
export async function clearNote(folder: string): Promise<void> {
    await rm(join(folder, RESUME_NOTE), { recursive: true, force: true }).catch(() => {});
}

function readNoteText(text: string): ResumeNote | null {
    let value: unknown;
    try {
        value = JSON.parse(text);
    } catch {
        return null;
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return null;
    }
    if (Object.keys(value).sort().join() !== "at,connected,profile,target") {
        return null;
    }
    const { target, at, connected, profile } = value as Record<string, unknown>;
    const fits =
        typeof target === "string" &&
        parseVersion(target) !== null &&
        typeof at === "number" &&
        Number.isSafeInteger(at) &&
        typeof connected === "boolean" &&
        (profile === null || (typeof profile === "string" && isProfileId(profile)));
    return fits ? { target, at, connected, profile: profile as ProfileId | null } : null;
}

/**
 * The note, or `null` if there is none or it is not exactly a note: too long,
 * another shape, or not a file at all. Never fails.
 */
export async function readNote(folder: string): Promise<ResumeNote | null> {
    let file: Awaited<ReturnType<typeof open>> | undefined;
    try {
        file = await open(join(folder, RESUME_NOTE), constants.O_RDONLY);
        const info = await file.stat();
        if (!info.isFile() || info.size > MAX_NOTE_BYTES) {
            return null;
        }
        const bytes = Buffer.alloc(MAX_NOTE_BYTES);
        const { bytesRead } = await file.read(bytes, 0, MAX_NOTE_BYTES, 0);
        return readNoteText(bytes.subarray(0, bytesRead).toString("utf8"));
    } catch {
        return null;
    } finally {
        await file?.close().catch(() => {});
    }
}

/** What a start should do about a note. */
export interface ResumePlan {
    /** What to tell the user, whatever else happens. */
    notice: AfterUpdateNotice | null;
    /** Whether to bring a connection back. */
    reconnect: boolean;
    profile: ProfileId | null;
}

/** Decides from the note, the running version and the time. Pure. */
export function planResume(note: ResumeNote, version: string, now: number): ResumePlan {
    const age = now - note.at;
    if (age < 0 || age > STALE_NOTE_MS) {
        return { notice: "stale", reconnect: false, profile: null };
    }
    return {
        notice: version === note.target ? null : "unfinished",
        reconnect: note.connected,
        profile: note.profile,
    };
}

export interface ReconnectSteps {
    /** The profiles there are now, or `null` if they cannot be read. */
    profileIds(): Promise<readonly string[] | null>;
    /** Brings the window forward: a login may have a question to ask. */
    show(): void;
    /** Starts a login for this profile; `false` if one is still under way. */
    connect(profile: ProfileId): boolean;
    say(notice: AfterUpdateNotice): void;
}

/**
 * Brings back the connection that was up, for the profile it was for and no
 * other. If that cannot be done it connects nothing, and says why. Never fails.
 */
export async function reconnectTo(profile: ProfileId | null, steps: ReconnectSteps): Promise<void> {
    if (profile === null) {
        steps.say("reconnect_unknown");
        return;
    }
    const ids = await steps.profileIds().catch(() => null);
    if (ids === null) {
        steps.say("reconnect_unavailable");
        return;
    }
    if (!ids.includes(profile)) {
        steps.say("profile_gone");
        return;
    }
    steps.show();
    if (!steps.connect(profile)) {
        steps.say("reconnect_busy");
    }
}

/**
 * The profile a connection was for: the one the app started it for. A
 * connection the app did not start, say from before it last opened, is known
 * only when there is just one profile it can be.
 */
export function knownProfile(
    started: ProfileId | null,
    ids: readonly ProfileId[] | null,
): ProfileId | null {
    if (started !== null) {
        return started;
    }
    const [only, other] = ids ?? [];
    return only !== undefined && other === undefined ? only : null;
}

/** Resolves when `ready` is true of the state, or with `false` when the limit passes. */
export function waitFor(
    link: { state(): LinkState; subscribe(listener: () => void): () => void },
    ready: (state: LinkState) => boolean,
    limitMs: number,
): Promise<boolean> {
    if (ready(link.state())) {
        return Promise.resolve(true);
    }
    return new Promise((done) => {
        const finish = (result: boolean) => {
            clearTimeout(timer);
            stop();
            done(result);
        };
        const timer = setTimeout(() => finish(false), limitMs);
        const stop = link.subscribe(() => {
            if (ready(link.state())) {
                finish(true);
            }
        });
    });
}

export interface ResumeSteps extends ReconnectSteps {
    folder: string;
    version: string;
    now(): number;
    state(): LinkState;
    subscribe(listener: () => void): () => void;
    serviceWaitMs?: number;
}

/**
 * Acts on the note at start. It is removed only once it has been acted on: if
 * the service cannot be reached yet it stays for a later start, within its time
 * limit, and the user is told. Returns whether this start deals with connecting,
 * so nothing else connects as well. Never fails.
 */
export async function resumeAtStart(steps: ResumeSteps): Promise<boolean> {
    await clearOldCopies(steps.folder, steps.now());
    const note = await readNote(steps.folder);
    if (note === null) {
        await clearNote(steps.folder);
        return false;
    }
    const plan = planResume(note, steps.version, steps.now());
    if (plan.notice !== null) {
        steps.say(plan.notice);
    }
    if (!plan.reconnect) {
        await clearNote(steps.folder);
        return false;
    }
    const reached = await waitFor(
        steps,
        (state) => state.link === "ready",
        steps.serviceWaitMs ?? SERVICE_WAIT_MS,
    );
    if (!reached) {
        steps.say("reconnect_unavailable");
        return false;
    }
    await clearNote(steps.folder);
    const state = steps.state();
    if (state.link === "ready" && state.conn.state === "disconnected") {
        await reconnectTo(plan.profile, steps);
    }
    return true;
}

/** Removes copies of the installer left from earlier runs. Never fails. */
export async function clearOldCopies(folder: string, now: number): Promise<void> {
    const names = await readdir(folder).catch((): string[] => []);
    for (const name of names) {
        if (!name.startsWith("run-")) {
            continue;
        }
        const path = join(folder, name);
        try {
            if (now - (await stat(path)).mtimeMs > OLD_COPY_MS) {
                await rm(path, { recursive: true, force: true });
            }
        } catch {
            // In use, or gone already: the next start tries again.
        }
    }
}
