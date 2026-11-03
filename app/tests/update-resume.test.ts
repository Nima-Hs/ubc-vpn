// What a start does with the note an update left. Only a fresh temporary folder
// is touched, and "connecting" here is a recorded call.

import { existsSync, readdirSync, utimesSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { LinkState } from "@shared/api";
import type { AfterUpdateNotice } from "@shared/updates";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Controller } from "../src/main/controller";
import type { ServiceLink } from "../src/main/link";
import {
    clearOldCopies,
    knownProfile,
    leaveNote,
    MAX_NOTE_BYTES,
    OLD_COPY_MS,
    planResume,
    RESUME_NOTE,
    type ResumeNote,
    readNote,
    reconnectTo,
    resumeAtStart,
    STALE_NOTE_MS,
} from "../src/main/update/resume";

const CAMPUS = "0123456789abcdef0123456789abcdef";
const LAB = "fedcba9876543210fedcba9876543210";
const NOW = 1_800_000_000_000;
const NOTE: ResumeNote = { target: "0.2.0", at: NOW - 1000, connected: true, profile: CAMPUS };
const DISCONNECTED = { link: "ready", conn: { state: "disconnected" } } as LinkState;

let folder: string;
beforeEach(async () => {
    folder = join(await mkdtemp(join(tmpdir(), "upd-resume-")), "updates");
    await mkdir(folder);
});
afterEach(async () => {
    await rm(dirname(folder), { recursive: true, force: true });
});

describe("reading the note", () => {
    const write = (value: unknown) => writeFile(join(folder, RESUME_NOTE), JSON.stringify(value));

    it("reads back what was left", async () => {
        await leaveNote(folder, NOTE);
        await expect(readNote(folder)).resolves.toEqual(NOTE);
        await leaveNote(folder, { ...NOTE, connected: false, profile: null });
        await expect(readNote(folder)).resolves.toMatchObject({ profile: null });
    });

    it("is nothing when there is no note, or no folder", async () => {
        await expect(readNote(folder)).resolves.toBeNull();
        await expect(readNote(join(folder, "missing"))).resolves.toBeNull();
    });

    it("refuses a note over the size limit, even a well-formed one", async () => {
        const long = `${JSON.stringify(NOTE)}${" ".repeat(MAX_NOTE_BYTES)}`;
        await writeFile(join(folder, RESUME_NOTE), long);
        await expect(readNote(folder)).resolves.toBeNull();
    });

    it("refuses extra fields, missing fields and wrong types", async () => {
        for (const bad of [
            { ...NOTE, extra: 1 },
            { target: NOTE.target, at: NOTE.at, connected: true },
            { ...NOTE, target: "not a version" },
            { ...NOTE, target: 2 },
            { ...NOTE, at: "soon" },
            { ...NOTE, at: 1.5 },
            { ...NOTE, connected: "yes" },
            { ...NOTE, profile: "not an id" },
            { ...NOTE, profile: 7 },
            [NOTE],
            "text",
            null,
        ]) {
            await write(bad);
            await expect(readNote(folder), JSON.stringify(bad)).resolves.toBeNull();
        }
        await writeFile(join(folder, RESUME_NOTE), "{not json");
        await expect(readNote(folder)).resolves.toBeNull();
    });

    it("does not fail when something other than a file is in its place", async () => {
        await mkdir(join(folder, RESUME_NOTE));
        await expect(readNote(folder)).resolves.toBeNull();
    });
});

describe("what a start makes of the note", () => {
    it("reconnects that profile when the update took", () => {
        expect(planResume(NOTE, "0.2.0", NOW)).toEqual({
            notice: null,
            reconnect: true,
            profile: CAMPUS,
        });
    });

    it("says an update did not finish, and still brings the connection back", () => {
        expect(planResume(NOTE, "0.1.0", NOW)).toEqual({
            notice: "unfinished",
            reconnect: true,
            profile: CAMPUS,
        });
    });

    it("has nothing to reconnect when nothing was connected", () => {
        const plain = { ...NOTE, connected: false, profile: null };
        expect(planResume(plain, "0.2.0", NOW)).toEqual({
            notice: null,
            reconnect: false,
            profile: null,
        });
    });

    it("connects nothing from a note over a day old, or from the future", () => {
        const stale = { notice: "stale", reconnect: false, profile: null };
        const atLimit = { ...NOTE, at: NOW - STALE_NOTE_MS };
        expect(planResume(atLimit, "0.2.0", NOW).reconnect).toBe(true);
        expect(planResume({ ...NOTE, at: atLimit.at - 1 }, "0.2.0", NOW)).toEqual(stale);
        expect(planResume({ ...NOTE, at: NOW + 1 }, "0.2.0", NOW)).toEqual(stale);
    });
});

/** What reconnecting needs, recording what is done, in order. */
function reconnecting(ids: string[] | null = [CAMPUS, LAB], starts = true) {
    const done: string[] = [];
    const said: AfterUpdateNotice[] = [];
    return {
        done,
        said,
        steps: {
            profileIds: async () => ids,
            show: () => done.push("show"),
            connect: (profile: string) => {
                done.push(`connect ${profile}`);
                return starts;
            },
            say: (notice: AfterUpdateNotice) => said.push(notice),
        },
    };
}

describe("bringing a connection back", () => {
    it("connects the profile that was connected, with the window forward first", async () => {
        const { done, said, steps } = reconnecting();
        await reconnectTo(LAB, steps);
        expect(done).toEqual(["show", `connect ${LAB}`]);
        expect(said).toEqual([]);
    });

    it("connects nothing, and says so, when the profile is gone", async () => {
        const { done, said, steps } = reconnecting([CAMPUS]);
        await reconnectTo(LAB, steps);
        expect(done).toEqual([]);
        expect(said).toEqual(["profile_gone"]);
    });

    it("connects nothing, and says so, when it does not know the profile", async () => {
        const { done, said, steps } = reconnecting();
        await reconnectTo(null, steps);
        expect(done).toEqual([]);
        expect(said).toEqual(["reconnect_unknown"]);
    });

    it("connects nothing, and says so, when the profiles cannot be read", async () => {
        const { done, said, steps } = reconnecting(null);
        await reconnectTo(CAMPUS, steps);
        expect(done).toEqual([]);
        expect(said).toEqual(["reconnect_unavailable"]);
        const failing = reconnecting();
        failing.steps.profileIds = async () => {
            throw new Error("no client");
        };
        await reconnectTo(CAMPUS, failing.steps);
        expect(failing.said).toEqual(["reconnect_unavailable"]);
    });

    it("says so when a login still ending stops the reconnect", async () => {
        const { said, steps } = reconnecting([CAMPUS], false);
        await reconnectTo(CAMPUS, steps);
        expect(said).toEqual(["reconnect_busy"]);
    });

    it("knows the profile of a connection it did not start only if it can be just one", () => {
        expect(knownProfile(LAB, [CAMPUS, LAB])).toBe(LAB);
        expect(knownProfile(null, [CAMPUS])).toBe(CAMPUS);
        expect(knownProfile(null, [CAMPUS, LAB])).toBeNull();
        expect(knownProfile(null, null)).toBeNull();
        expect(knownProfile(null, [])).toBeNull();
    });
});

describe("the start after an update", () => {
    function start(state: LinkState, ids = [CAMPUS, LAB], serviceWaitMs = 2_000) {
        const fake = reconnecting(ids);
        const listeners = new Set<() => void>();
        const current = { state };
        return {
            ...fake,
            current,
            tell: () => {
                for (const listener of [...listeners]) {
                    listener();
                }
            },
            run: () =>
                resumeAtStart({
                    ...fake.steps,
                    folder,
                    version: "0.2.0",
                    now: () => NOW,
                    state: () => current.state,
                    subscribe: (listener) => {
                        listeners.add(listener);
                        return () => listeners.delete(listener);
                    },
                    serviceWaitMs,
                }),
        };
    }
    const noted = () => existsSync(join(folder, RESUME_NOTE));

    it("does nothing without a note, and leaves others to connect", async () => {
        const run = start(DISCONNECTED);
        await expect(run.run()).resolves.toBe(false);
        expect(run.done).toEqual([]);
    });

    it("connects the noted profile, uses up the note, and is the only one to connect", async () => {
        await leaveNote(folder, { ...NOTE, profile: LAB });
        const run = start(DISCONNECTED);
        await expect(run.run()).resolves.toBe(true);
        expect(run.done).toEqual(["show", `connect ${LAB}`]);
        expect(noted()).toBe(false);
    });

    it("waits for the service to be reached", async () => {
        await leaveNote(folder, NOTE);
        const run = start({ link: "starting" });
        const resumed = run.run();
        expect(run.done).toEqual([]);
        await vi.waitFor(() => expect(noted()).toBe(true));
        run.current.state = DISCONNECTED;
        await new Promise((done) => setTimeout(done, 20));
        run.tell();
        await expect(resumed).resolves.toBe(true);
        expect(run.done).toEqual(["show", `connect ${CAMPUS}`]);
    });

    it("keeps the note for a later start when the service stays out of reach, and says so", async () => {
        await leaveNote(folder, NOTE);
        const run = start({ link: "unavailable", reason: "not_running" }, [CAMPUS], 30);
        await expect(run.run()).resolves.toBe(false);
        expect(run.done).toEqual([]);
        expect(run.said).toEqual(["reconnect_unavailable"]);
        expect(noted()).toBe(true);
    });

    it("connects nothing on top of a connection already up", async () => {
        await leaveNote(folder, NOTE);
        const run = start({ link: "ready", conn: { state: "connecting" } } as LinkState);
        await expect(run.run()).resolves.toBe(true);
        expect(run.done).toEqual([]);
        expect(noted()).toBe(false);
    });

    it("clears a stale note, says so, and connects nothing", async () => {
        await leaveNote(folder, { ...NOTE, at: NOW - STALE_NOTE_MS - 1 });
        const run = start(DISCONNECTED);
        await expect(run.run()).resolves.toBe(false);
        expect(run.done).toEqual([]);
        expect(run.said).toEqual(["stale"]);
        expect(noted()).toBe(false);
    });

    it("says an update did not finish, then reconnects", async () => {
        await leaveNote(folder, { ...NOTE, target: "0.3.0" });
        const run = start(DISCONNECTED);
        await expect(run.run()).resolves.toBe(true);
        expect(run.said).toEqual(["unfinished"]);
        expect(run.done).toEqual(["show", `connect ${CAMPUS}`]);
    });

    it("clears whatever is in the note's place and carries on", async () => {
        await mkdir(join(folder, RESUME_NOTE));
        await writeFile(join(folder, RESUME_NOTE, "inside"), "x");
        const run = start(DISCONNECTED);
        await expect(run.run()).resolves.toBe(false);
        expect(noted()).toBe(false);
    });
});

describe("old copies of the installer", () => {
    async function copyAged(name: string, ageMs: number) {
        const path = join(folder, name);
        await mkdir(path);
        await writeFile(join(path, "setup.exe"), "x");
        const when = (Date.now() - ageMs) / 1000;
        utimesSync(path, when, when);
    }

    it("go at start, but not one the setup program may still be using, or anything else", async () => {
        await copyAged("run-old", OLD_COPY_MS + 60_000);
        await copyAged("run-recent", 60_000);
        await copyAged("not-a-copy", OLD_COPY_MS + 60_000);
        await writeFile(join(folder, RESUME_NOTE), "note");
        await clearOldCopies(folder, Date.now());
        expect(readdirSync(folder).sort()).toEqual(
            ["not-a-copy", RESUME_NOTE, "run-recent"].sort(),
        );
    });

    it("does not fail without a folder", async () => {
        await expect(clearOldCopies(join(folder, "missing"), Date.now())).resolves.toBeUndefined();
    });
});

describe("which profile a connection is for", () => {
    function setUp() {
        const listeners = new Set<(state: LinkState) => void>();
        let state: LinkState = DISCONNECTED;
        const link = {
            getState: () => state,
            subscribe: (listener: (next: LinkState) => void) => {
                listeners.add(listener);
                return () => listeners.delete(listener);
            },
        } as unknown as ServiceLink;
        const set = (conn: string) => {
            state = { link: "ready", conn: { state: conn } } as unknown as LinkState;
            for (const listener of listeners) {
                listener(state);
            }
        };
        let active = CAMPUS;
        const started: (string | null | undefined)[] = [];
        let busy = false;
        let report: (login: { phase: "idle" }) => void = () => {};
        const controller = new Controller(link, (onState) => {
            report = onState;
            return {
                start: (profile) => {
                    if (busy) {
                        return false;
                    }
                    started.push(profile);
                    return true;
                },
                answer: () => false,
                cancel: () => {},
                stop: () => {},
                windDown: () => null,
            };
        });
        controller.setProfileForLogin(() => active);
        return {
            controller,
            set,
            started,
            choose: (id: string) => {
                active = id;
            },
            setBusy: (value: boolean) => {
                busy = value;
            },
            loginEnded: () => report({ phase: "idle" }),
        };
    }

    it("stays the one it was started for, whichever is chosen while connected", async () => {
        const { controller, set, choose } = setUp();
        await controller.connect();
        set("connecting");
        set("connected");
        choose(LAB);
        expect(controller.connectionProfile()).toBe(CAMPUS);
    });

    it("is forgotten when the connection ends, or a login ends with nothing up", async () => {
        const up = setUp();
        await up.controller.connect();
        up.set("connected");
        up.set("disconnected");
        expect(up.controller.connectionProfile()).toBeNull();
        const failed = setUp();
        await failed.controller.connect();
        failed.loginEnded();
        expect(failed.controller.connectionProfile()).toBeNull();
    });

    it("is kept when a login ends with the connection up", async () => {
        const { controller, set, loginEnded } = setUp();
        await controller.connect();
        set("connected");
        loginEnded();
        expect(controller.connectionProfile()).toBe(CAMPUS);
    });

    it("connects a named profile, not the one chosen, and says when it cannot", () => {
        const { controller, started, setBusy } = setUp();
        expect(controller.connectTo(LAB)).toBe(true);
        expect(started).toEqual([LAB]);
        expect(controller.connectionProfile()).toBe(LAB);
        setBusy(true);
        expect(controller.connectTo(CAMPUS)).toBe(false);
        expect(controller.connectionProfile()).toBe(LAB);
    });
});
