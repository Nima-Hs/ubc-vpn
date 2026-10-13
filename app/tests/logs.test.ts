// The service's log on its way to the interface: every line is checked and
// cleaned in the main process, the app keeps a bounded number of them, and
// the report goes to the clipboard and nowhere else.

import type { LinkState } from "@shared/api";
import { EMPTY_LINE, LOGS_IPC, type LogUpdate, MAX_LOG_LINES, MAX_LOG_TEXT } from "@shared/logs";
import type { LogCursor } from "@shared/protocol/LogCursor";
import type { LogLine } from "@shared/protocol/LogLine";
import { describe, expect, it } from "vitest";
import { createDemoLogs, DEMO_LOG_SCENARIOS } from "../src/main/demo/demo-logs";
import { LogBook, type LogFeed, takeDiagnostics, takeLine, takePage } from "../src/main/logs/book";
import {
    COPY_GAP_MS,
    CopyGate,
    closeWhenAway,
    copyReport,
    logHandlers,
} from "../src/main/logs/ipc";
import { composeReport, REPORT_LINES } from "../src/main/logs/report";
import { pause, until } from "./bridge-harness";

/** Obviously fake. Searched for wherever a secret must not turn up. */
const COOKIE = "Zq7-made-up-0123456789";

const line = (seq: number, text = `line ${seq}`, more: Partial<LogLine> = {}): LogLine => ({
    seq,
    at_unix_ms: 1_800_000_000_000 + seq,
    level: "info",
    source: "service",
    text,
    ...more,
});

const DIAGNOSTICS = {
    service_version: "0.1.0",
    protocol_version: 3,
    os: "linux",
    arch: "x86_64",
    os_version: "6.8",
    uptime_s: 90,
    state: "connected",
    subnets: 2,
    dns_domains: 1,
    last_error: { code: "gateway_unreachable", message: "The gateway did not answer." },
    policy_readable: true,
    gateway: "vpn.example",
    pins: 2,
    owner_claimed: true,
};

/** A pretend service the test steers by hand. */
function service(kept: LogLine[] = [], pageSize = 100) {
    const state = {
        run: 1,
        lines: kept,
        calls: [] as string[],
        listener: null as ((line: unknown) => void) | null,
        reachable: true,
        page: null as unknown,
        /** How often the service was asked for its account of itself. */
        diagnosed: 0,
        /** While set, a page is not answered until this is. */
        hold: null as Promise<void> | null,
        /** The number this run's first line had, and the numbers it no longer holds. */
        firstEver: 0,
        lost: [] as number[],
        /** Writes a line; `tell` says whether the app is sent it as it happens. */
        write(next: LogLine, tell = true) {
            state.lines.push(next);
            if (tell) {
                state.listener?.({ ...next });
            }
        },
        restart(lines: LogLine[], lost: number[] = []) {
            state.run += 1;
            state.lines = lines;
            state.lost = lost;
        },
        /** Lets a line go, as the service does when it is full. */
        lose(seq: number) {
            state.lines = state.lines.filter((held) => held.seq !== seq);
            state.lost.push(seq);
        },
    };
    const feed: LogFeed = {
        watch: async (onLine) => {
            state.calls.push(onLine === null ? "watch off" : "watch on");
            state.listener = onLine;
        },
        fetch: async (after: LogCursor | null) => {
            state.calls.push(
                `fetch ${after === null ? "from the start" : `${after.run}/${after.seq}`}`,
            );
            if (state.hold !== null) {
                await state.hold;
            }
            if (!state.reachable) {
                return null;
            }
            if (state.page !== null) {
                return state.page;
            }
            // As the contract has it: no cursor, or one from another run,
            // is answered from the start of this run, and "dropped" says a
            // line of this run after the cursor existed and is gone. (These
            // tests number from 0 where the service numbers from 1; the app
            // does not depend on which.)
            const known = after !== null && after.run === state.run;
            const from = known ? after.seq : state.firstEver - 1;
            const page = state.lines.filter((held) => held.seq > from).slice(0, pageSize);
            return {
                run: state.run,
                lines: page,
                next: page.at(-1)?.seq ?? Math.max(from, 0),
                dropped: state.lost.some((seq) => seq > from),
            };
        },
        diagnostics: async () => {
            state.diagnosed += 1;
            return state.reachable ? DIAGNOSTICS : null;
        },
    };
    return { state, feed };
}

function book(kept: LogLine[] = [], pageSize = 100) {
    const { state, feed } = service(kept, pageSize);
    const updates: LogUpdate[] = [];
    const opened = new LogBook(feed, (update) => updates.push(update));
    const seqs = () => opened.view().lines.map((held) => held.seq);
    return { state, feed, updates, book: opened, seqs };
}

describe("a line from the service", () => {
    it("is taken when it is exactly a line, as a fresh object", () => {
        const raw = line(4, "CSTP connected", { level: "warn", source: "engine" });
        const taken = takeLine(raw);
        expect(taken).toEqual(raw);
        expect(taken).not.toBe(raw);
    });

    it("has its text made one plain line of bounded length, whatever the service did", () => {
        const dirty = "a\nnewline, a\ttab, a ‮direction override and a bell\u0007";
        expect(takeLine(line(1, dirty))?.text).toBe(
            "a newline, a tab, a direction override and a bell",
        );
        expect(takeLine(line(1, "x".repeat(MAX_LOG_TEXT + 100)))?.text).toHaveLength(MAX_LOG_TEXT);
        // A line that comes to nothing still happened: it keeps its place
        // and says so, where an empty row would say nothing.
        expect(takeLine(line(1, "  \n "))?.text).toBe(EMPTY_LINE);
        expect(takeLine(line(1, "\u{e0041}\u202e"))?.text).toBe(EMPTY_LINE);
        // The tag characters, which are invisible and can spell out text
        // nobody sees, and the line and paragraph separators.
        expect(
            takeLine(line(1, "safe\u{e0001}\u{e0068}\u{e0069}\u{e007f}\u2028\u2029text"))?.text,
        ).toBe("safe text");
    });

    it.each([
        ["nothing", null],
        ["text", "a line"],
        ["a list", [line(1)]],
        ["a field missing", { ...line(1), text: undefined }],
        ["a number that is not whole", line(1.5)],
        ["a negative number", line(-1)],
        ["a number as text", { ...line(1), seq: "1" }],
        ["a number too large to carry exactly", line(2 ** 60)],
        ["a time that is not a number", { ...line(1), at_unix_ms: "now" }],
        ["a level it does not know", { ...line(1), level: "debug" }],
        ["a level that is an object's own word", { ...line(1), level: "constructor" }],
        ["a source it does not know", { ...line(1), source: "kernel" }],
        ["text that is not text", { ...line(1), text: { toString: (): string => "x" } }],
        // The contract has no such field. A line that carries one is refused
        // whole, not passed on without it.
        ["a field the contract does not have", { ...line(1), cookie: COOKIE }],
    ])("is refused when it is %s", (_name, raw) => {
        expect(takeLine(raw)).toBeNull();
    });
});

describe("a page of lines", () => {
    it("is taken with every line cleaned", () => {
        const page = { run: 3, lines: [line(0), line(1, "a\nb")], next: 1, dropped: false };
        expect(takePage(page)).toEqual({ ...page, lines: [line(0), line(1, "a b")] });
    });

    it.each([
        ["nothing", null],
        [
            "one bad line among good ones",
            { run: 1, lines: [line(0), { seq: 1 }], next: 1, dropped: false },
        ],
        ["no run", { lines: [], next: 0, dropped: false }],
        ["a cursor that is not a number", { run: 1, lines: [], next: "0", dropped: false }],
        ["no word on dropped lines", { run: 1, lines: [], next: 0 }],
        ["lines that are not a list", { run: 1, lines: "none", next: 0, dropped: false }],
        ["an extra field", { run: 1, lines: [], next: 0, dropped: false, path: "/home/someone" }],
        [
            "more lines than the app keeps",
            {
                run: 1,
                lines: Array.from({ length: MAX_LOG_LINES + 1 }, (_, seq) => line(seq)),
                next: MAX_LOG_LINES,
                dropped: false,
            },
        ],
    ])("is refused whole when it has %s", (_name, raw) => {
        expect(takePage(raw)).toBeNull();
    });
});

describe("the log the app keeps", () => {
    it("turns watching on before it reads, so nothing written in between is missed", async () => {
        const { book: opened, state } = book([line(0), line(1)]);
        await opened.open();
        expect(state.calls[0]).toBe("watch on");
        expect(state.calls[1]).toBe("fetch from the start");
    });

    it("reads page after page until there is no more, oldest first", async () => {
        const kept = Array.from({ length: 25 }, (_, seq) => line(seq));
        const { book: opened, state, seqs } = book(kept, 10);
        const view = await opened.open();
        expect(view.available).toBe(true);
        expect(seqs()).toEqual(kept.map((held) => held.seq));
        // Three pages of lines, and the empty one that says that is all.
        expect(state.calls.filter((call) => call.startsWith("fetch"))).toEqual([
            "fetch from the start",
            "fetch 1/9",
            "fetch 1/19",
            "fetch 1/24",
        ]);
    });

    it("adds each new line as it is written, and tells the interface", async () => {
        const { book: opened, state, updates, seqs } = book([line(0)]);
        await opened.open();
        updates.length = 0;
        state.write(line(1));
        state.write(line(2, "a\nb"));
        expect(seqs()).toEqual([0, 1, 2]);
        expect(updates.map((update) => update.lines.map((held) => held.text))).toEqual([
            ["line 1"],
            ["a b"],
        ]);
        expect(updates.every((update) => !update.reset)).toBe(true);
    });

    it("takes a line once, though it came in a page and again as it was written", async () => {
        const { book: opened, state, updates, seqs } = book([line(0), line(1)]);
        await opened.open();
        updates.length = 0;
        const fetches = state.calls.length;
        state.listener?.(line(1));
        state.listener?.(line(0));
        await pause(20);
        expect(seqs()).toEqual([0, 1]);
        expect(updates).toEqual([]);
        // A plain duplicate is not a reason to read again.
        expect(state.calls).toHaveLength(fetches);
    });

    it("reads again when a number is missing, because the service dropped a line", async () => {
        const { book: opened, state, seqs } = book([line(0)]);
        await opened.open();
        // The service wrote 1 and 2 but could only deliver 2.
        state.write(line(1), false);
        state.write(line(2));
        await until(() => seqs().length === 3, "the missing line being read");
        expect(seqs()).toEqual([0, 1, 2]);
        expect(state.calls.at(-1)).toMatch(/^fetch 1\//);
    });

    it("reads a gap again once, then accepts it and marks the line after it", async () => {
        const { book: opened, state, updates, seqs } = book([line(0), line(1)]);
        await opened.open();
        updates.length = 0;
        // The service wrote 2, 3 and 4, could deliver only 4, and has
        // already let 2 and 3 go: login lines and the rest are kept apart,
        // and each kind is let go by itself.
        state.write(line(2), false);
        state.write(line(3), false);
        state.lose(2);
        state.lose(3);
        state.write(line(4));
        await until(() => seqs().includes(4), "the line after the gap");
        expect(seqs()).toEqual([0, 1, 4]);
        // The line after the gap says lines before it are no longer kept;
        // the start of the log is whole, so that is not said of it.
        expect(opened.view().lines.map((held) => held.gap)).toEqual([undefined, undefined, true]);
        expect(opened.view().dropped).toBe(false);
        expect(updates.flatMap((update) => update.lines).find((held) => held.seq === 4)?.gap).toBe(
            true,
        );
        // Read once for the gap, and not again: the lines that follow are
        // simply added, with no mark and no more asking.
        await pause(30);
        const asked = state.calls.length;
        state.write(line(5));
        state.write(line(6));
        await pause(30);
        expect(seqs()).toEqual([0, 1, 4, 5, 6]);
        expect(opened.view().lines.at(-1)?.gap).toBeUndefined();
        expect(state.calls).toHaveLength(asked);
    });

    it("tells a hole in the middle from the start of the log having gone", async () => {
        // The first page already has a hole in it, and the start is whole.
        const middle = book([line(1), line(2), line(6), line(7)]);
        middle.state.firstEver = 1;
        middle.state.lost.push(3, 4, 5);
        const withHole = await middle.book.open();
        expect(withHole.dropped).toBe(false);
        expect(withHole.lines.map((held) => held.gap)).toEqual([
            undefined,
            undefined,
            true,
            undefined,
        ]);
        // Here the start has gone and the rest is whole.
        const start = book([line(40), line(41)]);
        start.state.firstEver = 1;
        start.state.lost.push(1, 2, 3);
        const withoutStart = await start.book.open();
        expect(withoutStart.dropped).toBe(true);
        expect(withoutStart.lines.some((held) => held.gap === true)).toBe(false);
    });

    it("asks once when the lines after a gap have all gone too, and marks the next line to come", async () => {
        const { book: opened, state, seqs } = book([line(0)]);
        await opened.open();
        // Lines 1 and 2 were written and let go before the app could read them.
        state.lost.push(1, 2);
        const asked = state.calls.length;
        state.listener?.(line(2));
        await pause(30);
        expect(seqs()).toEqual([0]);
        // One page was asked for. It said lines had gone and brought none,
        // and that was the end of it: no asking again and again.
        expect(state.calls.slice(asked)).toEqual(["fetch 1/0"]);
        state.lines.push(line(3));
        state.listener?.(line(3));
        await until(() => seqs().includes(3), "the next line");
        expect(opened.view().lines.at(-1)).toMatchObject({ seq: 3, gap: true });
    });

    it("takes a number once, though one page brings it twice", async () => {
        const { book: opened, state, seqs } = book();
        state.page = {
            run: 1,
            lines: [line(3), line(1), line(3), line(2), line(1)],
            next: 3,
            dropped: false,
        };
        const first = opened.open();
        await pause(20);
        state.page = null;
        state.lines = [line(1), line(2), line(3)];
        await first;
        expect(seqs()).toEqual([1, 2, 3]);
    });

    it("turns watching on once, however many times it is opened at once", async () => {
        const { book: opened, state } = book([line(0)]);
        const views = await Promise.all(Array.from({ length: 50 }, () => opened.open()));
        expect(state.calls.filter((call) => call === "watch on")).toHaveLength(1);
        expect(views.every((view) => view.lines.length === 1)).toBe(true);
        // Opened again while open, it is still the one watch.
        await opened.open();
        expect(state.calls.filter((call) => call === "watch on")).toHaveLength(1);
        // And closing something that is not open asks the service nothing.
        await opened.close();
        await opened.close();
        expect(state.calls.filter((call) => call === "watch off")).toHaveLength(1);
        expect(opened.isOpen()).toBe(false);
    });

    it("does not take a watched line while a reading is under way", async () => {
        const { book: opened, state, updates } = book([line(0), line(1)]);
        await opened.open();
        updates.length = 0;
        // The service starts again. A reading is asked for and is slow to be
        // answered. Meanwhile a line of the new run arrives whose number
        // happens to follow the last one held from the old run.
        let answer = () => {};
        state.hold = new Promise<void>((resolve) => {
            answer = resolve;
        });
        state.restart([line(0, "new run"), line(1, "new run"), line(2, "new run")]);
        state.listener?.(line(9, "new run"));
        await pause(20);
        state.listener?.(line(2, "new run"));
        await pause(20);
        // Taken now, it would sit after the old run's lines as if it followed them.
        expect(updates).toEqual([]);
        expect(opened.view().lines.map((held) => held.text)).toEqual(["line 0", "line 1"]);
        state.hold = null;
        answer();
        await until(() => updates.length > 0, "the reading being answered");
        expect(updates[0]?.reset).toBe(true);
        expect(opened.view().lines.every((held) => held.text === "new run")).toBe(true);
    });

    it("orders by number, never by time", async () => {
        const early = line(1, "written second", { at_unix_ms: 1000 });
        const late = line(0, "written first", { at_unix_ms: 9000 });
        const { book: opened } = book([late, early]);
        const view = await opened.open();
        expect(view.lines.map((held) => held.text)).toEqual(["written first", "written second"]);
    });

    it("throws away what it holds when the service has started again", async () => {
        const { book: opened, state, updates, seqs } = book([line(0), line(1), line(2)]);
        await opened.open();
        updates.length = 0;
        state.restart([line(0, "a new run"), line(1, "its second line")]);
        // The new run's numbers begin again; one arrives as it is written.
        state.listener?.(line(1, "its second line", { at_unix_ms: 5 }));
        await until(() => updates.some((update) => update.reset), "the reset");
        expect(seqs()).toEqual([0, 1]);
        expect(opened.view().lines.map((held) => held.text)).toEqual([
            "a new run",
            "its second line",
        ]);
        // Nothing of the new run has been lost, and the service says so.
        expect(opened.view().dropped).toBe(false);
    });

    it("after a new run, still says so if that run has already let lines go", async () => {
        const { book: opened, state } = book([line(0), line(1)]);
        await opened.open();
        // The new run has written 300 lines and kept the last two.
        state.restart([line(298), line(299)], [0, 1, 2]);
        await opened.close();
        const view = await opened.open();
        expect(view.lines.map((held) => held.seq)).toEqual([298, 299]);
        expect(view.dropped).toBe(true);
    });

    it("keeps a bounded number of lines, the newest, and says older ones are gone", async () => {
        const kept = Array.from({ length: MAX_LOG_LINES + 50 }, (_, seq) => line(seq));
        const { book: opened, state, seqs } = book(kept, 400);
        const view = await opened.open();
        expect(view.lines).toHaveLength(MAX_LOG_LINES);
        expect(view.lines[0]?.seq).toBe(50);
        expect(view.dropped).toBe(true);
        // And stays bounded as more are written.
        for (let seq = MAX_LOG_LINES + 50; seq < MAX_LOG_LINES + 80; seq++) {
            state.write(line(seq));
        }
        expect(seqs()).toHaveLength(MAX_LOG_LINES);
        expect(seqs().at(-1)).toBe(MAX_LOG_LINES + 79);
    });

    it("says so when the service itself had already let older lines go", async () => {
        const { book: opened, state } = book([line(0)]);
        state.page = { run: 1, lines: [line(40), line(41)], next: 41, dropped: true };
        const first = opened.open();
        await pause(20);
        state.page = null;
        state.lines = [line(40), line(41)];
        expect((await first).dropped).toBe(true);
    });

    it("says the log cannot be read when the service does not answer, and keeps what it has", async () => {
        const { book: opened, state, updates, seqs } = book([line(0), line(1)]);
        await opened.open();
        state.reachable = false;
        updates.length = 0;
        state.write(line(3));
        await until(() => updates.length > 0, "the interface being told");
        expect(updates.at(-1)).toMatchObject({ available: false, lines: [] });
        expect(seqs()).toEqual([0, 1]);
        // Once it answers again, the gap is read and the log is whole.
        state.reachable = true;
        state.write(line(2), false);
        state.write(line(4));
        await until(() => seqs().length === 5, "the log being whole again");
        expect(seqs()).toEqual([0, 1, 2, 3, 4]);
        expect(opened.view().available).toBe(true);
    });

    it("treats an answer that is not a page as no answer, and passes nothing of it on", async () => {
        const { book: opened, state } = book();
        state.page = { run: 1, lines: [{ ...line(0), cookie: COOKIE }], next: 0, dropped: false };
        const view = await opened.open();
        expect(view).toEqual({ available: false, lines: [], dropped: false });
        expect(JSON.stringify(view)).not.toContain(COOKIE);
    });

    it("ignores what is not a line, and tells the interface nothing of it", async () => {
        const { book: opened, state, updates, seqs } = book([line(0)]);
        await opened.open();
        updates.length = 0;
        for (const raw of [null, "text", { ...line(1), cookie: COOKIE }, { seq: 1 }]) {
            state.listener?.(raw);
        }
        await pause(20);
        expect(seqs()).toEqual([0]);
        expect(JSON.stringify(updates)).not.toContain(COOKIE);
    });

    it("stops when the interface closes the log: watching off, and no more said", async () => {
        const { book: opened, state, updates } = book([line(0)]);
        await opened.open();
        await opened.close();
        expect(state.calls.at(-1)).toBe("watch off");
        updates.length = 0;
        state.lines.push(line(1));
        expect(updates).toEqual([]);
        // Opened again, it reads on from where it was.
        const view = await opened.open();
        expect(view.lines.map((held) => held.seq)).toEqual([0, 1]);
        expect(state.calls).toContain("fetch 1/0");
    });

    it("takes nothing, and says nothing, once it is closed, whatever still arrives", async () => {
        const { book: opened, state, updates, seqs } = book([line(0)]);
        await opened.open();
        // A service slow to stop sending: it still has the way to reach the app.
        const stillSending = state.listener;
        await opened.close();
        updates.length = 0;
        stillSending?.(line(1));
        stillSending?.(line(5));
        await pause(30);
        expect(seqs()).toEqual([0]);
        expect(updates).toEqual([]);

        // And a page that was being read when it closed is not announced.
        let answer: (page: unknown) => void = () => {};
        const said: LogUpdate[] = [];
        const slow = new LogBook(
            {
                watch: async () => {},
                fetch: () =>
                    new Promise((resolve) => {
                        answer = resolve;
                    }),
                diagnostics: async () => null,
            },
            (update) => said.push(update),
        );
        const opening = slow.open();
        await pause(10);
        await slow.close();
        answer({ run: 1, lines: [line(0)], next: 0, dropped: false });
        await opening;
        expect(said).toEqual([]);
    });

    it("takes a line once when a page brings again what is already held", async () => {
        const { book: opened, state, seqs } = book([line(0), line(1)]);
        await opened.open();
        // A service that answers from further back than it was asked.
        state.page = { run: 1, lines: [line(0), line(1), line(2)], next: 2, dropped: false };
        state.listener?.(line(3));
        await until(() => seqs().includes(2), "the page being read");
        expect(seqs()).toEqual([0, 1, 2]);
    });

    it("is not held for ever by a service whose pages never end", async () => {
        const { book: opened, state } = book();
        let seq = 0;
        state.page = null;
        const endless: LogFeed = {
            watch: async () => {},
            fetch: async () => {
                seq += 1;
                return { run: 1, lines: [line(seq)], next: seq, dropped: false };
            },
            diagnostics: async () => null,
        };
        const held = new LogBook(endless, () => {});
        const view = await held.open();
        expect(view.lines.length).toBeLessThanOrEqual(64);
        expect(seq).toBeLessThanOrEqual(64);
        expect(opened.view().lines).toEqual([]);
    });
});

describe("the service's account of itself", () => {
    it("is taken, cleaned, with nothing the contract does not name", () => {
        const taken = takeDiagnostics({
            ...DIAGNOSTICS,
            os: "linux‮\n",
            os_version: "6.8\u{e0041}\u2028",
            last_error: { code: "gateway_unreachable", message: "The gateway\ndid not answer." },
        });
        expect(taken).toEqual({ ...DIAGNOSTICS, os: "linux" });
        expect(taken).not.toBe(DIAGNOSTICS);
    });

    it("has every text in it made one plain line, so none can add a line to the report", () => {
        const twoLines = (text: string) => `${text}\nOwner claimed: no`;
        const dirty = {
            ...DIAGNOSTICS,
            service_version: twoLines("0.1.0"),
            os: twoLines("linux"),
            arch: twoLines("x86_64"),
            os_version: twoLines("6.8"),
            gateway: twoLines("vpn.example"),
            last_error: { code: "gateway_unreachable", message: twoLines("It did not answer.") },
        };
        const taken = takeDiagnostics(dirty);
        for (const text of [
            taken?.service_version,
            taken?.os,
            taken?.arch,
            taken?.os_version,
            taken?.gateway,
            taken?.last_error?.message,
        ]) {
            expect(text).not.toMatch(/[\n\r]/);
            expect(text).toContain("Owner claimed: no");
        }
        const parts = {
            appVersion: "0.1.0",
            platform: "linux",
            arch: "x64",
            link: { link: "ready", conn: { state: "disconnected" } } as LinkState,
            lines: [],
            dropped: false,
            now: 0,
        };
        const clean = composeReport({ ...parts, diagnostics: takeDiagnostics(DIAGNOSTICS) });
        const report = composeReport({ ...parts, diagnostics: taken });
        // The same number of lines, and the real answer still on a line of its own.
        expect(report.text.split("\n")).toHaveLength(clean.text.split("\n").length);
        expect(report.text.split("\n").filter((row) => row.startsWith("Owner claimed:"))).toEqual([
            "Owner claimed: yes",
        ]);
    });

    it("may have no OS version, last error or gateway to give, and must have the rest", () => {
        const bare = { ...DIAGNOSTICS, os_version: null, last_error: null, gateway: null };
        expect(takeDiagnostics(bare)).toEqual(bare);
        for (const key of Object.keys(DIAGNOSTICS)) {
            expect(takeDiagnostics({ ...DIAGNOSTICS, [key]: undefined }), key).toBeNull();
        }
        // The state is one of the contract's words, and the counts are counts.
        for (const state of ["dancing", "constructor", { state: "connected" }, 3]) {
            expect(takeDiagnostics({ ...DIAGNOSTICS, state }), String(state)).toBeNull();
        }
        expect(takeDiagnostics({ ...DIAGNOSTICS, subnets: -1 })).toBeNull();
        expect(takeDiagnostics({ ...DIAGNOSTICS, dns_domains: "1" })).toBeNull();
        expect(
            takeDiagnostics({ ...DIAGNOSTICS, last_error: { code: "gremlins", message: "m" } }),
        ).toBeNull();
        expect(takeDiagnostics(null)).toBeNull();
    });

    it("is refused whole when it carries a field the contract does not have", () => {
        expect(takeDiagnostics({ ...DIAGNOSTICS, home: "/home/someone" })).toBeNull();
        expect(takeDiagnostics({ ...DIAGNOSTICS, cookie: COOKIE })).toBeNull();
    });
});

describe("the diagnostics report", () => {
    const READY: LinkState = { link: "ready", conn: { state: "disconnected" } };
    const parts = {
        appVersion: "0.1.0",
        platform: "linux",
        arch: "x64",
        link: READY,
        dropped: false,
        now: 1_800_000_000_000,
    };

    it("holds the versions, the system, the state, the last error and the newest lines", () => {
        const diagnostics = takeDiagnostics(DIAGNOSTICS);
        const report = composeReport({
            ...parts,
            diagnostics,
            lines: [line(0), line(1, "CSTP connected")],
        });
        expect(report.lines).toBe(2);
        for (const expected of [
            "UBC VPN diagnostics report",
            "App: 0.1.0 (linux x64)",
            "Service: reachable",
            "Service version: 0.1.0, protocol 3",
            "System: linux x86_64 6.8",
            "Connection: connected, with 2 subnets and 1 domain through the tunnel",
            "Last error: gateway_unreachable: The gateway did not answer.",
            "Policy: readable, gateway vpn.example, 2 pins",
            "Owner claimed: yes",
            "#1 2027-01-15T08:00:00.001Z info service  CSTP connected",
        ]) {
            expect(report.text, expected).toContain(expected);
        }
    });

    it("carries the newest lines only, and says older ones are left out", () => {
        const lines = Array.from({ length: REPORT_LINES + 30 }, (_, seq) => line(seq));
        const report = composeReport({ ...parts, diagnostics: null, lines });
        expect(report.lines).toBe(REPORT_LINES);
        expect(report.text).not.toContain("#29 ");
        expect(report.text).toContain("#30 ");
        expect(report.text).toContain("older lines are not included");
        expect(report.text).toContain("The service did not give its own account of itself.");
        expect(composeReport({ ...parts, diagnostics: null, lines: [line(0)] }).text).not.toContain(
            "older lines",
        );
    });

    it("says when the service cannot be reached", () => {
        const gone: LinkState = { link: "unavailable", reason: "not_running" };
        const report = composeReport({ ...parts, link: gone, diagnostics: null, lines: [] });
        expect(report.text).toContain("Service: not reachable (not_running)");
    });
});

describe("copying the report", () => {
    const partsWith = (copied: string[], fail = false) => ({
        appVersion: "0.1.0",
        platform: "linux",
        arch: "x64",
        link: (): LinkState => ({ link: "ready", conn: { state: "disconnected" } }),
        copy: (text: string) => {
            if (fail) {
                throw new Error("no clipboard");
            }
            copied.push(text);
        },
        focused: () => true,
    });
    /** A gate that lets everything by, for the tests that are about something else. */
    const open = { allows: () => true };

    it("is done once for a burst of requests, with the service asked once", async () => {
        const { book: opened, feed, state } = book([line(0)]);
        await opened.open();
        const copied: string[] = [];
        const parts = partsWith(copied);
        const gate = new CopyGate(opened, parts.focused);
        const results = await Promise.all(
            Array.from({ length: 200 }, () => copyReport(opened, feed, parts, gate)),
        );
        expect(copied).toHaveLength(1);
        expect(state.diagnosed).toBe(1);
        expect(results.filter((result) => result.ok)).toHaveLength(1);
        expect(results.filter((result) => !result.ok)).toHaveLength(199);
    });

    it("is allowed again only after a few seconds", async () => {
        const { book: opened } = book([line(0)]);
        await opened.open();
        expect(COPY_GAP_MS).toBeGreaterThanOrEqual(2000);
        const gate = new CopyGate(opened, () => true, 150);
        expect(gate.allows()).toBe(true);
        expect(gate.allows()).toBe(false);
        await pause(60);
        expect(gate.allows()).toBe(false);
        await pause(130);
        expect(gate.allows()).toBe(true);
    });

    it("is refused, and the service asked nothing, unless the log is open and the window in use", async () => {
        const { book: opened, feed, state } = book([line(0)]);
        const copied: string[] = [];
        let focused = true;
        const parts = { ...partsWith(copied), focused: () => focused };
        const gate = new CopyGate(opened, parts.focused, 0);
        // The log has never been opened.
        expect(await copyReport(opened, feed, parts, gate)).toEqual({ ok: false });
        await opened.open();
        // The window is not the one the user is working in.
        focused = false;
        expect(await copyReport(opened, feed, parts, gate)).toEqual({ ok: false });
        focused = true;
        expect(await copyReport(opened, feed, parts, gate)).toEqual({ ok: true, lines: 1 });
        // And not once the log has been closed again.
        await opened.close();
        expect(await copyReport(opened, feed, parts, gate)).toEqual({ ok: false });
        expect(copied).toHaveLength(1);
        expect(state.diagnosed).toBe(1);
    });

    it("puts it on the clipboard once, and answers with a count, never the text", async () => {
        const { book: opened, feed } = book([line(0), line(1, "CSTP connected")]);
        await opened.open();
        const copied: string[] = [];
        const result = await copyReport(opened, feed, partsWith(copied), open);
        expect(result).toEqual({ ok: true, lines: 2 });
        expect(copied).toHaveLength(1);
        expect(copied[0]).toContain("CSTP connected");
        expect(copied[0]).toContain("Service version: 0.1.0");
        expect(JSON.stringify(result)).not.toContain("CSTP");
    });

    it("copies nothing by itself: not on opening, not as lines arrive, not on closing", async () => {
        // The whole of what the interface can ask for, as the app wires it,
        // with a window and a clipboard that only record.
        const { feed, state } = book([line(0)]);
        const copied: string[] = [];
        const opened = new LogBook(feed, () => {});
        const gate = new CopyGate(opened, () => true);
        const handlers = logHandlers(opened, feed, partsWith(copied), gate);
        expect(Object.keys(handlers).sort()).toEqual([
            "logs:close",
            "logs:copy-report",
            "logs:open",
        ]);
        await handlers[LOGS_IPC.open]();
        state.write(line(1));
        await handlers[LOGS_IPC.open]();
        await handlers[LOGS_IPC.close]();
        expect(copied).toEqual([]);
        expect(state.diagnosed).toBe(0);
        // Only the one request copies, and it does.
        await handlers[LOGS_IPC.open]();
        expect(await handlers[LOGS_IPC.copyReport]()).toEqual({ ok: true, lines: 2 });
        expect(copied).toHaveLength(1);
    });

    it("still copies what it has when the service gives no account of itself", async () => {
        const { book: opened, feed, state } = book([line(0)]);
        await opened.open();
        state.reachable = false;
        const copied: string[] = [];
        expect(await copyReport(opened, feed, partsWith(copied), open)).toEqual({
            ok: true,
            lines: 1,
        });
        expect(copied[0]).toContain("The service did not give its own account of itself.");
        // A service whose answer cannot be believed is treated the same.
        const broken = { diagnostics: async () => ({ ...DIAGNOSTICS, pins: "two" }) };
        // (An answer with a field out of place is no answer at all.)
        await copyReport(opened, broken, partsWith(copied), open);
        expect(copied[1]).toContain("did not give its own account");
    });

    it("says so when the clipboard cannot be written", async () => {
        const { book: opened, feed } = book([line(0)]);
        await opened.open();
        expect(await copyReport(opened, feed, partsWith([], true), open)).toEqual({ ok: false });
    });
});

describe("a log nobody can be looking at", () => {
    it("is closed when the window is put away, its page loads again, or its process dies", async () => {
        const heard = new Map<string, () => void>();
        const window = {
            on: (event: string, listener: () => void) => void heard.set(event, listener),
            webContents: {
                on: (event: string, listener: () => void) => void heard.set(event, listener),
            },
        };
        const { book: opened, state } = book([line(0)]);
        closeWhenAway(window, opened);
        expect([...heard.keys()].sort()).toEqual([
            "did-start-loading",
            "hide",
            "render-process-gone",
        ]);
        for (const event of ["hide", "did-start-loading", "render-process-gone"]) {
            await opened.open();
            expect(opened.isOpen()).toBe(true);
            heard.get(event)?.();
            await pause(10);
            expect(opened.isOpen(), event).toBe(false);
            expect(state.calls.at(-1), event).toBe("watch off");
        }
        // The first load of the page, before anything was opened, asks the service nothing.
        const before = state.calls.length;
        heard.get("did-start-loading")?.();
        await pause(10);
        expect(state.calls).toHaveLength(before);
    });
});

describe("the demo's pretend log", () => {
    it("answers in the agreed shapes, in every scenario", async () => {
        const demo = createDemoLogs(1000);
        for (const name of DEMO_LOG_SCENARIOS) {
            demo.setScenario(name);
            const page = await demo.fetch(null);
            if (name === "logs-unavailable") {
                expect(page).toBeNull();
                expect(await demo.diagnostics()).toBeNull();
            } else {
                expect(takePage(page), name).not.toBeNull();
                expect(takeDiagnostics(await demo.diagnostics()), name).not.toBeNull();
            }
        }
    });

    it("drops lines on the way, as a real service may, and the log is still whole", async () => {
        const demo = createDemoLogs(30);
        demo.setScenario("logs-gaps");
        const held = new LogBook(demo, () => {});
        const first = (await held.open()).lines.length;
        await until(() => held.view().lines.length >= first + 6, "more lines arriving");
        await held.close();
        const seqs = held.view().lines.map((kept) => kept.seq);
        expect(seqs).toEqual(seqs.map((_, at) => (seqs[0] ?? 0) + at));
    });

    it("has a hole that stays, and the app marks the line after it", async () => {
        const demo = createDemoLogs(1000);
        demo.setScenario("logs-lost");
        const view = await new LogBook(demo, () => {}).open();
        // The login lines went; the start of the log did not.
        expect(view.dropped).toBe(false);
        expect(view.lines.some((held) => held.source === "login")).toBe(false);
        const marked = view.lines.filter((held) => held.gap === true);
        expect(marked).toHaveLength(1);
        expect(marked[0]?.text).toBe("Connecting to vpn.example");
        expect(marked[0]?.source).toBe("engine");
    });

    it("pages a long log, and says older lines have gone", async () => {
        const demo = createDemoLogs(1000);
        demo.setScenario("logs-many");
        const view = await new LogBook(demo, () => {}).open();
        expect(view.lines).toHaveLength(500);
        expect(view.dropped).toBe(true);
    });
});
