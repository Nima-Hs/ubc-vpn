// The service's log, as far as the interface is given it.
//
// Every line that reaches the interface passes through here, and through
// `takeLine` in particular: its shape is checked, its text is made one plain
// line of bounded length, and a fresh object holding only the known fields is
// made. The service redacts; this is the app's own second look, the same as
// for text from a login. Nothing here writes a line anywhere but to the
// interface, and nothing is kept on disk.

import {
    type LogUpdate,
    type LogView,
    MAX_LOG_LINES,
    MAX_LOG_TEXT,
    type ShownLine,
} from "@shared/logs";
import type { Diagnostics } from "@shared/protocol/Diagnostics";
import type { LogCursor } from "@shared/protocol/LogCursor";
import type { LogLevel } from "@shared/protocol/LogLevel";
import type { LogLine } from "@shared/protocol/LogLine";
import type { LogPage } from "@shared/protocol/LogPage";
import type { LogSource } from "@shared/protocol/LogSource";
import type { StateKind } from "@shared/protocol/StateKind";
import { plainText } from "../channel/connect";
import { isErrorInfo } from "../channel/validate";

/**
 * What the log needs from the service, real or fake. Answers are `unknown`
 * on purpose: nothing is believed until it has been checked here.
 */
export interface LogFeed {
    /**
     * `watch_logs`: with a listener, each new line is passed to it as it is
     * written; with `null`, that stops. The service may drop lines it could
     * not deliver, so what arrives can have gaps.
     */
    watch(onLine: ((line: unknown) => void) | null): Promise<void>;
    /** `logs { after }`: one page, or `null` if the service could not be asked. */
    fetch(after: LogCursor | null): Promise<unknown>;
    /** `diagnostics`, or `null` if the service could not be asked. */
    diagnostics(): Promise<unknown>;
}

const LEVELS: ReadonlySet<string> = new Set<LogLevel>(["error", "warn", "info"]);
const SOURCES: ReadonlySet<string> = new Set<LogSource>(["service", "engine", "login"]);
const STATES: ReadonlySet<string> = new Set<StateKind>([
    "disconnected",
    "connecting",
    "connected",
    "disconnecting",
    "login_needed",
    "failed",
]);

// The tag characters: invisible, and able to spell out text nobody sees. The
// service refuses them in a line; the app takes them out as well. (Text from
// a login keeps them, because a few flags are written with them.)
const TAGS = /[\u{e0000}-\u{e007f}]/gu;

/** A line's text, or any text shown beside the log, made plain. */
const shown = (text: string, limit: number): string => plainText(text.replace(TAGS, ""), limit);

const isObject = (value: unknown): value is Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value);
/** A whole number that JSON carries exactly. */
const isCount = (value: unknown): value is number =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const hasOnly = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
    Object.keys(value).every((key) => keys.includes(key));

/**
 * One line from the service, made fit to show, or `null` if it is not a
 * line. The text is cleaned whatever the service did to it.
 */
export function takeLine(raw: unknown): ShownLine | null {
    if (
        !isObject(raw) ||
        !hasOnly(raw, ["seq", "at_unix_ms", "level", "source", "text"]) ||
        !isCount(raw.seq) ||
        !isCount(raw.at_unix_ms) ||
        typeof raw.level !== "string" ||
        !LEVELS.has(raw.level) ||
        typeof raw.source !== "string" ||
        !SOURCES.has(raw.source) ||
        typeof raw.text !== "string"
    ) {
        return null;
    }
    return {
        seq: raw.seq,
        at_unix_ms: raw.at_unix_ms,
        level: raw.level as LogLevel,
        source: raw.source as LogSource,
        text: shown(raw.text, MAX_LOG_TEXT),
    };
}

/** One page from the service, every line made fit to show, or `null`. */
export function takePage(raw: unknown): LogPage | null {
    if (
        !isObject(raw) ||
        !hasOnly(raw, ["run", "lines", "next", "dropped"]) ||
        !isCount(raw.run) ||
        !isCount(raw.next) ||
        typeof raw.dropped !== "boolean" ||
        !Array.isArray(raw.lines) ||
        raw.lines.length > MAX_LOG_LINES
    ) {
        return null;
    }
    const lines: LogLine[] = [];
    for (let at = 0; at < raw.lines.length; at++) {
        const line = takeLine(raw.lines[at]);
        if (line === null) {
            return null;
        }
        lines.push(line);
    }
    return { run: raw.run, lines, next: raw.next, dropped: raw.dropped };
}

const SHORT = 64;

const DIAGNOSTICS_FIELDS = [
    "service_version",
    "protocol_version",
    "os",
    "arch",
    "os_version",
    "uptime_s",
    "state",
    "subnets",
    "dns_domains",
    "last_error",
    "policy_readable",
    "pins",
    "gateway",
    "owner_claimed",
] as const;

/** The service's account of itself, checked and cleaned, or `null`. */
export function takeDiagnostics(raw: unknown): Diagnostics | null {
    const text = (value: unknown): value is string => typeof value === "string";
    if (
        !isObject(raw) ||
        !hasOnly(raw, DIAGNOSTICS_FIELDS) ||
        !text(raw.service_version) ||
        !isCount(raw.protocol_version) ||
        !text(raw.os) ||
        !text(raw.arch) ||
        !(raw.os_version === null || text(raw.os_version)) ||
        !isCount(raw.uptime_s) ||
        !text(raw.state) ||
        !STATES.has(raw.state) ||
        !isCount(raw.subnets) ||
        !isCount(raw.dns_domains) ||
        !(raw.last_error === null || isErrorInfo(raw.last_error)) ||
        typeof raw.policy_readable !== "boolean" ||
        !(raw.gateway === null || text(raw.gateway)) ||
        !isCount(raw.pins) ||
        typeof raw.owner_claimed !== "boolean"
    ) {
        return null;
    }
    return {
        service_version: shown(raw.service_version, SHORT),
        protocol_version: raw.protocol_version,
        os: shown(raw.os, SHORT),
        arch: shown(raw.arch, SHORT),
        os_version: raw.os_version === null ? null : shown(raw.os_version, MAX_LOG_TEXT),
        uptime_s: raw.uptime_s,
        state: raw.state as StateKind,
        subnets: raw.subnets,
        dns_domains: raw.dns_domains,
        last_error:
            raw.last_error === null
                ? null
                : {
                      code: raw.last_error.code,
                      message: shown(raw.last_error.message, MAX_LOG_TEXT),
                  },
        policy_readable: raw.policy_readable,
        gateway: raw.gateway === null ? null : shown(raw.gateway, 253),
        pins: raw.pins,
        owner_claimed: raw.owner_claimed,
    };
}

/** The most pages read in one go, so a service that never ends cannot hold the app. */
const MAX_PAGES = 64;

/**
 * Follows the service's log while the interface has it open, and keeps a
 * bounded number of lines.
 *
 * The order of work is the contract's: turn watching on first, then read
 * what is already there, so nothing written in between is missed. A line
 * seen twice is taken once, by its number. A gap in the numbers means the
 * service dropped a line it could not deliver, and what is missing is read
 * again: once. The service may no longer hold those lines, and then the gap
 * is for good; the line after it is marked and reading carries on. When the
 * service has started afresh, what is held is thrown away.
 */
export class LogBook {
    private lines: ShownLine[] = [];
    /** The run of the service the lines are from, once known. */
    private run: number | null = null;
    /**
     * The highest line number taken in this run: where to read on from. The
     * page's own `next` is checked but not relied on, so a service that
     * means "the next line" by it and one that means "the last line" are
     * read the same.
     */
    private last = -1;
    /** Lines older than the first one held are gone. */
    private dropped = false;
    private available = true;
    private opened = false;
    private reading: Promise<void> | null = null;
    private readAgain = false;

    constructor(
        private readonly feed: LogFeed,
        private readonly onUpdate: (update: LogUpdate) => void,
    ) {}

    /** Starts following the log, and returns what is held once it is up to date. */
    async open(): Promise<LogView> {
        this.opened = true;
        await this.feed.watch((line) => this.onLine(line));
        await this.read();
        return this.view();
    }

    async close(): Promise<void> {
        this.opened = false;
        await this.feed.watch(null);
    }

    view(): LogView {
        return { available: this.available, lines: [...this.lines], dropped: this.dropped };
    }

    private onLine(raw: unknown): void {
        if (!this.opened) {
            return;
        }
        const line = takeLine(raw);
        if (line === null) {
            return;
        }
        if (this.run !== null && line.seq === this.last + 1 && this.reading === null) {
            this.keep([line]);
            this.tell(false, [line]);
            return;
        }
        const held = this.lines.find((other) => other.seq === line.seq);
        if (held !== undefined && held.at_unix_ms === line.at_unix_ms) {
            // The same line again: it came in a page as well.
            return;
        }
        // A gap, a line from before the first page, or a number already used
        // by a different line, which means the service has started again.
        void this.read();
    }

    /** Reads everything after what is held. One reading at a time. */
    private read(): Promise<void> {
        if (this.reading !== null) {
            this.readAgain = true;
            return this.reading;
        }
        this.reading = (async () => {
            do {
                this.readAgain = false;
                await this.readPages();
            } while (this.readAgain && this.opened);
        })().finally(() => {
            this.reading = null;
        });
        return this.reading;
    }

    private async readPages(): Promise<void> {
        for (let pages = 0; pages < MAX_PAGES; pages++) {
            // Closed while reading: the page in hand was kept, and no more is asked for.
            if (!this.opened) {
                return;
            }
            const after =
                this.run === null || this.last < 0 ? null : { run: this.run, seq: this.last };
            let page: LogPage | null;
            try {
                page = takePage(await this.feed.fetch(after));
            } catch {
                page = null;
            }
            if (page === null) {
                if (this.available) {
                    this.available = false;
                    this.tell(false, []);
                }
                return;
            }
            const cameBack = !this.available;
            this.available = true;
            // Another run of the service: its numbers start again, and the
            // lines held are no longer part of what it has.
            const reset = this.run !== null && page.run !== this.run;
            if (this.run !== page.run) {
                this.lines = [];
                this.last = -1;
                this.dropped = false;
                this.run = page.run;
            }
            const fresh: ShownLine[] = page.lines
                .filter((line) => line.seq > this.last)
                .sort((a, b) => a.seq - b.seq);
            // "Dropped" is the service's word that lines of this run after
            // the cursor are gone. Where they went from shows in the numbers:
            // a line that does not follow the one before it comes after a
            // hole. A hole before the very first line is the start of the
            // log having gone; any other is marked on the line after it. If
            // every line after the cursor has gone, there is nothing to mark
            // yet: the next line to come will not follow on either, and the
            // page that brings it will say "dropped" again.
            if (page.dropped) {
                let before = Math.max(this.last, 0);
                for (let at = 0; at < fresh.length; at++) {
                    const line = fresh[at] as ShownLine;
                    if (line.seq > before + 1) {
                        if (this.lines.length === 0 && at === 0) {
                            this.dropped = true;
                        } else {
                            fresh[at] = { ...line, gap: true };
                        }
                    }
                    before = line.seq;
                }
            }
            this.keep(fresh);
            if (reset || fresh.length > 0 || cameBack || page.dropped) {
                this.tell(reset, fresh);
            }
            // No more, or a page that brought nothing new: that is all for now.
            if (fresh.length === 0) {
                return;
            }
        }
    }

    private keep(lines: readonly ShownLine[]): void {
        for (const line of lines) {
            this.lines.push(line);
            this.last = Math.max(this.last, line.seq);
        }
        if (this.lines.length > MAX_LOG_LINES) {
            this.lines.splice(0, this.lines.length - MAX_LOG_LINES);
            this.dropped = true;
        }
    }

    private tell(reset: boolean, lines: readonly ShownLine[]): void {
        if (this.opened) {
            this.onUpdate({
                reset,
                lines: [...lines],
                dropped: this.dropped,
                available: this.available,
            });
        }
    }
}
