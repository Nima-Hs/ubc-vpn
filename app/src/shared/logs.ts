// The service's log, as the main process gives it to the interface. The
// shapes the service itself uses are the contract's, generated into
// `protocol/` (`LogLine`, `LogPage`, `LogCursor`, `Diagnostics`). No production
// build contains any of this yet: see `__LOGS__`.

import type { LogLine } from "./protocol/LogLine";

/** The most lines kept, in the main process and in the interface alike. */
export const MAX_LOG_LINES = 1000;
/** The longest a line's text may be when shown. */
export const MAX_LOG_TEXT = 512;
/**
 * What stands in for a line whose text came to nothing once it was cleaned.
 * The line keeps its number and its place; an empty row would say nothing.
 */
export const EMPTY_LINE = "[a line with nothing that can be shown]";

/** A line as the interface is given it: checked, cleaned and plain. */
export interface ShownLine extends LogLine {
    /** Lines written just before this one are no longer kept. */
    gap?: true;
}

/** What the interface gets when it opens the log. */
export interface LogView {
    /** `false` when the service could not be asked. */
    available: boolean;
    lines: ShownLine[];
    /** Whether lines older than the first of these existed and are gone. */
    dropped: boolean;
}

/** What has changed since the last view or update. */
export interface LogUpdate {
    /** Throw away what is held: the service started again. */
    reset: boolean;
    /** New lines, oldest first. */
    lines: ShownLine[];
    dropped: boolean;
    available: boolean;
}

/** What copying the report came to. Never the report itself. */
export type ReportResult =
    | { ok: true; lines: number }
    /**
     * Why it was not copied, so the screen can say something true: the log
     * was not open, another window was in use, it was copied a moment ago,
     * or writing the clipboard failed. Never any part of the report.
     */
    | { ok: false; reason: "closed" | "not_in_use" | "too_soon" | "failed" };

/** Present only in builds that have the log screen. */
export interface LogsApi {
    /** Starts following the log and returns what is held now. */
    open(): Promise<LogView>;
    /** Stops following it. */
    close(): Promise<void>;
    onUpdate(listener: (update: LogUpdate) => void): () => void;
    /** Puts a diagnostics report on the clipboard. Call only on the user's own press. */
    copyReport(): Promise<ReportResult>;
}

export const LOGS_IPC = {
    open: "logs:open",
    close: "logs:close",
    update: "logs:update",
    copyReport: "logs:copy-report",
} as const;
