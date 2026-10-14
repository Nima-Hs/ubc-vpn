import type { LinkState } from "@shared/api";
import { LOGS_IPC, type ReportResult } from "@shared/logs";
import type { BrowserWindow } from "electron";
import { handleFromInterface } from "../ipc";
import { LogBook, type LogFeed, takeDiagnostics } from "./book";
import { composeReport } from "./report";

/** What the report needs that the log does not hold. */
export interface ReportParts {
    appVersion: string;
    platform: string;
    arch: string;
    link(): LinkState;
    /** Puts text on the clipboard. The one place a report goes. */
    copy(text: string): void;
    /** Whether the app's window is the one the user is working in. */
    focused(): boolean;
}

/** The least time between one copy of the report and the next. */
export const COPY_GAP_MS = 3_000;

/**
 * Decides whether a copy that the interface asks for is made. The main
 * process cannot see a key press, so it cannot know the user asked. It
 * holds to what a user's own press would look like instead: the log is open
 * on screen, the window is the one in use, and it is not one of a stream.
 * Without this a page gone wrong could write over the clipboard, and ask
 * the service for its account of itself, as often as it liked.
 */
export class CopyGate {
    private lastAt = Number.NEGATIVE_INFINITY;

    constructor(
        private readonly book: Pick<LogBook, "isOpen">,
        private readonly focused: () => boolean,
        private readonly gapMs = COPY_GAP_MS,
    ) {}

    /** Whether to copy now. A yes counts as a copy, whatever comes of it. */
    allows(): boolean {
        const now = Date.now();
        if (!this.book.isOpen() || !this.focused() || now - this.lastAt < this.gapMs) {
            return false;
        }
        this.lastAt = now;
        return true;
    }
}

/**
 * Closes the log when nobody can be looking at it: the window was put away,
 * or its page is being loaded again and has forgotten that it opened it.
 * The page opens it again when it is shown.
 */
export function closeWhenAway(
    window: {
        on(event: "hide", listener: () => void): unknown;
        webContents: {
            on(event: "did-start-loading" | "render-process-gone", listener: () => void): unknown;
        };
    },
    book: Pick<LogBook, "close">,
): void {
    const close = () => void book.close();
    window.on("hide", close);
    window.webContents.on("did-start-loading", close);
    window.webContents.on("render-process-gone", close);
}

/**
 * Makes and copies the report, if `gate` allows it. The answer says how
 * many lines went, and never carries the text. A copy that is not allowed
 * asks the service nothing and writes nothing.
 */
export async function copyReport(
    book: Pick<LogBook, "view">,
    feed: Pick<LogFeed, "diagnostics">,
    parts: ReportParts,
    gate: Pick<CopyGate, "allows">,
): Promise<ReportResult> {
    if (!gate.allows()) {
        return { ok: false };
    }
    let diagnostics: ReturnType<typeof takeDiagnostics>;
    try {
        diagnostics = takeDiagnostics(await feed.diagnostics());
    } catch {
        diagnostics = null;
    }
    const held = book.view();
    try {
        const report = composeReport({
            appVersion: parts.appVersion,
            platform: parts.platform,
            arch: parts.arch,
            link: parts.link(),
            diagnostics,
            lines: held.lines,
            dropped: held.dropped,
            now: Date.now(),
        });
        parts.copy(report.text);
        return { ok: true, lines: report.lines };
    } catch {
        return { ok: false };
    }
}

/**
 * What each of the interface's three requests does, by channel. Kept apart
 * from Electron so that it can be tested whole: opening and closing only
 * open and close, and nothing but the copy request ever copies.
 */
export function logHandlers(
    book: Pick<LogBook, "open" | "close" | "view">,
    feed: Pick<LogFeed, "diagnostics">,
    parts: ReportParts,
    gate: Pick<CopyGate, "allows">,
): Record<(typeof LOGS_IPC)["open" | "close" | "copyReport"], () => unknown> {
    return {
        [LOGS_IPC.open]: () => book.open(),
        [LOGS_IPC.close]: () => book.close(),
        [LOGS_IPC.copyReport]: () => copyReport(book, feed, parts, gate),
    };
}

/**
 * The few things the interface can ask about the log. Each is checked to
 * come from the interface's own page, like every other request, and none
 * takes an argument.
 */
export function registerLogs(
    window: BrowserWindow,
    devServerUrl: string | undefined,
    feed: LogFeed,
    parts: ReportParts,
): LogBook {
    const book = new LogBook(feed, (update) => {
        if (!window.isDestroyed()) {
            window.webContents.send(LOGS_IPC.update, update);
        }
    });
    const gate = new CopyGate(book, parts.focused);
    for (const [channel, handler] of Object.entries(logHandlers(book, feed, parts, gate))) {
        handleFromInterface(window, devServerUrl, channel, handler);
    }
    closeWhenAway(window, book);
    return book;
}
