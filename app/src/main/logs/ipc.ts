import type { LinkState } from "@shared/api";
import { LOGS_IPC, type LogUpdate, type ReportResult } from "@shared/logs";
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

    /** Whether to copy now, or why not. A yes counts as a copy, whatever comes of it. */
    allows(): "yes" | "closed" | "not_in_use" | "too_soon" {
        const now = Date.now();
        if (!this.book.isOpen()) {
            return "closed";
        }
        if (!this.focused()) {
            return "not_in_use";
        }
        if (now - this.lastAt < this.gapMs) {
            return "too_soon";
        }
        this.lastAt = now;
        return "yes";
    }
}

/**
 * Closes the log when nobody can be looking at it, and opens it again when
 * someone can. Put away with the log open, the window gets it back when it
 * is shown: the screen is still the one it was, and it is told everything
 * afresh, as after the service has started again. A page that is loaded
 * again, or whose process died, has forgotten it opened the log; it opens
 * it itself if it shows the log, and nothing is opened for it.
 */
export function followWindow(
    window: {
        on(event: "hide" | "show", listener: () => void): unknown;
        webContents: {
            on(event: "did-start-loading" | "render-process-gone", listener: () => void): unknown;
        };
    },
    book: Pick<LogBook, "close" | "open" | "isOpen">,
    tell: (update: LogUpdate) => void,
): { pageClosed(): void } {
    let reopen = false;
    window.on("hide", () => {
        reopen = book.isOpen();
        void book.close();
    });
    window.on("show", () => {
        if (!reopen) {
            return;
        }
        reopen = false;
        void book.open().then((view) => tell({ reset: true, ...view }));
    });
    const forgotten = () => {
        reopen = false;
        void book.close();
    };
    window.webContents.on("did-start-loading", forgotten);
    window.webContents.on("render-process-gone", forgotten);
    // The page closed it itself: it has left the Logs screen, even if that
    // happened while the window was away, and nothing is opened for it.
    return {
        pageClosed: () => {
            reopen = false;
        },
    };
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
    const allowed = gate.allows();
    if (allowed !== "yes") {
        return { ok: false, reason: allowed };
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
        return { ok: false, reason: "failed" };
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
    /** Told when the page itself closes the log; see `followWindow`. */
    pageClosed: () => void = () => {},
): Record<(typeof LOGS_IPC)["open" | "close" | "copyReport"], () => unknown> {
    return {
        [LOGS_IPC.open]: () => book.open(),
        [LOGS_IPC.close]: () => {
            pageClosed();
            return book.close();
        },
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
    const tell = (update: LogUpdate) => {
        if (!window.isDestroyed()) {
            window.webContents.send(LOGS_IPC.update, update);
        }
    };
    const book = new LogBook(feed, tell);
    const gate = new CopyGate(book, parts.focused);
    const following = followWindow(window, book, tell);
    const handlers = logHandlers(book, feed, parts, gate, following.pageClosed);
    for (const [channel, handler] of Object.entries(handlers)) {
        handleFromInterface(window, devServerUrl, channel, handler);
    }
    return book;
}
