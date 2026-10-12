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
}

/**
 * Makes and copies the report. Called only for the interface's own "copy"
 * press. The answer says how many lines went, and never carries the text.
 */
export async function copyReport(
    book: Pick<LogBook, "view">,
    feed: Pick<LogFeed, "diagnostics">,
    parts: ReportParts,
): Promise<ReportResult> {
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
    const handle = (channel: string, handler: () => unknown) =>
        handleFromInterface(window, devServerUrl, channel, handler);
    handle(LOGS_IPC.open, () => book.open());
    handle(LOGS_IPC.close, () => book.close());
    handle(LOGS_IPC.copyReport, () => copyReport(book, feed, parts));
    return book;
}
