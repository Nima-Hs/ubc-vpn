// The Logs screen's words.

/** The Logs screen's fixed words. */
export const LOGS = {
    title: "Logs",
    body: "What the VPN service has done, oldest first. The service removes passwords, codes and session cookies before it keeps a line.",
    loading: "Reading the log…",
    empty: "Nothing has been logged yet.",
    unavailable:
        "The log could not be read because the VPN service did not answer. Wait a few seconds, then try again.",
    dropped: "Older lines are no longer kept.",
    gap: "Some lines here are no longer kept.",
    newBelow: "There are newer lines below.",
    listLabel: "Log lines",
    toNewest: "Newest lines",
    level: { error: "Error", warn: "Warning", info: "Info" },
    source: { service: "Service", engine: "Engine", login: "Login" },
    copyReport: "Copy report",
    // Said before anything is copied, so the user knows what they would be sending.
    reportHolds:
        "The report holds the newest log lines, the versions of the app and the service, your operating system and the state of the connection. Log lines can name folders on this computer, your user name and network addresses. It holds no password, code or session.",
    copyNow: "Copy to clipboard",
    reportHoldsLabel: "What the report holds",
    reportCopied: (lines: number) =>
        `Report copied, with ${lines} log ${lines === 1 ? "line" : "lines"}.`,
    // Why a copy was not made, said as it is.
    reportRefused: {
        closed: "The report was not copied because the log is not open. Open Logs, then try again.",
        not_in_use:
            "The report was not copied because another window was in use. Click this window, then try again.",
        too_soon: "The report was copied a moment ago. Wait a few seconds to copy it again.",
        failed: "The report could not be put on the clipboard. Try again.",
    },
} as const;
