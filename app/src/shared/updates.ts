// What the interface and the main process share about updates: where a
// check stands, and the few things the interface may ask. The design is in
// docs/architecture.md, "Updates". Whether updates are automatic is a
// setting like the others, saved through the profiles (`setUpdates`).

/** Why the last check or download did not finish. */
export type UpdateFailure =
    /** GitHub could not be reached. */
    | "offline"
    /** GitHub answered with something other than a release. */
    | "github"
    /** The list or the installer failed a check: nothing from it is used. */
    | "refused"
    /** The installer could not be saved. */
    | "disk";

export type UpdateStatus =
    /** This copy cannot update itself: a test or development build, or a system not supported yet. */
    | { phase: "unavailable" }
    /** Not checked yet since the app started. */
    | { phase: "idle" }
    | { phase: "checking" }
    | { phase: "up_to_date" }
    /** A newer version exists. Automatic updates are off, so it is not downloaded. */
    | { phase: "available"; version: string }
    | { phase: "downloading"; version: string }
    /** Downloaded and checked, ready to install. */
    | { phase: "ready"; version: string }
    /** "Restart to update" was pressed: disconnecting, then the administrator prompt. */
    | { phase: "installing"; version: string }
    | { phase: "failed"; reason: UpdateFailure };

/** Why the last "Restart to update" did not install. Nothing was changed. */
export type InstallNotice =
    /** The user cancelled the administrator prompt. */
    | "cancelled"
    /** The setup program could not be started. */
    | "failed"
    /** The downloaded installer no longer matched the list, so it was dropped. */
    | "changed"
    /** The VPN could not be disconnected first. */
    | "not_disconnected";

/** What the app has to say about an update that "Restart to update" started. */
export type AfterUpdateNotice =
    /** The app started again on its old version: the update did not take. */
    | "unfinished"
    /** A note from an update was over a day old, so nothing was reconnected. */
    | "stale"
    /** The profile that was connected no longer exists, so nothing was connected. */
    | "profile_gone"
    /** The app does not know which profile was connected, so nothing was connected. */
    | "reconnect_unknown"
    /** The service or the profiles could not be reached, so nothing was connected. */
    | "reconnect_unavailable"
    /** A login was still ending, so the reconnect did not start. */
    | "reconnect_busy";

export interface UpdateView {
    status: UpdateStatus;
    /** Said until it is dismissed, a connection is made, or the next "Restart to update". */
    after: readonly AfterUpdateNotice[];
    /** Said after a "Restart to update" that did not install; `null` otherwise. */
    notice: InstallNotice | null;
    /** When a check last reached a verdict, in milliseconds since 1970; `null` if none has yet. */
    lastChecked: number | null;
}

/** What the Settings screen may ask about updates. */
export interface UpdatesApi {
    get(): Promise<UpdateView>;
    /** Checks now, unless a check or a download is under way. The outcome arrives through `onChange`. */
    checkNow(): Promise<void>;
    /**
     * "Restart to update": disconnects, installs the downloaded update behind
     * one administrator prompt, and starts the app again. Does nothing unless
     * one is ready. The outcome arrives through `onChange`.
     */
    install(): Promise<void>;
    /** Puts away what the app had to say after an update. */
    dismiss(): Promise<void>;
    onChange(listener: (view: UpdateView) => void): () => void;
}

export const UPDATES_IPC = {
    get: "updates:get",
    checkNow: "updates:check-now",
    install: "updates:install",
    dismiss: "updates:dismiss",
    /** From the main process: where updates now stand. */
    changed: "updates:changed",
} as const;
