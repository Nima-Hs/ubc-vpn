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
    | { phase: "failed"; reason: UpdateFailure };

export interface UpdateView {
    status: UpdateStatus;
    /** When a check last reached a verdict, in milliseconds since 1970; `null` if none has yet. */
    lastChecked: number | null;
}

/** What the Settings screen may ask about updates. */
export interface UpdatesApi {
    get(): Promise<UpdateView>;
    /** Checks now, unless a check or a download is under way. The outcome arrives through `onChange`. */
    checkNow(): Promise<void>;
    onChange(listener: (view: UpdateView) => void): () => void;
}

export const UPDATES_IPC = {
    get: "updates:get",
    checkNow: "updates:check-now",
    /** From the main process: where updates now stand. */
    changed: "updates:changed",
} as const;
