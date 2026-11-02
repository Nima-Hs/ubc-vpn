// The tray menu's words about profiles.

import type { LinkState } from "../api";

/** The tray menu's list of profiles. */
export const TRAY_PROFILE = "Profile";

/** Atop the tray's profiles while a login is under way, when they cannot be changed. */
export const TRAY_PROFILE_DURING_LOGIN = "You can change profile once this login ends.";

/**
 * Said wherever a profile is chosen while a connection is up or on its way:
 * the connection keeps the routes it started with, and the profile chosen is
 * used by the next connect. `null` when there is nothing to say.
 */
export function profileSwitchNote(state: LinkState): string | null {
    if (state.link !== "ready") {
        return null;
    }
    const { state: conn } = state.conn;
    return conn === "connected" || conn === "connecting" || conn === "disconnecting"
        ? "Takes effect the next time you connect."
        : null;
}
