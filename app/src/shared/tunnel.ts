// Split or full tunnel: one setting for every profile, which the main
// screen, Settings and the tray all show and change. The main process owns
// where a switch stands and puts it in the snapshot, so all three always
// agree. The setting is saved, and a live connection switched, by the
// command-line client (`settings set-tunnel`, `crates/core/src/settings_cli.rs`).

import type { LinkState } from "./api";
import type { ProfilesError } from "./profiles";
import type { TunnelMode } from "./protocol/TunnelMode";

/** What came of a switch, when there is something to say about it. */
export type TunnelOutcome =
    /** The service would not switch the live connection, which keeps `kept`. */
    | { kind: "refused"; kept: TunnelMode; wanted: TunnelMode; message: string }
    /** The policy forbids full mode. Nothing was saved. */
    | { kind: "forbidden" }
    /** The service did not say in time whether the connection was switched. */
    | { kind: "unknown"; wanted: TunnelMode; message: string }
    /** The choice could not be saved, so nothing changed. */
    | { kind: "not_saved"; wanted: TunnelMode; error: ProfilesError };

/** Where the tunnel setting stands. Part of every snapshot. */
export interface TunnelStatus {
    /** The mode saved for the next connect; `null` until it has been read. */
    saved: TunnelMode | null;
    /** Whether the policy lets full mode be chosen. */
    fullAllowed: boolean;
    /** A switch under way, from the mode shown when it started. */
    switching: { from: TunnelMode; to: TunnelMode } | null;
    /** What came of the last switch, until another starts or the connection changes. */
    outcome: TunnelOutcome | null;
}

export const UNREAD_TUNNEL: TunnelStatus = {
    saved: null,
    fullAllowed: true,
    switching: null,
    outcome: null,
};

export const TUNNEL_MODES: readonly TunnelMode[] = ["split", "full"];

/**
 * The mode everything shows: the one being switched to, else the one a live
 * connection has, else the one saved. Split until anything is known.
 */
export function shownMode(state: LinkState, tunnel: TunnelStatus): TunnelMode {
    if (tunnel.switching !== null) {
        return tunnel.switching.to;
    }
    if (state.link === "ready" && state.conn.state === "connected") {
        return state.conn.tunnel.mode;
    }
    return tunnel.saved ?? "split";
}

/** Whether the connection is up, so a switch changes it in place. */
export function switchesLive(state: LinkState): boolean {
    return state.link === "ready" && state.conn.state === "connected";
}

/**
 * Why the mode cannot be changed just now, or `null` when it can. While a
 * connection is being made or closed, or a login is under way, the mode it
 * uses is already fixed.
 */
export function tunnelLocked(
    state: LinkState,
    tunnel: TunnelStatus,
    loggingIn: boolean,
): string | null {
    if (tunnel.saved === null) {
        return TUNNEL.unread;
    }
    if (tunnel.switching !== null) {
        return null;
    }
    const conn = state.link === "ready" ? state.conn.state : null;
    if (loggingIn || conn === "connecting" || conn === "disconnecting") {
        return TUNNEL.whileConnecting;
    }
    return null;
}

/** The words of the tunnel setting, wherever it is shown. */
export const TUNNEL = {
    legend: "Tunnel",
    names: { split: "Split tunnel", full: "Full tunnel" } satisfies Record<TunnelMode, string>,
    /** Short, for the main screen's choice and the tray. */
    short: { split: "Split", full: "Full" } satisfies Record<TunnelMode, string>,
    hints: {
        split: "Only traffic to UBC networks goes through the VPN. Everything else uses your normal connection.",
        full: "All your traffic goes through UBC, and UBC looks up every web address. Your local network, such as a printer, is still reached directly.",
    } satisfies Record<TunnelMode, string>,
    forbidden: "Full tunnel is turned off by this computer’s VPN policy.",
    /** Beside the choice while connected: said before anyone switches. */
    live: "You stay connected. Connections outside UBC may reset.",
    whileConnecting: "You can change the tunnel once the VPN has connected or disconnected.",
    unread: "Reading your settings…",
    /** Atop the routes while full tunnel is on. */
    routesNotUsed:
        "Full tunnel is on, so all your traffic goes through UBC and this list is not used. It is kept for when you switch back to split tunnel.",
    routesNotUsedTitle: "Not in use",
} as const;

/** The words for what came of a switch: a title, and the reason in plain words. */
export function describeTunnelOutcome(
    outcome: TunnelOutcome,
    describeError: (error: ProfilesError) => string,
): { title: string; body: string } {
    switch (outcome.kind) {
        case "refused":
            return {
                title: `Still on ${TUNNEL.names[outcome.kept].toLowerCase()}`,
                body:
                    outcome.message.trim() === ""
                        ? "The VPN service refused the switch."
                        : outcome.message.trim(),
            };
        case "forbidden":
            return { title: "Full tunnel is not available", body: TUNNEL.forbidden };
        case "unknown":
            return {
                title: "Switch not confirmed",
                body: `UBC VPN could not tell whether the switch to ${TUNNEL.names[outcome.wanted].toLowerCase()} worked. Check the connection, or disconnect and connect again.`,
            };
        case "not_saved":
            return {
                title: `Not switched to ${TUNNEL.names[outcome.wanted].toLowerCase()}`,
                body: describeError(outcome.error),
            };
    }
}
