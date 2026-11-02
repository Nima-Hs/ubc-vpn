// The words for the state of the connection: the window's main screen, its
// title bar and the tray all show them.

import type { LinkState } from "../api";
import type { ConnState } from "../protocol/ConnState";
import type { TunnelMode } from "../protocol/TunnelMode";
import { shownMode, TUNNEL, type TunnelStatus, UNREAD_TUNNEL } from "../tunnel";
import { FAILURES, UPDATE_BOTH } from "./failures";

/** Picks the colour and motion of the status indicator. */
export type Tone = "idle" | "busy" | "on" | "attention" | "problem";

/** What the one main button does. */
export type ActionKind = "connect" | "disconnect" | "retry";

export interface StateCopy {
    tone: Tone;
    /** A few words; the largest text in the window and the tray's tooltip. */
    title: string;
    /** What this state means for the user, and what to do about it. */
    body: string;
    /** The service's own account of a failure, shown beneath the body. */
    detail?: string;
    /** The main button, or `null` when no action would help. */
    action: { kind: ActionKind; label: string } | null;
    /** The button is shown but waiting: something is already under way. */
    working: boolean;
    /**
     * Split or full: what the picture, the tray icon and the taskbar show.
     * The mode being switched to, the one in effect, or the one saved.
     */
    mode: TunnelMode;
}

const CONNECT = { kind: "connect", label: "Connect" } as const;
const TRY_AGAIN = { kind: "connect", label: "Try again" } as const;

const plural = new Intl.PluralRules("en");

/** "1 subnet", "3 subnets". */
export function count(n: number, one: string, other: string): string {
    return `${n} ${plural.select(n) === "one" ? one : other}`;
}

/** The words of the connection details, shown while connected. */
export const DETAILS = {
    label: "Connection details",
    address: "Your VPN address",
    subnets: "Subnets through the VPN",
    domains: "Domains looked up through the VPN",
    /** Full tunnel: everything goes through, and the saved lists are the user's own. */
    traffic: "Through the VPN",
    allTraffic: "All your traffic",
    subnetsFull: "Your saved subnets",
    domainsFull: "Your saved domains",
    none: "None",
    subnetCount: (n: number) => count(n, "subnet", "subnets"),
    domainCount: (n: number) => count(n, "domain", "domains"),
    showEach: (n: number) => `Show all ${n} saved subnets`,
    showCombined: "Show combined ranges",
} as const;

/**
 * The note under a range shown in place of the subnets it was saved as:
 * "Saved as 16 subnets, leaving out 10.20.255.254".
 */
export function describeLeftOut(
    parts: number,
    leftOut: readonly string[],
    addresses: number,
): string {
    const saved = `Saved as ${count(parts, "subnet", "subnets")}`;
    if (addresses === 0) {
        return saved;
    }
    return addresses === 1
        ? `${saved}, leaving out ${leftOut[0]}`
        : `${saved}, leaving out ${count(addresses, "address", "addresses")}`;
}

function describeConn(conn: ConnState, tunnel: TunnelStatus): Omit<StateCopy, "mode"> {
    switch (conn.state) {
        case "disconnected":
            return {
                tone: "idle",
                title: "Not connected",
                body: "All your traffic is using your normal connection.",
                action: CONNECT,
                working: false,
            };
        case "connecting":
            return {
                tone: "busy",
                title: "Connecting",
                body:
                    tunnel.saved === "full"
                        ? "Opening the tunnel. Once it is open, all your traffic will go through UBC."
                        : "Opening the tunnel and setting up your routes.",
                action: { kind: "connect", label: "Connecting…" },
                working: true,
            };
        case "connected": {
            const subnets = conn.tunnel.subnets.length;
            const switching = tunnel.switching;
            if (switching !== null) {
                return {
                    tone: "busy",
                    // Short, so the title keeps to one line and nothing moves.
                    title: "Switching",
                    body: `Moving to ${TUNNEL.names[switching.to].toLowerCase()}. The VPN stays connected.`,
                    action: { kind: "disconnect", label: "Disconnect" },
                    working: false,
                };
            }
            if (conn.tunnel.mode === "full") {
                return {
                    tone: "on",
                    title: "Connected",
                    body: "Full tunnel: all your traffic goes through UBC, and your computer’s name lookups go to UBC’s DNS servers. Your local network is still reached directly.",
                    action: { kind: "disconnect", label: "Disconnect" },
                    working: false,
                };
            }
            return {
                tone: "on",
                title: "Connected",
                body:
                    subnets === 0
                        ? "The tunnel is open, but no subnets are routed through it. All your traffic is using your normal connection."
                        : `Split tunnel: traffic to ${count(subnets, "UBC subnet", "UBC subnets")} goes through the VPN. Everything else uses your normal connection.`,
                action: { kind: "disconnect", label: "Disconnect" },
                working: false,
            };
        }
        case "disconnecting":
            return {
                tone: "busy",
                title: "Disconnecting",
                body: "Closing the tunnel and removing its routes.",
                action: { kind: "disconnect", label: "Disconnecting…" },
                working: true,
            };
        case "login_needed":
            return {
                tone: "attention",
                title: FAILURES.login_needed.title,
                body: FAILURES.login_needed.body,
                action: { kind: "connect", label: "Log in" },
                working: false,
            };
        case "failed": {
            const failure = FAILURES[conn.code];
            const loginNeeded = conn.code === "login_needed";
            return {
                tone: loginNeeded ? "attention" : "problem",
                title: failure.title,
                body: failure.body,
                ...(conn.message.trim() !== "" && { detail: conn.message.trim() }),
                action: loginNeeded
                    ? { kind: "connect", label: "Log in" }
                    : failure.retry
                      ? TRY_AGAIN
                      : null,
                working: false,
            };
        }
    }
}

/**
 * The words for a state, and the mode its picture shows. Without `tunnel`,
 * nothing is known of the tunnel setting, and split is shown.
 */
export function describe(state: LinkState, tunnel: TunnelStatus = UNREAD_TUNNEL): StateCopy {
    return { ...describeLink(state, tunnel), mode: shownMode(state, tunnel) };
}

function describeLink(state: LinkState, tunnel: TunnelStatus): Omit<StateCopy, "mode"> {
    switch (state.link) {
        case "starting":
            return {
                tone: "busy",
                title: "Starting",
                body: "Looking for the VPN service on this computer.",
                action: CONNECT,
                working: true,
            };
        case "unavailable":
            // Two different problems: nothing answered, or something did
            // and the app could not make sense of it.
            return state.reason === "not_running"
                ? {
                      tone: "problem",
                      title: "Service not running",
                      body: "UBC VPN’s background service is not answering, so the app cannot connect. Restart your computer. If that does not help, install UBC VPN again.",
                      action: { kind: "retry", label: "Check again" },
                      working: false,
                  }
                : {
                      tone: "problem",
                      title: "Unexpected reply",
                      body: `UBC VPN’s background service answered, but the app could not understand its reply. ${UPDATE_BOTH}`,
                      action: { kind: "retry", label: "Check again" },
                      working: false,
                  };
        case "update_needed": {
            // The bridge writes "unknown" when the service's reply showed
            // no version. That is not a version number, and is not shown as one.
            const unknown = /^(unknown)?$/i.test(state.serviceVersion.trim());
            const versions = unknown
                ? `This app is version ${state.appVersion} and the VPN service is a different one`
                : `This app is version ${state.appVersion} and the VPN service is version ${state.serviceVersion}`;
            return {
                tone: "attention",
                title: "Update needed",
                body: `${versions}, so they cannot work together. ${UPDATE_BOTH}`,
                action: null,
                working: false,
            };
        }
        case "untrusted_service":
            return {
                tone: "problem",
                title: "Service not verified",
                body: "The app could not confirm that UBC VPN’s background service is the one answering, so it sent it nothing. Do not use the VPN on this computer. Install UBC VPN again, then restart your computer.",
                action: null,
                working: false,
            };
        case "not_owner":
            return {
                tone: "problem",
                title: FAILURES.not_owner.title,
                body: FAILURES.not_owner.body,
                action: null,
                working: false,
            };
        case "ready":
            return describeConn(state.conn, tunnel);
    }
}
