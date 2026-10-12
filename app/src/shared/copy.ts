// Every word the app shows about the connection, in one place, so the window
// and the tray always say the same thing.
//
// The rules: sentence case, plain words, no exclamation marks. A message about
// a problem says what happened, then what to do next.

import type { ActionError, LinkState } from "./api";
import type { ConnState } from "./protocol/ConnState";
import type { ErrorCode } from "./protocol/ErrorCode";

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
}

const CONNECT = { kind: "connect", label: "Connect" } as const;
const TRY_AGAIN = { kind: "connect", label: "Try again" } as const;
const UPDATE_BOTH = "Install the latest UBC VPN to update both.";

const plural = new Intl.PluralRules("en");

/** "1 subnet", "3 subnets". */
export function count(n: number, one: string, other: string): string {
    return `${n} ${plural.select(n) === "one" ? one : other}`;
}

interface Failure {
    title: string;
    body: string;
    /** Whether trying again could work without the user changing something else first. */
    retry: boolean;
}

const FAILURES: Record<ErrorCode, Failure> = {
    not_owner: {
        title: "Managed by another user",
        body: "Another user of this computer controls the VPN. An administrator can reset the VPN service to hand it over.",
        retry: false,
    },
    not_claimed: {
        title: "Setup not finished",
        body: "The VPN service has not been set up for you yet. Quit UBC VPN and open it again to finish.",
        retry: false,
    },
    protocol_mismatch: {
        title: "Update needed",
        body: `The app and the VPN service are different versions. ${UPDATE_BOTH}`,
        retry: false,
    },
    bad_request: {
        title: "Couldn’t connect",
        body: `The VPN service did not understand the app’s request. ${UPDATE_BOTH}`,
        retry: false,
    },
    route_refused: {
        title: "Route refused",
        body: "The VPN service refused one of your subnets or domains, so nothing was changed. The message below says which one. Remove or fix it, then connect again.",
        retry: true,
    },
    pin_mismatch: {
        title: "Connection blocked",
        body: "The server that answered could not prove it is UBC’s VPN, so nothing was sent to it. Try again from another network, and do not connect from this one while this keeps happening.",
        retry: true,
    },
    login_needed: {
        title: "Log in again",
        body: "Your UBC session has ended, so the VPN is off. Log in to connect again.",
        retry: true,
    },
    gateway_unreachable: {
        title: "Can’t reach UBC",
        body: "UBC’s VPN did not answer. Check your internet connection, then try again.",
        retry: true,
    },
    engine_failed: {
        title: "Tunnel failed",
        body: "The tunnel could not be opened, or it was lost. Your traffic is using your normal connection. Try again.",
        retry: true,
    },
    verification_failed: {
        title: "Routes not confirmed",
        body: "The VPN could not confirm its routes were set correctly, so it turned itself off and removed them. Try again.",
        retry: true,
    },
    busy: {
        title: "Still working",
        body: "The VPN service is finishing the last thing you asked for. Wait a few seconds, then try again.",
        retry: true,
    },
    policy_invalid: {
        title: "Reinstall needed",
        body: "A file the VPN service needs is missing or damaged. Install UBC VPN again to restore it.",
        retry: false,
    },
    internal: {
        title: "Service error",
        body: "Something went wrong inside the VPN service. Try again. If it keeps happening, restart your computer.",
        retry: true,
    },
};

function describeConn(conn: ConnState): StateCopy {
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
                body: "Opening the tunnel and setting up your routes.",
                action: { kind: "connect", label: "Connecting…" },
                working: true,
            };
        case "connected": {
            const subnets = conn.tunnel.subnets.length;
            return {
                tone: "on",
                title: "Connected",
                body:
                    subnets === 0
                        ? "The tunnel is open, but no subnets are routed through it. All your traffic is using your normal connection."
                        : `Traffic to ${count(subnets, "UBC subnet", "UBC subnets")} goes through the VPN. Everything else uses your normal connection.`,
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

/** The words for a state. */
export function describe(state: LinkState): StateCopy {
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
                      title: "Service not understood",
                      body: `UBC VPN’s background service answered, but not in a way this app understands. ${UPDATE_BOTH}`,
                      action: { kind: "retry", label: "Check again" },
                      working: false,
                  };
        case "update_needed": {
            const versions =
                state.serviceVersion === ""
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
        case "not_owner":
            return {
                tone: "problem",
                title: FAILURES.not_owner.title,
                body: FAILURES.not_owner.body,
                action: null,
                working: false,
            };
        case "ready":
            return describeConn(state.conn);
    }
}

export interface NoticeCopy {
    text: string;
    /** The service's own account of a refusal, shown beneath the text. */
    detail?: string;
}

/** The words for an action that did not start. */
export function describeActionError(error: ActionError): NoticeCopy {
    switch (error.kind) {
        case "login_unavailable":
            return {
                text: "This version of UBC VPN cannot log in to UBC yet, so it cannot connect.",
            };
        case "service_unavailable":
            return { text: "The VPN service did not answer. Wait a few seconds, then try again." };
        case "refused": {
            const detail = error.message.trim();
            return { text: FAILURES[error.code].body, ...(detail !== "" && { detail }) };
        }
    }
}
