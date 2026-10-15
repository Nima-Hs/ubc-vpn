// Every word the app shows about the connection, in one place, so the window
// and the tray always say the same thing.
//
// The rules: sentence case, plain words, no exclamation marks. A message about
// a problem says what happened, then what to do next.

import type { ActionError, LinkState, LoginPrompt, LoginState, SettingsError } from "./api";
import type { ConnState } from "./protocol/ConnState";
import type { ErrorCode } from "./protocol/ErrorCode";
import type { LoginErrorCode } from "./protocol/LoginErrorCode";
import type { PromptKind } from "./protocol/PromptKind";
import type { RouteProblemCode } from "./protocol/RouteProblemCode";
import type { SettingsView } from "./protocol/SettingsView";

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
            return describeConn(state.conn);
    }
}

/** While the command-line client is busy with the gateway. */
export const LOGIN_WORKING = {
    title: "Logging in",
    body: "Waiting for UBC to answer. If you approve logins on your phone, check it now.",
} as const;

/**
 * Whether the login has the screen. It does whenever one is under way, with
 * one exception: a login being wound up waits for the service if the service
 * has gone, and the screen then says what has happened to the service, which
 * is what the user needs to know, and not "Cancelling" for as long as that
 * lasts.
 */
export function loginHasScreen(state: LinkState, login: LoginState): boolean {
    return login.phase !== "idle" && !(login.phase === "cancelling" && state.link !== "ready");
}

export const LOGIN_CANCELLING = {
    title: "Cancelling",
    body: "Stopping the login. This takes a moment.",
} as const;

const PROMPTS: Record<PromptKind, { title: string; body: string }> = {
    username: {
        title: "Your CWL username",
        body: "UBC is asking who you are.",
    },
    password: {
        title: "Your password",
        body: "It is sent to UBC and nowhere else.",
    },
    code: {
        title: "Your one-time code",
        body: "Enter the code from your authenticator app or device.",
    },
    text: {
        title: "UBC has a question",
        body: "Answer in the field below to carry on logging in.",
    },
};

/** The words around a question the gateway asks. The field's label is the gateway's own. */
export function describePrompt(prompt: Pick<LoginPrompt, "kind">): {
    title: string;
    body: string;
    submit: string;
} {
    return { ...PROMPTS[prompt.kind], submit: "Continue" };
}

const LOGIN_FAILURES: Record<LoginErrorCode, Failure> = {
    wrong_password: {
        title: "Login refused",
        body: "UBC did not accept the username, the password or the code, and does not say which. Check them, then try again.",
        retry: true,
    },
    // UBC's gateway reads the way to confirm from the username, so one in
    // another form is refused before any password is judged. The example is
    // made up.
    check_username: {
        title: "Check your username",
        body: "UBC did not take the login. Check your username: it is your CWL username, your department and the way to confirm, as CWL.dept@method, for example user.ece@app.",
        retry: true,
    },
    pin_mismatch: FAILURES.pin_mismatch,
    cancelled: {
        title: "Login cancelled",
        body: "You stopped the login. Connect to start again.",
        retry: true,
    },
    gateway_unreachable: FAILURES.gateway_unreachable,
    // Refused before anything was sent: the saved routes did not pass the
    // check that is made when a login starts.
    route_refused: {
        title: "Route refused",
        body: "One of your subnets or domains is not allowed, so nothing was connected. The message below says which one. Fix it on the Routes screen, then connect again.",
        retry: true,
    },
    service_unavailable: {
        title: "Service not running",
        body: "UBC VPN’s background service did not answer, so nothing was connected. Restart your computer, then try again.",
        retry: true,
    },
    // Nothing to try again: the VPN is in use, and the way on is to go back.
    busy: {
        title: "VPN is busy",
        body: "The VPN is already connected, or is part-way through connecting or disconnecting. Go back and disconnect first, then connect again.",
        retry: false,
    },
    // The same words as when the service itself says so.
    not_owner: FAILURES.not_owner,
    internal: {
        title: "Login did not finish",
        body: "Something went wrong while logging in, and nothing was connected. Try again. If it keeps happening, install UBC VPN again.",
        retry: true,
    },
};

/** The words for a login that failed. `message` is the client's own account of it. */
export function describeLoginFailure(
    code: LoginErrorCode,
    message: string,
): { title: string; body: string; detail?: string; retry: boolean } {
    const failure = LOGIN_FAILURES[code];
    const detail = message.trim();
    return { ...failure, ...(detail !== "" && { detail }) };
}

/** A login under way, in one sentence or two, for a screen reader. */
export function loginAnnouncement(login: Exclude<LoginState, { phase: "idle" }>): string {
    switch (login.phase) {
        case "working":
            return `${LOGIN_WORKING.title}. ${LOGIN_WORKING.body}`;
        case "cancelling":
            return `${LOGIN_CANCELLING.title}. ${LOGIN_CANCELLING.body}`;
        case "prompt": {
            const copy = describePrompt(login.prompt);
            return `${copy.title}. ${login.prompt.message ?? copy.body}`;
        }
        case "failed": {
            const copy = describeLoginFailure(login.code, login.message);
            return `${copy.title}. ${copy.body}`;
        }
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

/** Shown on every screen while the app talks to a dev-mode service. */
export const DEVELOPMENT_MODE = "Development mode. This is not the real VPN.";

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

/** The Routes screen's fixed words. */
export const ROUTES = {
    title: "Routes",
    body: "Only traffic to these subnets goes through the VPN. Everything else uses your normal connection.",
    loading: "Reading your settings…",
    subnets: "Subnets",
    noSubnets: "No subnets yet. Add the UBC networks you want to reach through the VPN.",
    domains: "Domains",
    domainsBody: "Names under these domains are looked up through the VPN.",
    noDomains: "No domains yet. Add one if UBC names should be looked up through the VPN.",
    whileConnected: "Changes apply the next time you connect.",
    saved: "Saved.",
    checking: "Checking…",
    unsaved: "You have changes that are not saved.",
} as const;

/** What the policy and the app allow, said before the user types anything. */
export function describeRouteLimits(
    view: Pick<
        SettingsView,
        "policy_readable" | "allowed_routes" | "min_prefix_len" | "max_routes"
    >,
): { limits: string; allowed?: string; noPolicy?: string } {
    const limits = `A subnet can be no larger than /${view.min_prefix_len}: the number after the slash must be ${view.min_prefix_len} or more. You can list up to ${view.max_routes} subnets and ${view.max_routes} domains.`;
    if (!view.policy_readable) {
        return {
            limits,
            noPolicy:
                "The VPN’s policy file is missing or damaged, so routes cannot be checked against it and the VPN will not connect. Install UBC VPN again to restore it.",
        };
    }
    return view.allowed_routes === null
        ? { limits }
        : {
              limits,
              allowed: "Subnets must be inside one of the networks this installation allows:",
          };
}

/** What is wrong with one entry, or with the whole list, and how to put it right. */
export function describeRouteProblem(
    code: RouteProblemCode,
    limits: Pick<SettingsView, "min_prefix_len" | "max_routes">,
): string {
    switch (code) {
        case "no_subnets":
            return "Add at least one subnet. Without one, nothing goes through the VPN.";
        case "too_many":
            return `There are more than ${limits.max_routes} subnets or more than ${limits.max_routes} domains. Remove some.`;
        case "bad_subnet":
            return "Write a network as address/length with no spaces, such as 203.0.113.0/24. The address must be the first one in the network.";
        case "too_wide":
            return `This subnet is too large. Use /${limits.min_prefix_len} or a larger number after the slash.`;
        case "reserved":
            return "This range is reserved for special uses, such as this computer itself or the local network, and cannot go through the VPN.";
        case "not_allowed":
            return "This subnet is outside the networks this installation allows.";
        case "bad_domain":
            return "Write a plain lower-case name, such as campus.example.";
    }
}

/**
 * Why settings could not be read, checked or saved, and what to do. Empty
 * for the one case that is not a failure the user should hear about.
 */
export function describeSettingsError(
    error: SettingsError,
    doing: "read" | "check" | "save",
): string {
    switch (error) {
        case "unreadable":
            return "Your settings file is damaged, so it has been left as it is and your routes cannot be shown. If you edited it by hand, undo the change.";
        case "unwritable":
            return "Your settings could not be saved, and the old ones are unchanged. Check that your disk is not full, then save again.";
        case "bad_input":
            return doing === "save"
                ? "These routes are too long to save. Remove some entries, then save again."
                : "These routes are too long to check. Remove some entries.";
        case "busy":
            return "A save is already under way. Wait for it to finish.";
        case "superseded":
            // A newer check took this one's place. There is nothing to tell.
            return "";
        case "unavailable":
            return doing === "read"
                ? "UBC VPN could not read your settings. Try again. If it keeps happening, install UBC VPN again."
                : doing === "save"
                  ? "UBC VPN could not save your routes, and nothing was changed. Try again."
                  : "UBC VPN could not check these routes. Try again.";
    }
}
