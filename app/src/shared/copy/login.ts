// The words of a login: the questions the gateway asks, how a hidden answer
// is shown, and why a login failed.

import type { LinkState, LoginPrompt, LoginState } from "../api";
import type { LoginErrorCode } from "../protocol/LoginErrorCode";
import type { PromptKind } from "../protocol/PromptKind";
import { FAILURES, type Failure } from "./failures";

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

/**
 * The button that shows or hides what is typed in a hidden answer, named for
 * what pressing it does. `null` for a question whose answer is shown anyway.
 */
export function describeReveal(kind: PromptKind, shown: boolean): { label: string } | null {
    if (!isSecretKind(kind)) {
        return null;
    }
    const thing = kind === "password" ? "password" : kind === "code" ? "code" : "answer";
    return { label: `${shown ? "Hide" : "Show"} ${thing}` };
}

/**
 * Whether a question's answer is hidden as it is typed. Only the two kinds
 * known to be plain are shown: a kind added later, or one the app does not
 * know, is hidden until the user shows it.
 */
export function isSecretKind(kind: string): boolean {
    return kind !== "username" && kind !== "text";
}

/** What can happen to a hidden answer that the user has shown. */
export type RevealEvent = "toggle" | "submit" | "blur";

/**
 * Whether a hidden answer is shown after `event`. It starts hidden; only the
 * button shows it, and sending it or leaving the window hides it again, so it
 * is never left on screen for someone else to read.
 */
export function revealAfter(shown: boolean, event: RevealEvent): boolean {
    return event === "toggle" ? !shown : false;
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
        body: "UBC did not take the login. Check your username: it is your CWL username, your department and the way to confirm, as CWL.dept@method, for example jdoe.dept@app.",
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
