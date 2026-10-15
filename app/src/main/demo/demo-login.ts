// DEMO ONLY. A stand-in for the command-line client's side of a login, so the
// login screens can be designed and shown with no backend. It asks for a
// password and a one-time code, accepts anything, and then has the fake
// service connect. Imported only behind `__DEMO__`.

import type { LoginPrompt, LoginState } from "@shared/api";
import type { LoginErrorCode } from "@shared/protocol/LoginErrorCode";
import type { LoginRunner } from "../channel/connect";

const PASSWORD: LoginPrompt = { id: 1, kind: "password", label: "Password" };
const CODE: LoginPrompt = { id: 2, kind: "code", label: "Enter the code from your authenticator" };

const FAILURES: Record<Exclude<LoginErrorCode, "cancelled">, string> = {
    wrong_password: "the gateway showed the login form again",
    check_username: "the gateway sent an empty reply to the login",
    pin_mismatch: "the gateway's key matches no pin in the policy",
    gateway_unreachable: "timed out connecting to the gateway",
    route_refused: "198.51.100.0/4 is wider than /8",
    service_unavailable: "the service did not answer",
    busy: "the service is already connected",
    not_owner: "only the owner may do this",
    internal: "",
};

const SCENARIOS: Record<string, LoginState> = {
    "login-working": { phase: "working" },
    "login-cancelling": { phase: "cancelling" },
    "login-password": { phase: "prompt", prompt: PASSWORD },
    "login-password-again": {
        phase: "prompt",
        prompt: { ...PASSWORD, message: "Login failed. Enter your password again." },
    },
    "login-code": { phase: "prompt", prompt: CODE },
    "login-username": {
        phase: "prompt",
        prompt: { id: 3, kind: "username", label: "CWL username" },
    },
    // Whatever else a gateway might ask, in its own words, at awkward length.
    "login-text": {
        phase: "prompt",
        prompt: {
            id: 4,
            kind: "text",
            label: "Which of your registered devices should receive the verification request this time",
            message: `A long notice from the gateway, to show how the screen holds text it did not write. ${"It goes on. ".repeat(12)}`,
        },
    },
    ...Object.fromEntries(
        Object.entries(FAILURES).map(([code, message]) => [
            `login-failed-${code.replaceAll("_", "-")}`,
            { phase: "failed", code: code as LoginErrorCode, message },
        ]),
    ),
};

export const DEMO_LOGIN_SCENARIOS: readonly string[] = Object.keys(SCENARIOS);

export interface DemoLogin extends LoginRunner {
    /** Jumps to a named login state. Any other name ends the login. */
    setScenario(name: string): void;
}

/** `connect` is what a finished login leads to: the fake service connecting. */
export function createDemoLogin(
    onState: (state: LoginState) => void,
    connect: () => void,
    stepMs = 1400,
): DemoLogin {
    let state: LoginState = { phase: "idle" };
    let timer: NodeJS.Timeout | null = null;

    const set = (next: LoginState) => {
        if (timer !== null) {
            clearTimeout(timer);
            timer = null;
        }
        state = next;
        onState(next);
    };
    /** Shows "working" for a moment, then does `then`. */
    const workThen = (then: () => void) => {
        set({ phase: "working" });
        timer = setTimeout(then, stepMs);
    };

    return {
        start: () => {
            if (state.phase === "working" || state.phase === "prompt") {
                return false;
            }
            workThen(() => set({ phase: "prompt", prompt: PASSWORD }));
            return true;
        },
        answer: (id) => {
            if (state.phase !== "prompt" || state.prompt.id !== id) {
                return false;
            }
            if (id === PASSWORD.id) {
                workThen(() => set({ phase: "prompt", prompt: CODE }));
            } else {
                workThen(() => {
                    set({ phase: "idle" });
                    connect();
                });
            }
            return true;
        },
        cancel: () => set({ phase: "idle" }),
        stop: () => set({ phase: "idle" }),
        windDown: () => null,
        setScenario: (name) => {
            set(
                Object.hasOwn(SCENARIOS, name)
                    ? (SCENARIOS[name] as LoginState)
                    : { phase: "idle" },
            );
        },
    };
}
