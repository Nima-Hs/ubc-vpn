import type { LinkState, LoginState } from "@shared/api";
import {
    describe as describe_,
    describeLoginFailure,
    describePrompt,
    describeReveal,
    isSecretKind,
    LOGIN_WORKING,
    loginAnnouncement,
    loginHasScreen,
    revealAfter,
} from "@shared/copy";
import type { LoginErrorCode } from "@shared/protocol/LoginErrorCode";
import type { PromptKind } from "@shared/protocol/PromptKind";
import { describe, expect, it } from "vitest";
import { createDemoLogin, DEMO_LOGIN_SCENARIOS } from "../src/main/demo/demo-login";

const KINDS: PromptKind[] = ["username", "password", "code", "text"];
const CODES: LoginErrorCode[] = [
    "wrong_password",
    "check_username",
    "pin_mismatch",
    "cancelled",
    "gateway_unreachable",
    "route_refused",
    "service_unavailable",
    "busy",
    "not_owner",
    "internal",
];

describe("the words around a login", () => {
    it("gives each kind of question its own heading and one way forward", () => {
        const copies = KINDS.map((kind) => describePrompt({ kind }));
        expect(new Set(copies.map((copy) => copy.title)).size).toBe(KINDS.length);
        expect(new Set(copies.map((copy) => copy.submit))).toEqual(new Set(["Continue"]));
    });

    it("says where a password goes", () => {
        expect(describePrompt({ kind: "password" }).body).toBe(
            "It is sent to UBC and nowhere else.",
        );
    });

    it("gives every failure its own explanation, with what to do next", () => {
        const copies = CODES.map((code) => describeLoginFailure(code, ""));
        expect(new Set(copies.map((copy) => copy.body)).size).toBe(CODES.length);
        const next = /\b(try|check|install|restart|connect|reset|message below)\b/i;
        for (const copy of copies) {
            expect(copy.body, copy.title).toMatch(next);
            expect(copy.title.length, copy.title).toBeLessThanOrEqual(24);
        }
    });

    it("does not say which of the three was wrong, because UBC does not", () => {
        const copy = describeLoginFailure("wrong_password", "");
        expect(copy.title).toBe("Login refused");
        expect(copy.body).toContain("does not say which");
    });

    it("offers no second try when the VPN is already in use, only the way back", () => {
        const copy = describeLoginFailure("busy", "");
        expect(copy.title).toBe("VPN is busy");
        expect(copy.body).toContain("disconnect first");
        expect(copy.retry).toBe(false);
    });

    it("says the same as the rest of the app when another user owns the service", () => {
        const copy = describeLoginFailure("not_owner", "");
        const link = describe_({ link: "not_owner" });
        expect(copy.title).toBe(link.title);
        expect(copy.body).toBe(link.body);
        expect(copy.retry).toBe(false);
    });

    it("says nothing was connected when the service did not answer", () => {
        expect(describeLoginFailure("service_unavailable", "").body).toBe(
            "UBC VPN’s background service did not answer, so nothing was connected. Restart your computer, then try again.",
        );
    });

    it("shows the client's own account beside the explanation, when there is one", () => {
        expect(
            describeLoginFailure("route_refused", " 198.51.100.0/4 is wider than /8 ").detail,
        ).toBe("198.51.100.0/4 is wider than /8");
        expect(describeLoginFailure("internal", "  ").detail).toBeUndefined();
    });

    it("sends a refused route to the Routes screen, and does not blame the service", () => {
        // The saved routes are refused by the check made as a login starts,
        // before anything is sent to the service.
        const { body } = describeLoginFailure("route_refused", "");
        expect(body).toContain("Fix it on the Routes screen");
        expect(body).not.toMatch(/service/i);
    });

    it("follows the writing rules", () => {
        const everything = [
            LOGIN_WORKING.title,
            LOGIN_WORKING.body,
            ...KINDS.flatMap((kind) => Object.values(describePrompt({ kind }))),
            ...CODES.flatMap((code) => {
                const copy = describeLoginFailure(code, "");
                return [copy.title, copy.body];
            }),
        ];
        for (const text of everything) {
            expect(text).not.toMatch(/!|\boops\b|\bplease\b|\bsuccessfully\b|\bsorry\b/i);
            expect(text.charAt(0), text).toMatch(/[A-Z]/);
        }
    });

    it("gives a login the screen, except one being wound up while the service is gone", () => {
        const ready: LinkState = { link: "ready", conn: { state: "disconnected" } };
        const gone: LinkState = { link: "unavailable", reason: "not_running" };
        expect(loginHasScreen(ready, { phase: "idle" })).toBe(false);
        for (const link of [ready, gone]) {
            expect(loginHasScreen(link, { phase: "working" })).toBe(true);
            expect(loginHasScreen(link, { phase: "failed", code: "internal", message: "" })).toBe(
                true,
            );
        }
        expect(loginHasScreen(ready, { phase: "cancelling" })).toBe(true);
        // "Service not running" is what the user needs to see then.
        expect(loginHasScreen(gone, { phase: "cancelling" })).toBe(false);
        expect(loginHasScreen({ link: "starting" }, { phase: "cancelling" })).toBe(false);
    });

    it("has something to read out for every step", () => {
        const states: Exclude<LoginState, { phase: "idle" }>[] = [
            { phase: "working" },
            { phase: "cancelling" },
            { phase: "prompt", prompt: { id: 1, kind: "password", label: "Password" } },
            {
                phase: "prompt",
                prompt: { id: 1, kind: "password", label: "Password", message: "Login failed." },
            },
            { phase: "failed", code: "wrong_password", message: "" },
        ];
        expect(states.map(loginAnnouncement)).toEqual([
            "Logging in. Waiting for UBC to answer. If you approve logins on your phone, check it now.",
            "Cancelling. Stopping the login. This takes a moment.",
            "Your password. It is sent to UBC and nowhere else.",
            // The gateway's reason is what matters when a question comes back.
            "Your password. Login failed.",
            expect.stringContaining("Login refused. UBC did not accept"),
        ]);
    });
});

describe("the demo login", () => {
    it("asks for a password, then a code, then has the fake service connect", async () => {
        const seen: LoginState[] = [];
        let connected = 0;
        const login = createDemoLogin(
            (state) => seen.push(state),
            () => connected++,
            5,
        );
        const phase = () => seen.at(-1)?.phase;
        const until = async (wanted: string) => {
            for (let tries = 0; phase() !== wanted && tries < 400; tries++) {
                await new Promise((resolve) => setTimeout(resolve, 5));
            }
            expect(phase()).toBe(wanted);
        };

        expect(login.start()).toBe(true);
        expect(login.start()).toBe(false);
        await until("prompt");
        expect(login.answer(2, "anything")).toBe(false);
        expect(login.answer(1, "anything")).toBe(true);
        await until("prompt");
        expect(login.answer(2, "anything")).toBe(true);
        await until("idle");
        expect(connected).toBe(1);
        // It holds nothing of what it was given.
        expect(JSON.stringify(seen)).not.toContain("anything");
    });

    it("can show every login state, and ends the login for any other name", () => {
        const seen: LoginState[] = [];
        const login = createDemoLogin(
            (state) => seen.push(state),
            () => {},
            5,
        );
        for (const name of DEMO_LOGIN_SCENARIOS) {
            login.setScenario(name);
            expect(seen.at(-1)?.phase, name).not.toBe("idle");
        }
        expect(
            DEMO_LOGIN_SCENARIOS.filter((name) => name.startsWith("login-failed-")),
        ).toHaveLength(9);
        for (const name of ["disconnected", "__proto__", "constructor"]) {
            login.setScenario(name);
            expect(seen.at(-1)).toEqual({ phase: "idle" });
        }
    });
});

describe("showing a hidden answer", () => {
    it("is offered for a password and a code, named for what pressing it does", () => {
        expect(describeReveal("password", false)).toEqual({ label: "Show password" });
        expect(describeReveal("password", true)).toEqual({ label: "Hide password" });
        expect(describeReveal("code", false)).toEqual({ label: "Show code" });
        expect(describeReveal("code", true)).toEqual({ label: "Hide code" });
        // A username or a question's answer is shown as it is typed.
        expect(describeReveal("username", false)).toBeNull();
        expect(describeReveal("text", false)).toBeNull();
    });

    it("hides any answer whose kind is not known to be plain", () => {
        expect(isSecretKind("password")).toBe(true);
        expect(isSecretKind("code")).toBe(true);
        expect(isSecretKind("username")).toBe(false);
        expect(isSecretKind("text")).toBe(false);
        // A kind a newer client might send, which this app does not know.
        expect(isSecretKind("recovery_key")).toBe(true);
        expect(describeReveal("recovery_key" as PromptKind, false)).toEqual({
            label: "Show answer",
        });
    });

    it("is undone by sending the answer or leaving the window; only the button shows it", () => {
        expect(revealAfter(false, "toggle")).toBe(true);
        expect(revealAfter(true, "toggle")).toBe(false);
        for (const shown of [true, false]) {
            expect(revealAfter(shown, "submit")).toBe(false);
            expect(revealAfter(shown, "blur")).toBe(false);
        }
    });
});
