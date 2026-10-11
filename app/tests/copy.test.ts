import type { ActionError, LinkState } from "@shared/api";
import { describe as copyFor, count, describeActionError, type StateCopy } from "@shared/copy";
import type { ErrorCode } from "@shared/protocol/ErrorCode";
import { describe, expect, it } from "vitest";
import { trayKind } from "../src/main/tray-icon";

const TUNNEL = {
    interface: "utun4",
    address: "198.51.100.42",
    subnets: ["203.0.113.0/24", "198.51.100.0/24"],
    dns_domains: ["campus.example"],
};

const CODES: ErrorCode[] = [
    "not_owner",
    "not_claimed",
    "protocol_mismatch",
    "bad_request",
    "route_refused",
    "pin_mismatch",
    "login_needed",
    "gateway_unreachable",
    "engine_failed",
    "verification_failed",
    "busy",
    "policy_invalid",
    "internal",
];

const STATES: LinkState[] = [
    { link: "starting" },
    { link: "unavailable", reason: "not_running" },
    { link: "unavailable", reason: "protocol_error" },
    { link: "update_needed", appVersion: "0.1.0", serviceVersion: "0.2.0" },
    { link: "update_needed", appVersion: "0.1.0", serviceVersion: "" },
    { link: "not_owner" },
    { link: "ready", conn: { state: "disconnected" } },
    { link: "ready", conn: { state: "connecting" } },
    { link: "ready", conn: { state: "connected", tunnel: TUNNEL } },
    { link: "ready", conn: { state: "connected", tunnel: { ...TUNNEL, subnets: [] } } },
    { link: "ready", conn: { state: "disconnecting" } },
    { link: "ready", conn: { state: "login_needed" } },
    ...CODES.map(
        (code): LinkState => ({
            link: "ready",
            conn: { state: "failed", code, message: "the service's own words" },
        }),
    ),
];

const failed = (code: ErrorCode, message = "m"): StateCopy =>
    copyFor({ link: "ready", conn: { state: "failed", code, message } });

describe("the words for each state", () => {
    it("names each connection state plainly, with one action", () => {
        const of = (index: number) => copyFor(STATES[index] as LinkState);
        expect(of(6)).toMatchObject({
            tone: "idle",
            title: "Not connected",
            action: { kind: "connect", label: "Connect" },
            working: false,
        });
        expect(of(7)).toMatchObject({ tone: "busy", title: "Connecting", working: true });
        expect(of(8)).toMatchObject({
            tone: "on",
            title: "Connected",
            body: "Traffic to 2 UBC subnets goes through the VPN. Everything else uses your normal connection.",
            action: { kind: "disconnect", label: "Disconnect" },
        });
        expect(of(10)).toMatchObject({ tone: "busy", title: "Disconnecting", working: true });
        expect(of(11)).toMatchObject({
            tone: "attention",
            title: "Log in again",
            action: { kind: "connect", label: "Log in" },
        });
    });

    it("does not claim traffic is routed when no subnet is", () => {
        const copy = copyFor(STATES[9] as LinkState);
        expect(copy.body).toContain("no subnets are routed");
        expect(copy.body).not.toContain("0 UBC");
    });

    it("counts in words that agree", () => {
        expect(count(1, "UBC subnet", "UBC subnets")).toBe("1 UBC subnet");
        expect(count(2, "UBC subnet", "UBC subnets")).toBe("2 UBC subnets");
        expect(count(0, "UBC subnet", "UBC subnets")).toBe("0 UBC subnets");
    });

    it("gives every error code its own title and its own advice", () => {
        const copies = CODES.map((code) => failed(code));
        // "Couldn't connect" would say nothing; only one code may fall back to it.
        expect(new Set(copies.map((copy) => copy.body)).size).toBe(CODES.length);
        expect(new Set(copies.map((copy) => copy.title)).size).toBeGreaterThanOrEqual(
            CODES.length - 1,
        );
    });

    it("offers to try again only when trying again could work", () => {
        expect(failed("gateway_unreachable").action).toEqual({
            kind: "connect",
            label: "Try again",
        });
        expect(failed("login_needed").action).toEqual({ kind: "connect", label: "Log in" });
        for (const code of [
            "not_owner",
            "policy_invalid",
            "protocol_mismatch",
            "bad_request",
        ] as const) {
            expect(failed(code).action, code).toBeNull();
        }
    });

    it("shows the service's own message beside its explanation, never in place of it", () => {
        const copy = failed("route_refused", "  198.51.100.0/4 is wider than /8 ");
        expect(copy.detail).toBe("198.51.100.0/4 is wider than /8");
        expect(copy.body).not.toContain("198.51.100.0/4");
        expect(failed("internal", "   ").detail).toBeUndefined();
    });

    it("explains a service that is not there, and one that needs updating", () => {
        expect(copyFor({ link: "unavailable", reason: "not_running" })).toMatchObject({
            tone: "problem",
            title: "Service not running",
            action: { kind: "retry", label: "Check again" },
        });
        const update = copyFor({
            link: "update_needed",
            appVersion: "0.1.0",
            serviceVersion: "0.2.0",
        });
        expect(update.title).toBe("Update needed");
        expect(update.body).toContain("version 0.1.0");
        expect(update.body).toContain("version 0.2.0");
        expect(update.action).toBeNull();
        // An unknown service version is not printed as an empty one.
        expect(copyFor(STATES[4] as LinkState).body).not.toContain("version .");
    });

    it("explains an action that did not start", () => {
        const errors: ActionError[] = [
            { kind: "login_unavailable" },
            { kind: "service_unavailable" },
            { kind: "refused", code: "busy", message: "m" },
        ];
        const texts = errors.map(describeActionError);
        expect(texts[0]).toContain("cannot log in to UBC yet");
        expect(new Set(texts).size).toBe(3);
    });
});

describe("the writing rules", () => {
    const everything = [
        ...STATES.map(copyFor).flatMap((copy) => [copy.title, copy.body, copy.action?.label ?? ""]),
        describeActionError({ kind: "login_unavailable" }),
        describeActionError({ kind: "service_unavailable" }),
    ].filter((text) => text !== "");

    it("uses no exclamation marks and no filler", () => {
        for (const text of everything) {
            expect(text).not.toMatch(/!|\boops\b|\bplease\b|\bsuccessfully\b|\bsorry\b/i);
        }
    });

    it("writes in sentence case", () => {
        for (const text of everything) {
            expect(text.charAt(0), text).toMatch(/[A-Z]/);
            // After the first word, capitals belong only to names and new sentences.
            const midSentence = text
                .replace(/\b(UBC|VPN|IT|I)\b/g, "")
                .match(/(?<![.?:] )(?<!^)\b[A-Z][a-z]+/g);
            expect(midSentence, text).toBeNull();
        }
    });

    it("ends every sentence, and keeps titles short", () => {
        for (const copy of STATES.map(copyFor)) {
            expect(copy.body).toMatch(/\.$/);
            expect(copy.title).not.toMatch(/\.$/);
            expect(copy.title.length).toBeLessThanOrEqual(24);
        }
    });

    it("tells the user what to do about every problem", () => {
        const next = /\b(try|check|install|restart|log in|wait|quit|reset|message below)\b/i;
        for (const state of STATES) {
            const copy = copyFor(state);
            if (copy.tone === "problem" || copy.tone === "attention") {
                expect(copy.body, copy.title).toMatch(next);
            }
        }
    });
});

describe("the tray icon's state", () => {
    it("follows the same reading of the state as the window", () => {
        expect(trayKind({ link: "ready", conn: { state: "disconnected" } })).toBe("off");
        expect(trayKind({ link: "ready", conn: { state: "connected", tunnel: TUNNEL } })).toBe(
            "on",
        );
        expect(trayKind({ link: "ready", conn: { state: "connecting" } })).toBe("busy");
        expect(trayKind({ link: "ready", conn: { state: "login_needed" } })).toBe("attention");
        expect(trayKind({ link: "unavailable", reason: "not_running" })).toBe("attention");
    });
});
