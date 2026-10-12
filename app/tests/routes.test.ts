import type { SettingsError } from "@shared/api";
import {
    describeRouteLimits,
    describeRouteProblem,
    describeSettingsError,
    ROUTES,
} from "@shared/copy";
import type { RouteProblemCode } from "@shared/protocol/RouteProblemCode";
import { beforeEach, describe, expect, it } from "vitest";
import { createDemoSettings, DEMO_SETTINGS_SCENARIOS } from "../src/main/demo/demo-settings";
import { leave, setUnsaved, show, stay, useNavigation } from "../src/renderer/src/lib/navigation";

const LIMITS = { min_prefix_len: 8, max_routes: 256 };
const CODES: RouteProblemCode[] = [
    "no_subnets",
    "too_many",
    "bad_subnet",
    "too_wide",
    "reserved",
    "not_allowed",
    "bad_domain",
];
const ERRORS: SettingsError[] = ["bad_input", "unreadable", "unwritable", "unavailable", "busy"];

const VIEW_LIMITS = { ...LIMITS, policy_readable: true, allowed_routes: null };

describe("the words on the Routes screen", () => {
    it("gives every problem its own wording, with how to put it right", () => {
        const texts = CODES.map((code) => describeRouteProblem(code, LIMITS));
        expect(new Set(texts).size).toBe(CODES.length);
        for (const text of texts) {
            expect(text).not.toMatch(/!|\binvalid\b|\bplease\b|\boops\b/i);
            expect(text).toMatch(/\.$/);
        }
    });

    it("says the limits in the numbers the client gave", () => {
        expect(describeRouteProblem("too_wide", { min_prefix_len: 12, max_routes: 9 })).toContain(
            "/12",
        );
        expect(describeRouteProblem("too_many", { min_prefix_len: 12, max_routes: 9 })).toContain(
            "more than 9",
        );
    });

    it("says the limits up front, and how the policy bears on them", () => {
        const base = { ...LIMITS, policy_readable: true, allowed_routes: null };
        expect(describeRouteLimits(base)).toEqual({
            limits: "A subnet can be no larger than /8: the number after the slash must be 8 or more. You can list up to 256 subnets and 256 domains.",
        });
        expect(
            describeRouteLimits({ ...base, allowed_routes: ["203.0.113.0/24"] }).allowed,
        ).toContain("must be inside");
        // No usable policy is not the same as a policy that sets no limit.
        const noPolicy = describeRouteLimits({ ...base, policy_readable: false });
        expect(noPolicy.noPolicy).toContain("missing or damaged");
        expect(noPolicy.noPolicy).toContain("Install UBC VPN again");
        expect(noPolicy.allowed).toBeUndefined();
    });

    it("says routes are too long to save, on the form, when a save is refused as bad input", () => {
        expect(describeSettingsError("bad_input", "save")).toBe(
            "These routes are too long to save. Remove some entries, then save again.",
        );
    });

    it("has words for every way reading, checking and saving can fail", () => {
        for (const doing of ["read", "check", "save"] as const) {
            for (const error of ERRORS) {
                const text = describeSettingsError(error, doing);
                expect(text.length, `${error} ${doing}`).toBeGreaterThan(20);
                expect(text).not.toMatch(/!|\bplease\b|\boops\b/i);
            }
        }
        expect(describeSettingsError("unwritable", "save")).toContain("the old ones are unchanged");
        // A reinstall never touches the user's settings file, so it is not offered.
        expect(describeSettingsError("unreadable", "read")).not.toMatch(/install/i);
    });

    it("says the size rule one way, and nothing for a check a newer one replaced", () => {
        const said = [
            describeRouteLimits(VIEW_LIMITS).limits,
            describeRouteProblem("too_wide", LIMITS),
        ];
        for (const text of said) {
            expect(text).toContain("after the slash");
            expect(text).not.toMatch(/narrow|wide|prefix/i);
        }
        for (const doing of ["read", "check", "save"] as const) {
            expect(describeSettingsError("superseded", doing)).toBe("");
        }
        expect(ROUTES.whileConnected).toBe("Changes apply the next time you connect.");
    });
});

describe("the demo settings", () => {
    it("reports each problem against its own entry, or against the whole input", async () => {
        const demo = createDemoSettings(1);
        const reply = await demo.checkRoutes({
            subnets: ["203.0.113.0/24", "10.0.0.0/4", "nonsense", "127.0.0.0/8", "192.0.2.0/24"],
            dns_domains: ["campus.example", "Campus.Example"],
        });
        expect(reply).toEqual({
            ok: true,
            value: {
                type: "invalid",
                problems: [
                    { code: "too_wide", list: "subnets", index: 1 },
                    { code: "bad_subnet", list: "subnets", index: 2 },
                    { code: "reserved", list: "subnets", index: 3 },
                    { code: "not_allowed", list: "subnets", index: 4 },
                    { code: "bad_domain", list: "dns_domains", index: 1 },
                ],
            },
        });
        await expect(demo.checkRoutes({ subnets: [], dns_domains: [] })).resolves.toMatchObject({
            value: { problems: [{ code: "no_subnets", list: null, index: null }] },
        });
    });

    it("saves what passes, and shows it on the next read", async () => {
        const demo = createDemoSettings(1);
        const routes = { subnets: ["198.51.100.0/24"], dns_domains: [] };
        await expect(demo.saveRoutes(routes)).resolves.toEqual({
            ok: true,
            value: { type: "ok", routes },
        });
        await expect(demo.getSettings()).resolves.toMatchObject({
            value: { settings: { routes } },
        });
        // What does not pass is not saved.
        await demo.saveRoutes({ subnets: ["nonsense"], dns_domains: [] });
        await expect(demo.getSettings()).resolves.toMatchObject({
            value: { settings: { routes } },
        });
    });

    it("can show every state of the screen", async () => {
        const demo = createDemoSettings(1);
        expect(DEMO_SETTINGS_SCENARIOS).toContain("routes-too-long-to-save");
        demo.setScenario("routes-unreadable");
        await expect(demo.getSettings()).resolves.toEqual({ ok: false, error: "unreadable" });
        demo.setScenario("routes-too-long-to-save");
        await expect(
            demo.saveRoutes({ subnets: ["203.0.113.0/24"], dns_domains: [] }),
        ).resolves.toEqual({
            ok: false,
            error: "bad_input",
        });
        demo.setScenario("routes-no-policy");
        await expect(demo.getSettings()).resolves.toMatchObject({
            value: { policy_readable: false, allowed_routes: null },
        });
        // A name it does not have changes nothing.
        demo.setScenario("__proto__");
        await expect(demo.getSettings()).resolves.toMatchObject({
            value: { policy_readable: false },
        });
    });
});

describe("leaving a screen", () => {
    beforeEach(() => useNavigation.setState({ current: "routes", unsaved: false, wanted: null }));

    it("is immediate when nothing would be lost", () => {
        show("connection");
        expect(useNavigation.getState()).toMatchObject({ current: "connection", wanted: null });
    });

    it("waits for the user's say when there are unsaved changes", () => {
        setUnsaved(true);
        show("connection");
        expect(useNavigation.getState()).toMatchObject({ current: "routes", wanted: "connection" });
        // Staying keeps the changes and forgets the request.
        stay();
        expect(useNavigation.getState()).toMatchObject({
            current: "routes",
            wanted: null,
            unsaved: true,
        });
        // Leaving goes where the user asked, and the changes are gone.
        show("connection");
        leave();
        expect(useNavigation.getState()).toEqual({
            current: "connection",
            wanted: null,
            unsaved: false,
        });
    });

    it("does not ask about the screen already showing", () => {
        setUnsaved(true);
        show("routes");
        expect(useNavigation.getState().wanted).toBeNull();
    });
});
