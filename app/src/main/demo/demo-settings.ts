// DEMO ONLY. An in-memory stand-in for `ubc-vpn settings`, so the Routes
// screen can be designed and shown with no backend. Its checks are a rough
// copy of the real rules, enough to exercise every message; the real ones
// live in the command-line client and are the only ones that count.
// Imported only behind `__DEMO__`.

import type { SettingsResult } from "@shared/api";
import type { RouteInput } from "@shared/protocol/RouteInput";
import type { RouteProblem } from "@shared/protocol/RouteProblem";
import type { RouteProblemCode } from "@shared/protocol/RouteProblemCode";
import type { RoutesReply } from "@shared/protocol/RoutesReply";
import type { SettingsView } from "@shared/protocol/SettingsView";
import type { SettingsService } from "../channel/settings";

const MIN_PREFIX = 8;
const MAX_ROUTES = 256;
// 198.51.100.0/24 and 203.0.113.0/24 are reserved for documentation.
const ALLOWED = ["203.0.113.0/24", "198.51.100.0/24"];

const view = (
    overrides: Partial<SettingsView> = {},
    routes: Partial<RouteInput> = {},
): SettingsView => ({
    settings: {
        username: "someone",
        routes: {
            subnets: ["203.0.113.0/24", "198.51.100.0/25"],
            dns_domains: ["campus.example"],
            ...routes,
        },
        save_password: false,
    },
    policy_readable: true,
    allowed_routes: ALLOWED,
    min_prefix_len: MIN_PREFIX,
    max_routes: MAX_ROUTES,
    ...overrides,
});

type Scenario = {
    view?: SettingsView;
    /** What `get` answers when it is not a view. `loading` never answers. */
    get?: "loading" | "unreadable" | "unavailable";
    /** What a save answers when it is not the usual check. */
    save?: "unwritable" | "bad_input" | "unavailable";
};

const SCENARIOS: Record<string, Scenario> = {
    routes: { view: view() },
    "routes-empty": { view: view({}, { subnets: [], dns_domains: [] }) },
    "routes-problems": {
        view: view(
            {},
            {
                subnets: [
                    "203.0.113.0/24",
                    "10.0.0.0/4",
                    "not a subnet",
                    "127.0.0.0/8",
                    "192.0.2.0/24",
                ],
                dns_domains: [
                    "campus.example",
                    "Campus.Example",
                    "an-extremely-long-department-name-that-does-not-break.research.campus.example",
                ],
            },
        ),
    },
    "routes-crowded": {
        view: view(
            { allowed_routes: null },
            {
                subnets: Array.from({ length: 256 }, (_, i) => `203.0.113.${i}/32`),
                dns_domains: Array.from({ length: 40 }, (_, i) => `lab-${i + 1}.campus.example`),
            },
        ),
    },
    "routes-no-limit": { view: view({ allowed_routes: null }) },
    "routes-no-policy": { view: view({ policy_readable: false, allowed_routes: null }) },
    "routes-loading": { get: "loading" },
    "routes-unreadable": { get: "unreadable" },
    "routes-unavailable": { get: "unavailable" },
    "routes-cannot-save": { view: view(), save: "unwritable" },
    "routes-too-long-to-save": { view: view(), save: "bad_input" },
};

export const DEMO_SETTINGS_SCENARIOS: readonly string[] = Object.keys(SCENARIOS);

function octets(address: string): number[] | null {
    const parts = address.split(".").map(Number);
    return parts.length === 4 &&
        parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
        ? parts
        : null;
}

/** Whether `inner` lies inside `outer`, both as address/length. */
function inside(inner: string, outer: string): boolean {
    const [innerAddress = "", innerLength = "0"] = inner.split("/");
    const [outerAddress = "", outerLength = "0"] = outer.split("/");
    const bits = (address: string) =>
        (octets(address) ?? []).reduce((all, part) => all * 256 + part, 0);
    const size = 2 ** (32 - Number(outerLength));
    return (
        Number(innerLength) >= Number(outerLength) &&
        Math.floor(bits(innerAddress) / size) === Math.floor(bits(outerAddress) / size)
    );
}

function subnetProblem(entry: string, allowed: readonly string[] | null): RouteProblemCode | null {
    const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(entry);
    const parts = match === null ? null : octets(match[1] ?? "");
    const length = Number(match?.[2]);
    if (parts === null || length > 32) {
        return "bad_subnet";
    }
    if (length < MIN_PREFIX) {
        return "too_wide";
    }
    const [first = 0, second = 0] = parts;
    if (first === 0 || first === 127 || first >= 224 || (first === 169 && second === 254)) {
        return "reserved";
    }
    return allowed !== null && !allowed.some((network) => inside(entry, network))
        ? "not_allowed"
        : null;
}

function check(input: RouteInput, allowed: readonly string[] | null): RoutesReply {
    const problems: RouteProblem[] = [];
    if (input.subnets.length === 0) {
        problems.push({ code: "no_subnets", list: null, index: null });
    }
    if (input.subnets.length > MAX_ROUTES || input.dns_domains.length > MAX_ROUTES) {
        return {
            type: "invalid",
            problems: [...problems, { code: "too_many", list: null, index: null }],
        };
    }
    input.subnets.forEach((entry, index) => {
        const code = subnetProblem(entry, allowed);
        if (code !== null) {
            problems.push({ code, list: "subnets", index });
        }
    });
    input.dns_domains.forEach((entry, index) => {
        if (!/^[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/.test(entry) || entry.length > 253) {
            problems.push({ code: "bad_domain", list: "dns_domains", index });
        }
    });
    return problems.length > 0 ? { type: "invalid", problems } : { type: "ok", routes: input };
}

export interface DemoSettings extends SettingsService {
    /** Puts the fake settings into a named state. Other names are ignored. */
    setScenario(name: string): void;
}

export function createDemoSettings(stepMs = 300): DemoSettings {
    let scenario: Scenario = SCENARIOS.routes as Scenario;
    let current = scenario.view ?? view();
    const later = <T>(value: T) =>
        new Promise<T>((resolve) => setTimeout(() => resolve(value), stepMs));

    // Reads that are being kept waiting, to show the "reading" state. Each
    // is answered when the scenario changes. A read that nothing could ever
    // answer is, to Electron, a reply that was never sent, and it says so
    // on the page at some later moment of its own choosing.
    const waiting: ((result: SettingsResult<SettingsView>) => void)[] = [];
    const answer = (): SettingsResult<SettingsView> =>
        scenario.get === undefined || scenario.get === "loading"
            ? { ok: true, value: current }
            : { ok: false, error: scenario.get };

    return {
        getSettings: () => {
            if (scenario.get === "loading") {
                return new Promise<SettingsResult<SettingsView>>((resolve) => {
                    waiting.push(resolve);
                });
            }
            return later(answer());
        },
        checkRoutes: (input) => later({ ok: true, value: check(input, current.allowed_routes) }),
        saveRoutes: (input) => {
            if (scenario.save !== undefined) {
                return later({ ok: false, error: scenario.save });
            }
            const reply = check(input, current.allowed_routes);
            if (reply.type === "ok") {
                current = { ...current, settings: { ...current.settings, routes: reply.routes } };
            }
            return later({ ok: true, value: reply });
        },
        stop: () => {},
        setScenario: (name) => {
            if (Object.hasOwn(SCENARIOS, name)) {
                scenario = SCENARIOS[name] as Scenario;
                current = scenario.view ?? current;
                if (scenario.get !== "loading") {
                    for (const resolve of waiting.splice(0)) {
                        resolve(answer());
                    }
                }
            }
        },
    };
}
