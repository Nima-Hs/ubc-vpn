// DEMO ONLY. An in-memory stand-in for the client's profiles commands, so the
// Settings screen can be designed and shown in every state with no backend.
// It follows `crates/cli/src/profiles.rs` as far as the screen can tell. It
// is imported only behind `__DEMO__`, and `scripts/check-production-build.mjs`
// fails if any of it is emitted.

import type { ProfilesError, ProfilesResult } from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { StartMode } from "@shared/protocol/StartMode";
import type { ProfilesService } from "../channel/profiles";

// Made-up ids, names and addresses: 203.0.113.0/24 is for documentation.
const CAMPUS = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";

function fresh(): ProfilesView {
    return {
        global: { start: "off", auto_connect: false, active_profile: CAMPUS },
        profiles: [
            {
                id: CAMPUS,
                name: "UBC VPN",
                username: "someone.example",
                routes: { subnets: ["203.0.113.0/24"], dns_domains: ["campus.example"] },
                save_password: true,
                password_saved: true,
            },
        ],
        keyring: "available",
        policy_readable: true,
        allowed_routes: null,
    };
}

interface Scenario {
    /** Changes the view starts from. */
    view?: (view: ProfilesView) => ProfilesView;
    /** What reading answers, when not the view. */
    list?: ProfilesError;
    /** What every change answers, when it is refused. */
    change?: ProfilesError;
}

const withActive = (
    view: ProfilesView,
    change: Partial<ProfilesView["profiles"][number]>,
): ProfilesView => ({
    ...view,
    profiles: view.profiles.map((profile) =>
        profile.id === view.global.active_profile ? { ...profile, ...change } : profile,
    ),
});

const SCENARIOS: Record<string, Scenario> = {
    settings: {},
    "settings-no-password": { view: (view) => withActive(view, { password_saved: false }) },
    "settings-no-keyring": {
        view: (view) => ({
            ...withActive(view, { save_password: false, password_saved: false }),
            keyring: "unavailable",
        }),
    },
    "settings-started-in-tray": {
        view: (view) => ({
            ...view,
            global: { ...view.global, start: "tray", auto_connect: true },
        }),
    },
    "settings-loading": {},
    "settings-unreadable": { list: "unreadable" },
    "settings-unavailable": { list: "unavailable" },
    "settings-cannot-save": { change: "unwritable" },
};

export const DEMO_PROFILES_SCENARIOS: readonly string[] = Object.keys(SCENARIOS);

export interface DemoProfiles extends ProfilesService {
    setScenario(name: string): void;
}

export function createDemoProfiles(): DemoProfiles {
    let view = fresh();
    let scenario: Scenario = {};
    let loading = false;
    /** A copy, as the real client sends a new view each time. */
    const answer = (): ProfilesResult => ({ ok: true, value: structuredClone(view) });
    const refused = (): ProfilesResult | null =>
        scenario.change === undefined ? null : { ok: false, error: scenario.change };

    return {
        list: () => {
            if (loading) {
                return new Promise(() => {});
            }
            return Promise.resolve(
                scenario.list === undefined ? answer() : { ok: false, error: scenario.list },
            );
        },
        setStartup: (start: StartMode, autoConnect: boolean) => {
            const no = refused();
            if (no !== null) {
                return Promise.resolve(no);
            }
            view = { ...view, global: { ...view.global, start, auto_connect: autoConnect } };
            return Promise.resolve(answer());
        },
        forgetPassword: (id: ProfileId | null) => {
            const no = refused();
            if (no !== null) {
                return Promise.resolve(no);
            }
            const target = id ?? view.global.active_profile;
            if (!view.profiles.some((profile) => profile.id === target)) {
                return Promise.resolve({ ok: false, error: "unknown_profile" });
            }
            view = {
                ...view,
                profiles: view.profiles.map((profile) =>
                    profile.id === target ? { ...profile, password_saved: false } : profile,
                ),
            };
            return Promise.resolve(answer());
        },
        stop: () => {},
        setScenario: (name) => {
            if (!Object.hasOwn(SCENARIOS, name)) {
                return;
            }
            scenario = SCENARIOS[name] as Scenario;
            loading = name === "settings-loading";
            view = scenario.view?.(fresh()) ?? fresh();
        },
    };
}
