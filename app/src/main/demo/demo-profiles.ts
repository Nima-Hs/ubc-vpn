// DEMO ONLY. An in-memory stand-in for the client's profiles commands, so the
// Settings screen can be designed and shown in every state with no backend.
// It follows the rules of `crates/core/src/profiles.rs` as far as the screen
// can tell: names are trimmed, 1 to 64 characters, and unique ignoring case;
// the last profile cannot be deleted; changing a username, or no longer
// saving the password, forgets a saved one. It is imported only behind
// `__DEMO__`, and `scripts/check-production-build.mjs` fails if any of it is
// emitted.

import {
    MAX_NAME_CHARS,
    MAX_PROFILES,
    type ProfilesError,
    type ProfilesResult,
} from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { ProfileView } from "@shared/protocol/ProfileView";
import type { StartMode } from "@shared/protocol/StartMode";
import type { ProfileChange, ProfilesService } from "../channel/profiles";

// Made-up ids, names and addresses: 203.0.113.0/24 and 198.51.100.0/24 are
// for documentation, and `.example` never resolves.
const CAMPUS = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const LAB = "1b2c3d4e5f60718293a4b5c6d7e8f90a";

const campus = (): ProfileView => ({
    id: CAMPUS,
    name: "UBC VPN",
    username: "someone.example",
    routes: { subnets: ["203.0.113.0/24"], dns_domains: ["campus.example"] },
    save_password: true,
    password_saved: true,
});

const lab = (): ProfileView => ({
    id: LAB,
    name: "Lab",
    username: "someone.lab@app",
    routes: { subnets: ["198.51.100.0/24"], dns_domains: ["lab.campus.example"] },
    save_password: false,
    password_saved: false,
});

function fresh(): ProfilesView {
    return {
        global: { start: "off", auto_connect: false, active_profile: CAMPUS, tunnel: "split" },
        profiles: [campus()],
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
    /**
     * Turning saving the password back on is refused: an old saved password
     * that was set aside could not be removed from the keyring.
     */
    stuckPassword?: boolean;
}

const withActive = (view: ProfilesView, change: Partial<ProfileView>): ProfilesView => ({
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
    "settings-profiles": { view: (view) => ({ ...view, profiles: [campus(), lab()] }) },
    "settings-many-profiles": {
        view: (view) => ({
            ...view,
            profiles: [
                campus(),
                lab(),
                ...Array.from({ length: 10 }, (_, i) => ({
                    ...lab(),
                    id: `${(i + 2).toString(16).padStart(2, "0")}${LAB.slice(2)}`,
                    name: `A department with a long name, number ${i + 1}`,
                })),
            ],
        }),
    },
    "settings-old-password-stuck": {
        view: (view) => withActive(view, { save_password: false, password_saved: false }),
        stuckPassword: true,
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

/** Characters that could make a name look like something it is not. */
const MISLEADING = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** A name made fit to store, or why not; as `check_name` does. */
function checkName(name: string): string | null {
    const trimmed = name.trim();
    const length = [...trimmed].length;
    return length >= 1 && length <= MAX_NAME_CHARS && !MISLEADING.test(trimmed) ? trimmed : null;
}

export function createDemoProfiles(): DemoProfiles {
    let view = fresh();
    let scenario: Scenario = {};
    let loading = false;
    let made = 0;
    /** A copy, as the real client sends a new view each time. */
    const answer = (): ProfilesResult => ({ ok: true, value: structuredClone(view) });
    const refuse = (error: ProfilesError): Promise<ProfilesResult> =>
        Promise.resolve({ ok: false, error });
    const change = (apply: () => ProfilesError | null): Promise<ProfilesResult> => {
        if (scenario.change !== undefined) {
            return refuse(scenario.change);
        }
        const refused = apply();
        return refused === null ? Promise.resolve(answer()) : refuse(refused);
    };
    const find = (id: ProfileId) => view.profiles.find((profile) => profile.id === id);
    const nameTaken = (name: string, except: ProfileId | null) =>
        view.profiles.some(
            (profile) => profile.id !== except && profile.name.toLowerCase() === name.toLowerCase(),
        );
    const edit = (id: ProfileId, changed: Partial<ProfileView>) => {
        view = {
            ...view,
            profiles: view.profiles.map((profile) =>
                profile.id === id ? { ...profile, ...changed } : profile,
            ),
        };
    };

    return {
        list: () => {
            if (loading) {
                return new Promise(() => {});
            }
            return scenario.list === undefined ? Promise.resolve(answer()) : refuse(scenario.list);
        },
        setStartup: (start: StartMode, autoConnect: boolean) =>
            change(() => {
                view = { ...view, global: { ...view.global, start, auto_connect: autoConnect } };
                return null;
            }),
        forgetPassword: (id: ProfileId | null) =>
            change(() => {
                const target = id ?? view.global.active_profile;
                if (find(target) === undefined) {
                    return "unknown_profile";
                }
                edit(target, { password_saved: false });
                return null;
            }),
        create: (name: string) =>
            change(() => {
                const checked = checkName(name);
                if (checked === null) {
                    return "bad_name";
                }
                if (nameTaken(checked, null)) {
                    return "name_taken";
                }
                if (view.profiles.length >= MAX_PROFILES) {
                    return "too_many_profiles";
                }
                made += 1;
                const id = `${made.toString(16).padStart(8, "0")}${"f".repeat(24)}`;
                view = {
                    ...view,
                    profiles: [
                        ...view.profiles,
                        {
                            id,
                            name: checked,
                            username: null,
                            routes: { subnets: [], dns_domains: [] },
                            save_password: false,
                            password_saved: false,
                        },
                    ],
                };
                return null;
            }),
        rename: (id: ProfileId, name: string) =>
            change(() => {
                const checked = checkName(name);
                if (find(id) === undefined) {
                    return "unknown_profile";
                }
                if (checked === null) {
                    return "bad_name";
                }
                if (nameTaken(checked, id)) {
                    return "name_taken";
                }
                // A rename keeps the saved password.
                edit(id, { name: checked });
                return null;
            }),
        update: (id: ProfileId, changed: ProfileChange) =>
            change(() => {
                const profile = find(id);
                if (profile === undefined) {
                    return "unknown_profile";
                }
                const next: Partial<ProfileView> = {};
                if (changed.username !== undefined) {
                    const username = changed.username === null ? null : changed.username.trim();
                    if (username !== null && (username === "" || /\s/.test(username))) {
                        return "bad_username";
                    }
                    if (username !== profile.username) {
                        // A new username forgets the old one's password.
                        next.username = username;
                        next.password_saved = false;
                    }
                }
                if (changed.save_password === true && scenario.stuckPassword === true) {
                    return "keyring_not_cleared";
                }
                if (changed.save_password !== undefined) {
                    if (changed.save_password && view.keyring === "unavailable") {
                        return "bad_input";
                    }
                    next.save_password = changed.save_password;
                    if (!changed.save_password) {
                        next.password_saved = false;
                    }
                }
                edit(id, next);
                return null;
            }),
        remove: (id: ProfileId) =>
            change(() => {
                if (find(id) === undefined) {
                    return "unknown_profile";
                }
                if (view.profiles.length === 1) {
                    return "last_profile";
                }
                const profiles = view.profiles.filter((profile) => profile.id !== id);
                const active =
                    view.global.active_profile === id
                        ? (profiles[0] as ProfileView).id
                        : view.global.active_profile;
                view = { ...view, profiles, global: { ...view.global, active_profile: active } };
                return null;
            }),
        switchTo: (id: ProfileId) =>
            change(() => {
                if (find(id) === undefined) {
                    return "unknown_profile";
                }
                view = { ...view, global: { ...view.global, active_profile: id } };
                return null;
            }),
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
