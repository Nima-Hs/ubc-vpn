// The user's profiles and the settings they share, through the command-line
// client: `profiles …`, `settings set-startup` and `password forget`. The
// contract is `crates/cli/src/profiles.rs`: each command reads at most one
// line and writes one line, the answer with exit status 0, or a refusal
// (`{"error": …}`) with exit status 1, after which nothing has changed.
//
// What the client sends comes from a file the user, or anything running as
// the user, can edit, so names, usernames and routes are cleaned here before
// the interface is given them, as `settings.ts` does. No command ever takes a
// password: the client refuses unknown fields, and none is ever sent.

import type { ProfilesError, ProfilesResult } from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { RouteSet } from "@shared/protocol/RouteSet";
import type { StartMode } from "@shared/protocol/StartMode";
import { markedText, plainText } from "./connect";
import { encodeLine } from "./framing";
import { OneLineCalls, type OneLineOptions } from "./one-line";
import { MAX_SHOWN_LENGTH } from "./settings";
import { isProfileFailure, isProfileId, isProfilesView } from "./validate";

/** What the rest of the main process needs from the profiles, real or fake. */
export interface ProfilesService {
    list(): Promise<ProfilesResult>;
    setStartup(start: StartMode, autoConnect: boolean): Promise<ProfilesResult>;
    forgetPassword(id: ProfileId | null): Promise<ProfilesResult>;
    /** A new profile with this name and nothing else: no username, no routes, no saved password. */
    create(name: string): Promise<ProfilesResult>;
    rename(id: ProfileId, name: string): Promise<ProfilesResult>;
    /** Changes the username, whether the password is saved, or both. Either change forgets a saved password. */
    update(id: ProfileId, change: ProfileChange): Promise<ProfilesResult>;
    /** Deletes a profile and forgets its saved password. The last one cannot be deleted. */
    remove(id: ProfileId): Promise<ProfilesResult>;
    /** Makes a profile the one the next connect uses. */
    switchTo(id: ProfileId): Promise<ProfilesResult>;
    /** Ends every client still running, for when the app quits. */
    stop(): void;
}

/** What `profiles update` may change. A field left out is not changed. */
export interface ProfileChange {
    username?: string | null;
    save_password?: boolean;
}

/** Each command, as its fixed arguments. */
export const PROFILES_ARGS = {
    list: ["profiles", "list", "--json"],
    setStartup: ["settings", "set-startup", "--json"],
    forgetPassword: ["password", "forget", "--json"],
    create: ["profiles", "create", "--json"],
    rename: ["profiles", "rename", "--json"],
    update: ["profiles", "update", "--json"],
    remove: ["profiles", "delete", "--json"],
    switchTo: ["profiles", "switch", "--json"],
} as const;

const UNAVAILABLE = { ok: false, error: "unavailable" } as const;

const shown = (text: string): string => plainText(text, MAX_SHOWN_LENGTH);
// Routes are edited and sent back, so what is removed leaves a mark.
const marked = (text: string): string => markedText(text, MAX_SHOWN_LENGTH);
const shownRoutes = (routes: RouteSet): RouteSet => ({
    subnets: routes.subnets.map(marked),
    dns_domains: routes.dns_domains.map(marked),
});

function shownView(view: ProfilesView): ProfilesView {
    return {
        ...view,
        profiles: view.profiles.map((profile) => ({
            ...profile,
            name: shown(profile.name),
            username: profile.username === null ? null : shown(profile.username),
            routes: shownRoutes(profile.routes),
        })),
        allowed_routes: view.allowed_routes?.map(shown) ?? null,
    };
}

export class ProfilesRunner implements ProfilesService {
    private readonly calls: OneLineCalls;
    private reading: Promise<ProfilesResult> | null = null;
    private changing = false;

    constructor(options: OneLineOptions) {
        this.calls = new OneLineCalls(options);
    }

    list(): Promise<ProfilesResult> {
        // Everyone who asks while one read is under way shares its answer.
        this.reading ??= this.call(PROFILES_ARGS.list, null).finally(() => {
            this.reading = null;
        });
        return this.reading;
    }

    setStartup(start: StartMode, autoConnect: boolean): Promise<ProfilesResult> {
        return this.change(PROFILES_ARGS.setStartup, { start, auto_connect: autoConnect });
    }

    forgetPassword(id: ProfileId | null): Promise<ProfilesResult> {
        if (id !== null && !isProfileId(id)) {
            return Promise.resolve({ ok: false, error: "bad_input" });
        }
        return this.change(PROFILES_ARGS.forgetPassword, { id });
    }

    async create(name: string): Promise<ProfilesResult> {
        const input = { name, username: null, routes: null, save_password: false };
        const first = await this.change(PROFILES_ARGS.create, input);
        // The id the client drew was taken: asked again, it draws another.
        if (!first.ok && first.error === "id_taken") {
            return this.change(PROFILES_ARGS.create, input);
        }
        return first;
    }

    rename(id: ProfileId, name: string): Promise<ProfilesResult> {
        return this.withId(id, () => this.change(PROFILES_ARGS.rename, { id, name }));
    }

    update(id: ProfileId, change: ProfileChange): Promise<ProfilesResult> {
        // Only the two fields the contract names, whatever else was passed.
        const input: Record<string, unknown> = { id };
        if (change.username !== undefined) {
            input.username = change.username;
        }
        if (change.save_password !== undefined) {
            input.save_password = change.save_password;
        }
        return this.withId(id, () => this.change(PROFILES_ARGS.update, input));
    }

    remove(id: ProfileId): Promise<ProfilesResult> {
        return this.withId(id, () => this.change(PROFILES_ARGS.remove, { id }));
    }

    switchTo(id: ProfileId): Promise<ProfilesResult> {
        return this.withId(id, () => this.change(PROFILES_ARGS.switchTo, { id }));
    }

    /** Runs `then` only for an id that is one; anything else starts nothing. */
    private withId(id: ProfileId, then: () => Promise<ProfilesResult>): Promise<ProfilesResult> {
        return isProfileId(id) ? then() : Promise.resolve({ ok: false, error: "bad_input" });
    }

    stop(): void {
        this.calls.stop();
    }

    /** One change at a time: two at once could finish in either order. */
    private async change(args: readonly string[], input: unknown): Promise<ProfilesResult> {
        if (this.changing) {
            return { ok: false, error: "busy" };
        }
        this.changing = true;
        try {
            return await this.call(args, input);
        } finally {
            this.changing = false;
        }
    }

    private async call(args: readonly string[], input: unknown): Promise<ProfilesResult> {
        let encoded: Buffer | null = null;
        if (input !== null) {
            try {
                encoded = encodeLine(input);
            } catch {
                // Longer than a line may be. The client would say the same.
                return { ok: false, error: "bad_input" };
            }
        }
        const line = await this.calls.run(args, encoded);
        if (line === null) {
            return UNAVAILABLE;
        }
        if (line.status === 0 && isProfilesView(line.value)) {
            return { ok: true, value: shownView(line.value) };
        }
        if (line.status === 1 && isProfileFailure(line.value)) {
            return { ok: false, error: line.value.error as ProfilesError };
        }
        return UNAVAILABLE;
    }
}
