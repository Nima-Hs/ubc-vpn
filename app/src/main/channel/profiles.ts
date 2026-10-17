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
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import type { TunnelReply } from "@shared/protocol/TunnelReply";
import { markedText, plainText } from "./connect";
import { encodeLine } from "./framing";
import { OneLineCalls, type OneLineOptions } from "./one-line";
import { MAX_SHOWN_LENGTH } from "./settings";
import {
    isProfileFailure,
    isProfileId,
    isProfilesView,
    isTunnelMode,
    isTunnelReply,
} from "./validate";

/** What came of `settings set-tunnel`: its reply, or why there was none. */
export type TunnelResult = { ok: true; value: TunnelReply } | { ok: false; error: ProfilesError };

/**
 * How long a switch of mode may take. The client waits for the service to
 * switch a live connection and check it, for up to two minutes
 * (`Limits::outcome`, `crates/cli/src/client.rs`); ending it sooner would
 * leave the app not knowing what the service went on to do.
 */
export const SET_TUNNEL_TIMEOUT_MS = 150_000;

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
    /**
     * Saves split or full for every profile, and has a live connection
     * switched to it. Its answer is not a view: read the profiles again after.
     */
    setTunnel(mode: TunnelMode): Promise<TunnelResult>;
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
    setTunnel: ["settings", "set-tunnel", "--json"],
} as const;

const UNAVAILABLE = { ok: false, error: "unavailable" } as const;

const shown = (text: string): string => plainText(text, MAX_SHOWN_LENGTH);
// Routes are edited and sent back, so what is removed leaves a mark.
const marked = (text: string): string => markedText(text, MAX_SHOWN_LENGTH);
const shownRoutes = (routes: RouteSet): RouteSet => ({
    subnets: routes.subnets.map(marked),
    dns_domains: routes.dns_domains.map(marked),
});

/**
 * The view the interface is given, built field by field from the ones it
 * needs, and never by copying what the client sent. A field the client adds
 * one day, a password among them, cannot reach the window: whether a
 * password is saved is all that ever does.
 */
function shownView(view: ProfilesView): ProfilesView {
    return {
        global: {
            start: view.global.start,
            auto_connect: view.global.auto_connect,
            active_profile: view.global.active_profile,
            tunnel: view.global.tunnel,
        },
        profiles: view.profiles.map((profile) => ({
            id: profile.id,
            name: shown(profile.name),
            username: profile.username === null ? null : shown(profile.username),
            routes: shownRoutes(profile.routes),
            save_password: profile.save_password,
            password_saved: profile.password_saved,
        })),
        keyring: view.keyring,
        policy_readable: view.policy_readable,
        allowed_routes: view.allowed_routes?.map(shown) ?? null,
        full_tunnel: view.full_tunnel,
    };
}

/** A reply as the rest of the app is given it: the service's words cleaned. */
function shownReply(reply: TunnelReply): TunnelReply {
    if (reply.type === "forbidden") {
        return { type: "forbidden" };
    }
    const { live } = reply;
    switch (live.result) {
        case "applied":
        case "next_connect":
            return { type: "ok", tunnel: reply.tunnel, live: { result: live.result } };
        case "refused":
        case "failed":
            return {
                type: "ok",
                tunnel: reply.tunnel,
                live: { result: live.result, code: live.code, message: shown(live.message) },
            };
        case "unknown":
            return {
                type: "ok",
                tunnel: reply.tunnel,
                live: { result: "unknown", message: shown(live.message) },
            };
    }
}

export class ProfilesRunner implements ProfilesService {
    private readonly calls: OneLineCalls;
    /** For switches of mode alone, which may wait on the service for longer. */
    private readonly slowCalls: OneLineCalls;
    private reading: Promise<ProfilesResult> | null = null;
    private changing = false;

    constructor(options: OneLineOptions) {
        this.calls = new OneLineCalls(options);
        this.slowCalls = new OneLineCalls({ timeoutMs: SET_TUNNEL_TIMEOUT_MS, ...options });
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

    async setTunnel(mode: TunnelMode): Promise<TunnelResult> {
        // Only a mode, and only one of the two.
        if (!isTunnelMode(mode)) {
            return { ok: false, error: "bad_input" };
        }
        if (this.changing) {
            return { ok: false, error: "busy" };
        }
        this.changing = true;
        try {
            const line = await this.slowCalls.run(PROFILES_ARGS.setTunnel, encodeLine({ mode }));
            if (line === null) {
                return UNAVAILABLE;
            }
            if (line.status === 0 && isTunnelReply(line.value)) {
                return { ok: true, value: shownReply(line.value) };
            }
            if (line.status === 1 && isProfileFailure(line.value)) {
                return { ok: false, error: line.value.error as ProfilesError };
            }
            return UNAVAILABLE;
        } finally {
            this.changing = false;
        }
    }

    /** Runs `then` only for an id that is one; anything else starts nothing. */
    private withId(id: ProfileId, then: () => Promise<ProfilesResult>): Promise<ProfilesResult> {
        return isProfileId(id) ? then() : Promise.resolve({ ok: false, error: "bad_input" });
    }

    stop(): void {
        this.calls.stop();
        this.slowCalls.stop();
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
