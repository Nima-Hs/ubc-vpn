import type { ActionResult, LoginState, Snapshot } from "@shared/api";
import type { ProfileId } from "@shared/protocol/ProfileId";
import { type TunnelStatus, UNREAD_TUNNEL } from "@shared/tunnel";
import type { LoginRunner } from "./channel/connect";
import type { ServiceLink } from "./link";

/** Makes the thing that runs a login, given where to report its progress. */
export type LoginFactory = (onState: (state: LoginState) => void) => LoginRunner;

/**
 * The one place actions are taken, whether the user asked in the window or
 * from the tray, so both see the same state and the same explanation when an
 * action does not start.
 *
 * What the user types at a login prompt passes through here on its way to
 * the command-line client. It is handed on and not kept: it never becomes
 * part of the snapshot the interface is sent.
 */
export class Controller {
    private snapshot: Snapshot;
    private readonly listeners = new Set<(snapshot: Snapshot) => void>();
    private readonly unsubscribe: () => void;
    private readonly loginRunner: LoginRunner | null;
    private closeHides = false;
    private login: LoginState = { phase: "idle" };
    /** The profile the login under way is for, while there is one. */
    private loginProfile: ProfileId | null = null;
    private tunnel: TunnelStatus = UNREAD_TUNNEL;
    /** Which profile a login started now is for: the active one, as the app knows it. */
    private profileForLogin: () => ProfileId | null = () => null;

    /**
     * Without `login`, pressing Connect explains that this build cannot log
     * in. That is the case until the login screens exist.
     */
    constructor(
        private readonly link: ServiceLink,
        login?: LoginFactory,
        /** Whether the client is run in dev mode; see `bridgeCommand`. */
        private readonly development = false,
    ) {
        this.snapshot = {
            state: link.getState(),
            notice: null,
            login: this.login,
            loginProfile: null,
            tunnel: this.tunnel,
            closeHides: false,
            development,
        };
        // A change of state makes any earlier notice out of date.
        this.unsubscribe = link.subscribe((state) => this.publish({ state, notice: null }));
        this.loginRunner =
            login?.((state) => {
                this.login = state;
                if (state.phase === "idle") {
                    this.loginProfile = null;
                }
                this.publish({ state: this.link.getState(), notice: null });
            }) ?? null;
    }

    /** Where a login started from now on learns which profile it is for. */
    setProfileForLogin(profile: () => ProfileId | null): void {
        this.profileForLogin = profile;
    }

    getSnapshot(): Snapshot {
        return this.snapshot;
    }

    subscribe(listener: (snapshot: Snapshot) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    /** Starts a login, which ends with the service being asked to connect. */
    connect(): Promise<void> {
        if (this.loginRunner === null) {
            return this.run(() => this.link.connect());
        }
        // One at a time: a second press while a login is under way does nothing.
        // The login is bound to the profile in use now, whatever is chosen while it runs.
        const profile = this.profileForLogin();
        if (this.loginRunner.start(profile)) {
            this.loginProfile = profile;
            this.publish({ state: this.link.getState(), notice: null });
        }
        return Promise.resolve();
    }

    /**
     * Passes the user's answer to the login prompt with this `id` on to the
     * command-line client. The value is not stored, logged or published.
     */
    answerPrompt(id: number, value: string): void {
        this.loginRunner?.answer(id, value);
    }

    /** Gives up a login, or dismisses one that failed. */
    cancelLogin(): void {
        this.loginRunner?.cancel();
    }

    /**
     * For when the app quits: a promise that ends once a login the user gave
     * up has been wound up, or `limitMs` has passed; `null` if there is none.
     */
    windDown(limitMs: number): Promise<void> | null {
        return this.loginRunner?.windDown(limitMs) ?? null;
    }

    disconnect(): Promise<void> {
        return this.run(() => this.link.disconnect());
    }

    /** Where the tunnel setting now stands, for the window and the tray. */
    setTunnel(tunnel: TunnelStatus): void {
        this.tunnel = tunnel;
        this.publish(this.snapshot);
    }

    /** Says whether closing the window hides it or quits the app. */
    setCloseHides(closeHides: boolean): void {
        this.closeHides = closeHides;
        this.publish(this.snapshot);
    }

    retry(): void {
        this.link.retry();
    }

    dispose(): void {
        this.unsubscribe();
        // Nothing is told about what happens from here on: the window and
        // the tray this would reach are being taken down.
        this.listeners.clear();
        this.loginRunner?.stop();
        this.link.dispose();
    }

    private async run(action: () => Promise<ActionResult>): Promise<void> {
        const result = await action();
        if (!result.ok) {
            this.publish({ state: this.link.getState(), notice: result.error });
        }
    }

    private publish(next: Pick<Snapshot, "state" | "notice">): void {
        const snapshot: Snapshot = {
            state: next.state,
            notice: next.notice,
            login: this.login,
            loginProfile: this.login.phase === "idle" ? null : this.loginProfile,
            tunnel: this.tunnel,
            closeHides: this.closeHides,
            development: this.development,
        };
        this.snapshot = snapshot;
        for (const listener of this.listeners) {
            listener(snapshot);
        }
    }
}
