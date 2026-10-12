import type { ActionResult, LoginState, Snapshot } from "@shared/api";
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
            closeHides: false,
            development,
        };
        // A change of state makes any earlier notice out of date.
        this.unsubscribe = link.subscribe((state) => this.publish({ state, notice: null }));
        this.loginRunner =
            login?.((state) => {
                this.login = state;
                this.publish({ state: this.link.getState(), notice: null });
            }) ?? null;
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
        this.loginRunner.start();
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

    disconnect(): Promise<void> {
        return this.run(() => this.link.disconnect());
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
            closeHides: this.closeHides,
            development: this.development,
        };
        this.snapshot = snapshot;
        for (const listener of this.listeners) {
            listener(snapshot);
        }
    }
}
