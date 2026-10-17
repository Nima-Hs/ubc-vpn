// Where a switch between split and full tunnel stands, for the window and
// the tray alike. Whichever asked, the switch is made here, one at a time,
// and everyone is told the same thing. No Electron import, so it can be
// tested on its own.

import type { LinkState } from "@shared/api";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import {
    shownMode,
    switchesLive,
    type TunnelOutcome,
    type TunnelStatus,
    tunnelLocked,
    UNREAD_TUNNEL,
} from "@shared/tunnel";
import type { TunnelResult } from "./channel/profiles";

/**
 * How long "Switching" may stay up after the client said the switch was
 * made, waiting for the service's new state to arrive. The client only says
 * so once the service reports the new mode, so this is a short wait.
 */
export const SETTLE_MS = 3000;

export interface TunnelSwitchDeps {
    /** Saves a mode, and has a live connection switched to it. */
    save(mode: TunnelMode): Promise<TunnelResult>;
    /** Reads the profiles again, so every screen has the saved mode. */
    reread(): void;
    state(): LinkState;
    subscribe(listener: (state: LinkState) => void): () => void;
    /** Whether a login is under way, which fixes the mode it connects with. */
    loggingIn(): boolean;
    /** Where the window and the tray hear of every change. */
    publish(status: TunnelStatus): void;
    timers?: {
        set(run: () => void, ms: number): unknown;
        clear(timer: unknown): void;
    };
}

/** What kind of state the connection is in, to tell when it changes. */
function connKind(state: LinkState): string {
    return state.link === "ready" ? state.conn.state : state.link;
}

export class TunnelSwitch {
    private status: TunnelStatus = UNREAD_TUNNEL;
    /** The connection's kind of state when the outcome was said. */
    private outcomeKind: string | null = null;
    /** Ends the wait for the new mode, while there is one. */
    private settle: (() => void) | null = null;
    /** Told each state while the new mode is waited for. */
    private waitingFor: ((state: LinkState) => void) | null = null;
    private readonly unsubscribe: () => void;
    private readonly timers: NonNullable<TunnelSwitchDeps["timers"]>;

    constructor(private readonly deps: TunnelSwitchDeps) {
        this.timers = deps.timers ?? {
            set: (run, ms) => setTimeout(run, ms),
            clear: (timer) => clearTimeout(timer as ReturnType<typeof setTimeout>),
        };
        this.unsubscribe = deps.subscribe((state) => this.onState(state));
    }

    get(): TunnelStatus {
        return this.status;
    }

    /** The profiles as they now are: the mode saved, and whether full may be chosen. */
    fromProfiles(view: ProfilesView): void {
        this.update({
            saved: view.global.tunnel,
            fullAllowed: view.full_tunnel === "allowed",
            readFailed: false,
        });
    }

    /** The profiles could not be read, or the client took too long: say so. */
    readFailed(): void {
        if (this.status.saved === null) {
            this.update({ readFailed: true });
        }
    }

    /**
     * Switches to `mode`: saves it, and changes a live connection in place.
     * Does nothing while the mode cannot be changed, or is already `mode`.
     */
    async request(mode: TunnelMode): Promise<void> {
        const state = this.deps.state();
        const before = this.status;
        if (
            before.switching !== null ||
            tunnelLocked(state, before, this.deps.loggingIn()) !== null
        ) {
            return;
        }
        const from = shownMode(state, before);
        if (mode === from && mode === before.saved) {
            return;
        }
        if (mode === "full" && !before.fullAllowed) {
            this.finish({ kind: "forbidden" });
            return;
        }
        this.outcomeKind = null;
        this.update({ switching: { from, to: mode }, outcome: null });
        try {
            await this.run(mode, from);
        } finally {
            // Whatever came of it, a client that failed or was ended after
            // saving included: every screen is given the mode as saved.
            this.deps.reread();
        }
    }

    private async run(mode: TunnelMode, from: TunnelMode): Promise<void> {
        const result = await this.deps.save(mode);
        if (!result.ok) {
            this.finish({ kind: "not_saved", wanted: mode, error: result.error });
            return;
        }
        const reply = result.value;
        if (reply.type === "forbidden") {
            this.update({ fullAllowed: false });
            this.finish({ kind: "forbidden" });
            return;
        }
        this.update({ saved: reply.tunnel });
        const { live } = reply;
        switch (live.result) {
            case "applied":
                await this.settled(mode);
                this.finish(null);
                break;
            case "next_connect":
            case "failed":
                // Failed: the service closed the connection, and its state says why.
                this.finish(null);
                break;
            case "refused": {
                // The connection keeps the mode it has, and so does the setting:
                // what is chosen is what is in effect.
                const back = await this.deps.save(from);
                const restored = back.ok && back.value.type === "ok" && back.value.tunnel === from;
                if (restored) {
                    this.update({ saved: from });
                }
                this.finish({
                    kind: "refused",
                    kept: from,
                    wanted: mode,
                    message: live.message,
                    restored,
                });
                break;
            }
            case "unknown":
                this.finish({ kind: "unknown", wanted: mode, message: live.message });
                break;
        }
    }

    dispose(): void {
        this.settle?.();
        this.unsubscribe();
    }

    /** Waits until the connection shows `mode`, or is no longer up, or a short while. */
    private settled(mode: TunnelMode): Promise<void> {
        const done = (state: LinkState) => !switchesLive(state) || shownLive(state) === mode;
        if (done(this.deps.state())) {
            return Promise.resolve();
        }
        return new Promise((resolve) => {
            const timer = this.timers.set(() => this.settle?.(), SETTLE_MS);
            this.settle = () => {
                this.timers.clear(timer);
                this.settle = null;
                this.waitingFor = null;
                resolve();
            };
            this.waitingFor = (state) => {
                if (done(state)) {
                    this.settle?.();
                }
            };
        });
    }

    private onState(state: LinkState): void {
        this.waitingFor?.(state);
        // What came of a switch is out of date once the connection changes.
        if (this.status.outcome !== null && connKind(state) !== this.outcomeKind) {
            this.outcomeKind = null;
            this.update({ outcome: null });
        }
    }

    private finish(outcome: TunnelOutcome | null): void {
        this.outcomeKind = outcome === null ? null : connKind(this.deps.state());
        this.update({ switching: null, outcome });
    }

    private update(change: Partial<TunnelStatus>): void {
        this.status = { ...this.status, ...change };
        this.deps.publish(this.status);
    }
}

/** The mode of a live connection, if there is one. */
function shownLive(state: LinkState): TunnelMode | null {
    return state.link === "ready" && state.conn.state === "connected"
        ? state.conn.tunnel.mode
        : null;
}
