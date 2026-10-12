// What the main process tells the interface, and the fixed set of functions
// the interface may call. Both sides import this file, so they cannot drift.

import type { ConnState } from "./protocol/ConnState";
import type { ErrorCode } from "./protocol/ErrorCode";

/** Why the service cannot be used right now. */
export type UnavailableReason =
    /** Nothing is listening: the service is stopped or not installed. */
    | "not_running"
    /** Something answered, but not in the protocol the app speaks. */
    | "protocol_error";

/**
 * Everything the interface needs to draw itself. `ready` carries the
 * connection state the service reports; the others describe why there is no
 * connection state to show.
 */
export type LinkState =
    /** The first attempt to reach the service is still in flight. */
    | { link: "starting" }
    | { link: "unavailable"; reason: UnavailableReason }
    /** The app and the service speak different protocol versions. */
    | { link: "update_needed"; appVersion: string; serviceVersion: string }
    /** Another user of this computer owns the service. */
    | { link: "not_owner" }
    | { link: "ready"; conn: ConnState };

/** Why an action the user asked for did not start. */
export type ActionError =
    /** Login is a later feature; without it there is no session to connect with. */
    | { kind: "login_unavailable" }
    | { kind: "service_unavailable" }
    /** The service refused. `message` is the service's own wording. */
    | { kind: "refused"; code: ErrorCode; message: string };

export type ActionResult = { ok: true } | { ok: false; error: ActionError };

/** What the interface is sent, whole, every time any part of it changes. */
export interface Snapshot {
    state: LinkState;
    /**
     * Why the last thing the user asked for did not start, whether they asked
     * in the window or from the tray. Cleared when the state next changes.
     */
    notice: ActionError | null;
    /**
     * Whether closing the window hides it and leaves the app in the tray.
     * Where there is no tray to come back from, closing quits instead.
     */
    closeHides: boolean;
}

/** The whole of what the interface can ask the main process to do. */
export interface VpnApi {
    /** Which OS draws the window, so the title bar can leave room for its controls. */
    readonly platform: string;
    getSnapshot(): Promise<Snapshot>;
    /** Calls `listener` on every change. Returns a function that stops it. */
    onSnapshot(listener: (snapshot: Snapshot) => void): () => void;
    /** The outcome arrives as a new snapshot, not as a return value. */
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    /** Tries to reach the service now instead of waiting for the next attempt. */
    retry(): Promise<void>;
    minimizeWindow(): Promise<void>;
    /** Closes the window: to the tray where there is one, otherwise quitting. */
    closeWindow(): Promise<void>;
    /** Present only in demo builds. */
    readonly demo?: DemoApi;
}

/** Demo builds only: puts the fake service into a named state. */
export interface DemoApi {
    listScenarios(): Promise<string[]>;
    setScenario(name: string): Promise<void>;
}

declare global {
    interface Window {
        /** Provided by the preload script. The interface's only way out. */
        readonly ubcVpn: VpnApi;
    }
}

/** IPC channel names. Nothing else crosses between the two processes. */
export const IPC = {
    getSnapshot: "vpn:get-snapshot",
    snapshot: "vpn:snapshot",
    connect: "vpn:connect",
    disconnect: "vpn:disconnect",
    retry: "vpn:retry",
    minimizeWindow: "window:minimize",
    closeWindow: "window:close",
} as const;

/** Demo builds only. Kept out of `IPC` so production builds do not carry them. */
export const DEMO_IPC = {
    listScenarios: "demo:list-scenarios",
    setScenario: "demo:set-scenario",
} as const;

/**
 * The window's colour before the interface has painted. It must equal
 * `--c-bg` in `tokens.css`; a test checks that.
 */
export const WINDOW_BACKGROUND = "#0b0e14";
