// Turns the channel into the one value the interface draws from, and the few
// actions it can take.

import type { ActionResult, LinkState } from "@shared/api";
import type { ConnState } from "@shared/protocol/ConnState";
import type { Outcome } from "@shared/protocol/Outcome";
import { BridgeClient, type BridgeFault, type BridgeStatus } from "./channel/bridge";

/** What the rest of the main process needs from a service, real or fake. */
export interface ServiceLink {
    getState(): LinkState;
    /** Calls `listener` on every change. Returns a function that stops it. */
    subscribe(listener: (state: LinkState) => void): () => void;
    connect(): Promise<ActionResult>;
    disconnect(): Promise<ActionResult>;
    retry(): void;
    dispose(): void;
}

/** Holds a {@link LinkState} and tells listeners when it changes. */
export class LinkStore {
    private state: LinkState = { link: "starting" };
    private readonly listeners = new Set<(state: LinkState) => void>();

    get(): LinkState {
        return this.state;
    }

    set(state: LinkState): void {
        this.state = state;
        for (const listener of this.listeners) {
            listener(state);
        }
    }

    subscribe(listener: (state: LinkState) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }
}

export interface ServiceLinkOptions {
    /** The command-line client and its arguments; see `bridgeCommand`. */
    command: string;
    args: readonly string[];
    appVersion: string;
    onFault?(fault: BridgeFault): void;
    initialRetryDelayMs?: number;
    maxRetryDelayMs?: number;
    startTimeoutMs?: number;
    replyTimeoutMs?: number;
}

export function createServiceLink(options: ServiceLinkOptions): ServiceLink {
    const store = new LinkStore();
    // The state arrives as the first event, and the claim is answered
    // separately. The interface is shown the state only once both are in.
    let claimed = false;
    let conn: ConnState | null = null;

    const publishReady = () => {
        if (claimed && conn !== null) {
            store.set({ link: "ready", conn });
        }
    };

    const onStatus = (status: BridgeStatus) => {
        claimed = false;
        conn = null;
        switch (status.status) {
            case "connecting":
                store.set({ link: "starting" });
                break;
            case "unavailable":
                store.set({ link: "unavailable", reason: status.reason });
                break;
            case "update_needed":
                store.set({
                    link: "update_needed",
                    appVersion: options.appVersion,
                    serviceVersion: status.serviceVersion,
                });
                break;
            case "untrusted_service":
                store.set({ link: "untrusted_service" });
                break;
            case "not_owner":
                store.set({ link: "not_owner" });
                break;
            case "ready":
                void claim();
                break;
        }
    };

    // The bridge sends no requests of its own, so the app claims the service
    // itself, every time a bridge is ready: the first user to run it becomes
    // the owner, and the owner's later claims are accepted.
    //
    // "Not the owner" can arrive two ways and means the same either way. The
    // bridge says it when the channel is reserved for the owner; the service
    // says it in answer to a request when the channel was not narrowed.
    const claim = async () => {
        let outcome: Outcome;
        try {
            outcome = await client.request({ method: "claim" });
        } catch {
            // The bridge ended or never answered. Either way the client has
            // already reported it and is starting another.
            return;
        }
        if (outcome.status === "error") {
            if (outcome.value.code === "not_owner") {
                store.set({ link: "not_owner" });
            } else {
                store.set({ link: "ready", conn: { state: "failed", ...outcome.value } });
            }
            return;
        }
        claimed = true;
        publishReady();
        if (conn !== null) {
            return;
        }
        // The first event has not arrived yet, so ask.
        try {
            const status = await client.request({ method: "status" });
            if (conn === null && status.status === "ok" && status.value.kind === "status") {
                conn = status.value.value;
                publishReady();
            }
        } catch {
            // As above.
        }
    };

    const client = new BridgeClient({
        command: options.command,
        args: options.args,
        onStatus,
        ...(options.onFault !== undefined && { onFault: options.onFault }),
        onEvent: (event) => {
            conn = event.value;
            publishReady();
        },
        ...(options.initialRetryDelayMs !== undefined && {
            initialRetryDelayMs: options.initialRetryDelayMs,
        }),
        ...(options.maxRetryDelayMs !== undefined && { maxRetryDelayMs: options.maxRetryDelayMs }),
        ...(options.startTimeoutMs !== undefined && { startTimeoutMs: options.startTimeoutMs }),
        ...(options.replyTimeoutMs !== undefined && { replyTimeoutMs: options.replyTimeoutMs }),
    });
    client.start();

    return {
        getState: () => store.get(),
        subscribe: (listener) => store.subscribe(listener),
        // Connecting needs a session cookie, and only a login can produce
        // one. Login is a later feature, so there is nothing to send yet.
        connect: async () => ({ ok: false, error: { kind: "login_unavailable" } }),
        disconnect: async () => {
            try {
                const outcome = await client.request({ method: "disconnect" });
                if (outcome.status === "ok") {
                    return { ok: true };
                }
                if (outcome.value.code === "not_owner") {
                    store.set({ link: "not_owner" });
                }
                return { ok: false, error: { kind: "refused", ...outcome.value } };
            } catch {
                return { ok: false, error: { kind: "service_unavailable" } };
            }
        },
        retry: () => client.retryNow(),
        dispose: () => client.stop(),
    };
}
