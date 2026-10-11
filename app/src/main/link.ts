// Turns the channel into the one value the interface draws from, and the few
// actions it can take.

import type { ActionResult, LinkState } from "@shared/api";
import type { ConnState } from "@shared/protocol/ConnState";
import type { Outcome } from "@shared/protocol/Outcome";
import { ChannelClient, type ChannelStatus } from "./channel/client";

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
    path: string;
    appVersion: string;
    initialRetryDelayMs?: number;
    maxRetryDelayMs?: number;
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

    const onStatus = (status: ChannelStatus) => {
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
            case "ready":
                void claim();
                break;
        }
    };

    // The app claims the service on every connection: the first user to run
    // it becomes the owner, and the owner's later claims are accepted.
    const claim = async () => {
        let outcome: Outcome;
        try {
            outcome = await client.request({ method: "claim" });
        } catch {
            // The connection dropped; the client is already reconnecting.
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

    const client = new ChannelClient({
        path: options.path,
        clientVersion: options.appVersion,
        onStatus,
        onEvent: (event) => {
            conn = event.value;
            publishReady();
        },
        ...(options.initialRetryDelayMs !== undefined && {
            initialRetryDelayMs: options.initialRetryDelayMs,
        }),
        ...(options.maxRetryDelayMs !== undefined && { maxRetryDelayMs: options.maxRetryDelayMs }),
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
                return outcome.status === "ok"
                    ? { ok: true }
                    : { ok: false, error: { kind: "refused", ...outcome.value } };
            } catch {
                return { ok: false, error: { kind: "service_unavailable" } };
            }
        },
        retry: () => client.retryNow(),
        dispose: () => client.stop(),
    };
}
