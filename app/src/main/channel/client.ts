// The app's end of the channel to the service: newline-delimited JSON over a
// named pipe (Windows) or a Unix socket (macOS, Linux). Node's `net` module
// treats both as a path, so the code is the same on every OS.
//
// Nothing in this file logs. A line may hold a session cookie, so no line,
// sent or received, is ever written anywhere or put in an error.

import { connect, type Socket } from "node:net";
import type { UnavailableReason } from "@shared/api";
import type { Event } from "@shared/protocol/Event";
import type { Hello } from "@shared/protocol/Hello";
import type { HelloReply } from "@shared/protocol/HelloReply";
import type { Outcome } from "@shared/protocol/Outcome";
import type { Request } from "@shared/protocol/Request";
import type { RequestBody } from "@shared/protocol/RequestBody";
import { encodeLine, LineDecoder } from "./framing";
import { isHelloReply, isServerMessage } from "./validate";

/** Must equal `PROTOCOL_VERSION` in `crates/core/src/protocol.rs`. */
export const PROTOCOL_VERSION = 2;

export type ChannelStatus =
    /** The first attempt is in flight. */
    | { status: "connecting" }
    | { status: "unavailable"; reason: UnavailableReason }
    /** The service answered with a different protocol version. */
    | { status: "update_needed"; serviceVersion: string }
    | { status: "ready"; hello: HelloReply };

/** Why a request got no answer. Never carries any part of a message. */
export class ChannelError extends Error {
    constructor(readonly reason: "not_connected" | "closed" | "timeout" | "too_long") {
        super(`channel request failed: ${reason}`);
        this.name = "ChannelError";
    }
}

export interface ChannelOptions {
    /** The pipe or socket path. */
    path: string;
    /** This app's version, sent in the `Hello`. */
    clientVersion: string;
    onStatus(status: ChannelStatus): void;
    onEvent(event: Event): void;
    /** Delay before the first retry; doubles up to `maxRetryDelayMs`. */
    initialRetryDelayMs?: number;
    maxRetryDelayMs?: number;
    /** How long to wait for a `HelloReply` or a response. */
    replyTimeoutMs?: number;
}

interface Pending {
    resolve(outcome: Outcome): void;
    reject(error: ChannelError): void;
    timer: NodeJS.Timeout;
}

const U32_MAX = 0xffffffff;

export class ChannelClient {
    private readonly options: Required<ChannelOptions>;
    private socket: Socket | null = null;
    private ready = false;
    private stopped = true;
    private retryDelayMs: number;
    private retryTimer: NodeJS.Timeout | null = null;
    private nextId = 1;
    private readonly pending = new Map<number, Pending>();

    constructor(options: ChannelOptions) {
        this.options = {
            initialRetryDelayMs: 250,
            maxRetryDelayMs: 5_000,
            replyTimeoutMs: 10_000,
            ...options,
        };
        this.retryDelayMs = this.options.initialRetryDelayMs;
    }

    /** Starts connecting, and keeps reconnecting until {@link stop}. */
    start(): void {
        if (!this.stopped) {
            return;
        }
        this.stopped = false;
        this.options.onStatus({ status: "connecting" });
        this.open();
    }

    stop(): void {
        this.stopped = true;
        this.clearRetry();
        this.closeSocket();
    }

    /** Skips the wait before the next attempt. Does nothing while connected. */
    retryNow(): void {
        if (this.stopped || this.socket !== null) {
            return;
        }
        this.clearRetry();
        this.open();
    }

    /**
     * Sends one request and resolves with the service's outcome, which may
     * itself be a refusal. Rejects with a {@link ChannelError} when there is
     * no answer.
     */
    request(body: RequestBody): Promise<Outcome> {
        const socket = this.socket;
        if (socket === null || !this.ready) {
            return Promise.reject(new ChannelError("not_connected"));
        }
        const id = this.takeId();
        const request: Request = { id, body };
        let line: Buffer;
        try {
            line = encodeLine(request);
        } catch {
            return Promise.reject(new ChannelError("too_long"));
        }
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new ChannelError("timeout"));
            }, this.options.replyTimeoutMs);
            this.pending.set(id, { resolve, reject, timer });
            socket.write(line);
        });
    }

    private takeId(): number {
        const id = this.nextId;
        this.nextId = id >= U32_MAX ? 1 : id + 1;
        return id;
    }

    private open(): void {
        const socket = connect(this.options.path);
        this.socket = socket;
        const decoder = new LineDecoder();
        let greeted = false;

        // A service that accepts the connection and then says nothing is as
        // unusable as one that is not there.
        const helloTimer = setTimeout(() => {
            this.fail(socket, "protocol_error");
        }, this.options.replyTimeoutMs);

        socket.once("connect", () => {
            const hello: Hello = {
                protocol_version: PROTOCOL_VERSION,
                client: "app",
                client_version: this.options.clientVersion,
            };
            socket.write(encodeLine(hello));
        });

        socket.on("data", (chunk: Buffer) => {
            let lines: string[];
            try {
                lines = decoder.push(chunk);
            } catch {
                this.fail(socket, "protocol_error");
                return;
            }
            for (const line of lines) {
                if (this.socket !== socket) {
                    return;
                }
                let message: unknown;
                try {
                    message = JSON.parse(line);
                } catch {
                    this.fail(socket, "protocol_error");
                    return;
                }
                if (greeted) {
                    this.onMessage(socket, message);
                } else {
                    greeted = true;
                    clearTimeout(helloTimer);
                    this.onHelloReply(socket, message);
                }
            }
        });

        // "error" is always followed by "close", which does the work. The
        // listener exists so a refused connection is not an uncaught error.
        socket.on("error", () => {});
        socket.once("close", () => {
            clearTimeout(helloTimer);
            if (this.socket === socket) {
                this.fail(socket, "not_running");
            }
        });
    }

    private onHelloReply(socket: Socket, message: unknown): void {
        // Like the service, read the version before anything else: a reply
        // from another version may not have the shape this one expects.
        const version = versionOf(message);
        if (version === null) {
            this.fail(socket, "protocol_error");
            return;
        }
        if (version !== PROTOCOL_VERSION) {
            const serviceVersion = serviceVersionOf(message);
            this.drop(socket);
            this.options.onStatus({ status: "update_needed", serviceVersion });
            // An installer may replace either side, so keep looking, slowly.
            this.scheduleRetry(this.options.maxRetryDelayMs);
            return;
        }
        if (!isHelloReply(message)) {
            this.fail(socket, "protocol_error");
            return;
        }
        this.ready = true;
        this.retryDelayMs = this.options.initialRetryDelayMs;
        this.options.onStatus({ status: "ready", hello: message });
    }

    private onMessage(socket: Socket, message: unknown): void {
        if (!isServerMessage(message)) {
            this.fail(socket, "protocol_error");
            return;
        }
        if (message.type === "event") {
            this.options.onEvent(message.data);
            return;
        }
        const pending = this.pending.get(message.data.id);
        // An answer nobody is waiting for is one whose request timed out.
        if (pending !== undefined) {
            this.pending.delete(message.data.id);
            clearTimeout(pending.timer);
            pending.resolve(message.data.outcome);
        }
    }

    /** Drops the connection, reports why, and schedules another attempt. */
    private fail(socket: Socket, reason: UnavailableReason): void {
        if (this.socket !== socket) {
            return;
        }
        this.drop(socket);
        if (this.stopped) {
            return;
        }
        this.options.onStatus({ status: "unavailable", reason });
        this.scheduleRetry(this.retryDelayMs);
        this.retryDelayMs = Math.min(this.retryDelayMs * 2, this.options.maxRetryDelayMs);
    }

    private drop(socket: Socket): void {
        if (this.socket === socket) {
            this.closeSocket();
        }
    }

    private closeSocket(): void {
        const socket = this.socket;
        this.socket = null;
        this.ready = false;
        socket?.destroy();
        for (const pending of this.pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(new ChannelError("closed"));
        }
        this.pending.clear();
    }

    private scheduleRetry(delayMs: number): void {
        this.clearRetry();
        this.retryTimer = setTimeout(() => {
            this.retryTimer = null;
            this.open();
        }, delayMs);
    }

    private clearRetry(): void {
        if (this.retryTimer !== null) {
            clearTimeout(this.retryTimer);
            this.retryTimer = null;
        }
    }
}

function versionOf(message: unknown): number | null {
    if (typeof message !== "object" || message === null) {
        return null;
    }
    const version = (message as { protocol_version?: unknown }).protocol_version;
    return typeof version === "number" && Number.isInteger(version) ? version : null;
}

function serviceVersionOf(message: unknown): string {
    const version = (message as { service_version?: unknown }).service_version;
    // Shown to the user, so keep it to the length of a real version number.
    return typeof version === "string" ? version.slice(0, 32) : "";
}
