// A small stand-in for the service, for tests. It speaks the channel protocol
// over a real named pipe (Windows) or Unix socket (elsewhere), the same way
// the service in `crates/` will: it reads only the version from the first
// line, always answers with a `HelloReply`, closes on a mismatch, and sends
// the current state as the first event.

import { randomUUID } from "node:crypto";
import { rmSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ConnState } from "@shared/protocol/ConnState";
import type { HelloReply } from "@shared/protocol/HelloReply";
import type { Outcome } from "@shared/protocol/Outcome";
import type { Request } from "@shared/protocol/Request";
import type { ServerMessage } from "@shared/protocol/ServerMessage";

export const TUNNEL = {
    interface: "utun4",
    address: "198.51.100.42",
    subnets: ["203.0.113.0/24"],
    dns_domains: ["campus.example"],
};

/** A pipe or socket path no other test, or real service, is using. */
export function uniqueChannelPath(): string {
    const name = `ubc-vpn-test-${randomUUID()}`;
    return process.platform === "win32" ? `\\\\.\\pipe\\${name}` : join(tmpdir(), `${name}.sock`);
}

export class MockService {
    protocolVersion = 2;
    serviceVersion = "0.1.0";
    /** Set to another user's claim being in place. */
    ownedByAnother = false;
    state: ConnState = { state: "disconnected" };
    /** When set, sent in place of the `HelloReply`. */
    helloReplyOverride: string | null = null;
    /** When set, sent in place of the first event. */
    firstLineOverride: string | null = null;
    /** When true, the service accepts connections and then says nothing. */
    silent = false;
    /** When true, requests get no answer. */
    ignoreRequests = false;

    /** Every line received, parsed, across all connections. */
    readonly received: unknown[] = [];
    connections = 0;

    private server: Server | null = null;
    private readonly sockets = new Set<Socket>();

    constructor(readonly path: string = uniqueChannelPath()) {}

    start(): Promise<void> {
        return new Promise((resolve, reject) => {
            const server = createServer((socket) => this.accept(socket));
            server.once("error", reject);
            server.listen(this.path, () => {
                this.server = server;
                resolve();
            });
        });
    }

    /** Stops listening and drops every client, as a stopped service would. */
    stop(): Promise<void> {
        for (const socket of this.sockets) {
            socket.destroy();
        }
        this.sockets.clear();
        const server = this.server;
        this.server = null;
        return new Promise((resolve) => {
            if (server === null) {
                resolve();
                return;
            }
            server.close(() => {
                if (process.platform !== "win32") {
                    rmSync(this.path, { force: true });
                }
                resolve();
            });
        });
    }

    /** Changes the state and tells every client, as the service does. */
    setState(state: ConnState): void {
        this.state = state;
        for (const socket of this.sockets) {
            this.send(socket, { type: "event", data: { kind: "state_changed", value: state } });
        }
    }

    /** Writes raw text to every client, for sending things the protocol forbids. */
    sendRaw(text: string): void {
        for (const socket of this.sockets) {
            socket.write(text);
        }
    }

    private send(socket: Socket, message: ServerMessage | HelloReply): void {
        socket.write(`${JSON.stringify(message)}\n`);
    }

    private accept(socket: Socket): void {
        this.connections++;
        this.sockets.add(socket);
        socket.on("close", () => this.sockets.delete(socket));
        socket.on("error", () => {});
        let buffered = "";
        let greeted = false;
        socket.on("data", (chunk) => {
            buffered += chunk.toString("utf8");
            for (;;) {
                const end = buffered.indexOf("\n");
                if (end === -1) {
                    return;
                }
                const message: unknown = JSON.parse(buffered.slice(0, end));
                buffered = buffered.slice(end + 1);
                this.received.push(message);
                if (this.silent) {
                    continue;
                }
                if (greeted) {
                    this.answer(socket, message as Request);
                } else {
                    greeted = true;
                    this.greet(socket, message as { protocol_version: number });
                }
            }
        });
    }

    private greet(socket: Socket, hello: { protocol_version: number }): void {
        if (this.helloReplyOverride !== null) {
            socket.end(this.helloReplyOverride);
            return;
        }
        this.send(socket, {
            protocol_version: this.protocolVersion,
            service_version: this.serviceVersion,
            owner_claimed: this.ownedByAnother,
        });
        if (hello.protocol_version !== this.protocolVersion) {
            socket.end();
            return;
        }
        if (this.firstLineOverride !== null) {
            socket.write(this.firstLineOverride);
            return;
        }
        this.send(socket, {
            type: "event",
            data: { kind: "state_changed", value: this.state },
        });
    }

    private answer(socket: Socket, request: Request): void {
        if (this.ignoreRequests) {
            return;
        }
        this.send(socket, {
            type: "response",
            data: { id: request.id, outcome: this.outcome(request) },
        });
        if (request.body.method === "disconnect" && !this.ownedByAnother) {
            this.setState({ state: "disconnecting" });
            this.setState({ state: "disconnected" });
        }
    }

    private outcome(request: Request): Outcome {
        if (this.ownedByAnother) {
            return {
                status: "error",
                value: { code: "not_owner", message: "only the owner may do this" },
            };
        }
        switch (request.body.method) {
            case "claim":
                return { status: "ok", value: { kind: "claimed" } };
            case "status":
                return { status: "ok", value: { kind: "status", value: this.state } };
            case "connect":
            case "disconnect":
                return { status: "ok", value: { kind: "accepted" } };
        }
    }
}
