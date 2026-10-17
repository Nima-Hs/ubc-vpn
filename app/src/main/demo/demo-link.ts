// DEMO ONLY. An in-memory stand-in for the service, so the interface can be
// designed and shown in every state with no backend. It is imported only
// behind `__DEMO__`, which is `false` in every build except `--mode demo`,
// and `scripts/check-production-build.mjs` fails if any of it is emitted.

import type { LinkState } from "@shared/api";
import type { ErrorCode } from "@shared/protocol/ErrorCode";
import type { LiveRoutes } from "@shared/protocol/LiveRoutes";
import type { TunnelInfo } from "@shared/protocol/TunnelInfo";
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import { LinkStore, type ServiceLink } from "../link";

// 198.51.100.0/24 and 203.0.113.0/24 are reserved for documentation, and
// `.example` never resolves: none of this is a real network.
const TUNNEL: TunnelInfo = {
    interface: "utun4",
    mode: "split",
    address: "198.51.100.42",
    subnets: ["203.0.113.0/24", "198.51.100.0/24"],
    dns_domains: ["campus.example", "lab.campus.example"],
};

const CROWDED_TUNNEL: TunnelInfo = {
    interface: "a-tunnel-device-with-an-unusually-long-name-0",
    mode: "split",
    address: "198.51.100.254",
    subnets: Array.from({ length: 256 }, (_, i) => `203.0.113.${i}/32`),
    dns_domains: [
        "an-extremely-long-department-name-that-does-not-break.research.campus.example",
        ...Array.from({ length: 40 }, (_, i) => `lab-${i + 1}.campus.example`),
    ],
};

/**
 * A list shaped like a real one: a range saved as the 16 pieces that leave
 * out one address in it, the way a route table must hold "all of it but the
 * VPN server", and a few subnets of their own. 21 in all. 10.0.0.0/8 is
 * private, so none of it is a real network either.
 */
const PIECES_TUNNEL: TunnelInfo = {
    interface: "utun4",
    mode: "split",
    address: "198.51.100.42",
    subnets: [
        "198.51.100.0/24",
        "10.20.0.0/17",
        "10.20.128.0/18",
        "10.20.192.0/19",
        "10.20.224.0/20",
        "10.20.240.0/21",
        "10.20.248.0/22",
        "10.20.252.0/23",
        "10.20.254.0/24",
        "10.20.255.0/25",
        "10.20.255.128/26",
        "10.20.255.192/27",
        "10.20.255.224/28",
        "10.20.255.240/29",
        "10.20.255.248/30",
        "10.20.255.252/31",
        "10.20.255.255/32",
        "10.30.0.0/16",
        "10.40.8.0/22",
        "192.0.2.0/24",
        "203.0.113.128/25",
    ],
    dns_domains: ["campus.example"],
};

const FAILURES: Record<ErrorCode, string> = {
    not_owner: "only the owner may do this",
    not_claimed: "the service has no owner yet",
    protocol_mismatch: "the app speaks protocol 3 and the service speaks protocol 4",
    bad_request: "unknown method",
    route_refused: "198.51.100.0/4 is wider than /8",
    pin_mismatch: "the gateway's key matches no pin in the policy",
    login_needed: "the session cookie was rejected",
    gateway_unreachable: "timed out connecting to the gateway",
    engine_failed: "the tunnel device could not be created",
    verification_failed: "the route to 203.0.113.0/24 could not be confirmed",
    busy: "another connect or disconnect is in progress",
    not_connected: "there is no tunnel whose routes could be changed",
    policy_invalid: "policy.json could not be read",
    internal:
        "an unexpectedly long message from the service that goes on for a while, to show how the interface holds text it did not write and cannot shorten",
};

const SCENARIOS: Record<string, LinkState> = {
    starting: { link: "starting" },
    disconnected: { link: "ready", conn: { state: "disconnected" } },
    connecting: { link: "ready", conn: { state: "connecting" } },
    connected: { link: "ready", conn: { state: "connected", tunnel: TUNNEL } },
    "connected-crowded": { link: "ready", conn: { state: "connected", tunnel: CROWDED_TUNNEL } },
    "connected-pieces": { link: "ready", conn: { state: "connected", tunnel: PIECES_TUNNEL } },
    // Full tunnel: everything through UBC, the local network still direct.
    "tunnel-full": {
        link: "ready",
        conn: { state: "connected", tunnel: { ...TUNNEL, mode: "full" } },
    },
    "tunnel-full-connecting": { link: "ready", conn: { state: "connecting" } },
    "tunnel-full-off": { link: "ready", conn: { state: "disconnected" } },
    // Connected in split, for a switch that hangs, is refused, or is not
    // allowed (see `TUNNEL_SWITCHES`, and `demo-profiles.ts`).
    "tunnel-switch-held": { link: "ready", conn: { state: "connected", tunnel: TUNNEL } },
    "tunnel-refused": { link: "ready", conn: { state: "connected", tunnel: TUNNEL } },
    "tunnel-forbidden": { link: "ready", conn: { state: "connected", tunnel: TUNNEL } },
    "connected-empty": {
        link: "ready",
        conn: { state: "connected", tunnel: { ...TUNNEL, subnets: [], dns_domains: [] } },
    },
    // The count of exactly one, where a careless plural shows.
    "connected-one": {
        link: "ready",
        conn: {
            state: "connected",
            tunnel: { ...TUNNEL, subnets: ["203.0.113.0/24"], dns_domains: ["campus.example"] },
        },
    },
    disconnecting: { link: "ready", conn: { state: "disconnecting" } },
    "login-needed": { link: "ready", conn: { state: "login_needed" } },
    ...Object.fromEntries(
        Object.entries(FAILURES).map(([code, message]) => [
            `failed-${code.replaceAll("_", "-")}`,
            { link: "ready", conn: { state: "failed", code: code as ErrorCode, message } },
        ]),
    ),
    // Text the app did not write: another script, an emoji, and a long
    // run with nowhere to break.
    "failed-awkward-message": {
        link: "ready",
        conn: {
            state: "failed",
            code: "engine_failed",
            message: `Không thể tạo thiết bị đường hầm 🚧 トンネルを開けません ${"/sys/devices/virtual/net".repeat(9)}`,
        },
    },
    "update-needed-long-version": {
        link: "update_needed",
        appVersion: "0.1.0",
        serviceVersion: "0.2.0-nightly.20261011+build.4127",
    },
    "service-unavailable": { link: "unavailable", reason: "not_running" },
    "service-garbled": { link: "unavailable", reason: "protocol_error" },
    "update-needed": { link: "update_needed", appVersion: "0.1.0", serviceVersion: "0.2.0" },
    "untrusted-service": { link: "untrusted_service" },
    "not-owner": { link: "not_owner" },
};

export const DEMO_SCENARIOS: readonly string[] = Object.keys(SCENARIOS);

/**
 * How a live switch of mode goes in a scenario: it never finishes, so the
 * switching state can be looked at, or the service refuses it, in the words
 * the service uses (`crates/service/src/full.rs`).
 */
const TUNNEL_SWITCHES: Record<string, "held" | LiveRoutes> = {
    "tunnel-switch-held": "held",
    "tunnel-refused": {
        result: "refused",
        code: "route_refused",
        message:
            "Full tunnel cannot be used on this network: its router is not on a network this computer is on, so it could not stay reachable directly.",
    },
};

export interface DemoLink extends ServiceLink {
    /** Jumps straight to a named state. Unknown names are ignored. */
    setScenario(name: string): void;
    /** What the service does with a switch of mode: in place while connected. */
    switchTunnel(mode: TunnelMode): Promise<LiveRoutes>;
}

/** `mode` says which mode a connect uses: the one saved. */
export function createDemoLink(stepMs = 1400, mode: () => TunnelMode = () => "split"): DemoLink {
    const store = new LinkStore();
    let timer: NodeJS.Timeout | null = null;
    let switches: "held" | LiveRoutes | null = null;
    /** Answers a held switch: the next scenario does, for the next connect. */
    let release: (() => void) | null = null;

    const cancel = () => {
        if (timer !== null) {
            clearTimeout(timer);
            timer = null;
        }
    };
    const after = (state: LinkState) => {
        cancel();
        timer = setTimeout(() => store.set(state), stepMs);
    };
    const isBusy = () => {
        const state = store.get();
        return (
            state.link === "ready" &&
            (state.conn.state === "connecting" || state.conn.state === "disconnecting")
        );
    };
    const busy = {
        ok: false,
        error: { kind: "refused", code: "busy", message: FAILURES.busy },
    } as const;

    store.set(SCENARIOS.disconnected as LinkState);

    return {
        getState: () => store.get(),
        subscribe: (listener) => store.subscribe(listener),
        connect: async () => {
            if (isBusy()) {
                return busy;
            }
            store.set(SCENARIOS.connecting as LinkState);
            after({
                link: "ready",
                conn: { state: "connected", tunnel: { ...TUNNEL, mode: mode() } },
            });
            return { ok: true };
        },
        disconnect: async () => {
            if (isBusy()) {
                return busy;
            }
            store.set(SCENARIOS.disconnecting as LinkState);
            after(SCENARIOS.disconnected as LinkState);
            return { ok: true };
        },
        retry: () => {
            store.set(SCENARIOS.starting as LinkState);
            after(SCENARIOS.disconnected as LinkState);
        },
        switchTunnel: (to) => {
            const state = store.get();
            if (state.link !== "ready" || state.conn.state !== "connected") {
                return Promise.resolve({ result: "next_connect" });
            }
            if (switches === "held") {
                return new Promise((resolve) => {
                    release = () => resolve({ result: "next_connect" });
                });
            }
            if (switches !== null) {
                return Promise.resolve(switches);
            }
            const tunnel = state.conn.tunnel;
            // As the client answers: once the service shows the new mode.
            return new Promise((resolve) => {
                setTimeout(() => {
                    store.set({
                        link: "ready",
                        conn: { state: "connected", tunnel: { ...tunnel, mode: to } },
                    });
                    resolve({ result: "applied" });
                }, stepMs / 2);
            });
        },
        setScenario: (name) => {
            release?.();
            release = null;
            // `hasOwn`, so a name such as "__proto__" is not mistaken for a scenario.
            const state = Object.hasOwn(SCENARIOS, name) ? SCENARIOS[name] : undefined;
            if (state !== undefined) {
                cancel();
                store.set(state);
                switches = Object.hasOwn(TUNNEL_SWITCHES, name)
                    ? (TUNNEL_SWITCHES[name] ?? null)
                    : null;
            }
        },
        dispose: cancel,
    };
}
