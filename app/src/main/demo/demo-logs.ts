// A stand-in for the service's log, for demo builds only. It answers in the
// shapes of protocol version 3 (`@shared/protocol`) and behaves as the
// contract says a service may: pages of bounded size, a run number, lines
// that can be dropped on the way. It is not the service, and every line in
// it is made up.

import type { Diagnostics } from "@shared/protocol/Diagnostics";
import type { LogCursor } from "@shared/protocol/LogCursor";
import type { LogLevel } from "@shared/protocol/LogLevel";
import type { LogLine } from "@shared/protocol/LogLine";
import type { LogPage } from "@shared/protocol/LogPage";
import type { LogSource } from "@shared/protocol/LogSource";
import type { LogFeed } from "../logs/book";

/** The most lines the pretend service keeps, and the most it gives in one page. */
const KEPT = 500;
const PAGE = 100;

type Said = [LogLevel, LogSource, string];

// 203.0.113.0/24 is reserved for documentation, and `.example` names never resolve.
const STORY: Said[] = [
    ["info", "service", "ubc-vpn-service 0.1.0 is running"],
    ["info", "login", "Connecting to vpn.example"],
    ["info", "login", "Server certificate matches a pin"],
    ["info", "login", "Login succeeded"],
    ["info", "engine", "Connecting to vpn.example"],
    ["info", "engine", "CSTP connected. DPD 60, Keepalive 300"],
    ["info", "service", "Route 203.0.113.0/24 added"],
    ["warn", "service", "DNS for campus.example could not be confirmed; trying once more"],
    ["info", "service", "DNS for campus.example confirmed"],
    ["info", "engine", "Rekeying the tunnel"],
    ["error", "engine", "The gateway closed the session"],
    ["info", "service", "Everything was removed"],
];
const AWKWARD: Said[] = [
    ["info", "service", "A short line"],
    ["warn", "engine", `An-unbroken-line-${"0123456789abcdef".repeat(20)}`],
    ["error", "service", "A line with a\nnewline, a\ttab and a ‮direction override"],
    ["info", "engine", "[a line too long to keep was left out]"],
    ["error", "login", "The gateway rejected the username, password or code."],
    ["info", "service", "   "],
    [
        "warn",
        "service",
        '<b>not bold</b> <img src=x onerror=alert(1)> <a href="https://example.com">not a link</a>',
    ],
];

export const DEMO_LOG_SCENARIOS = [
    "logs",
    "logs-empty",
    "logs-many",
    "logs-awkward",
    "logs-gaps",
    "logs-lost",
    "logs-new-run",
    "logs-unavailable",
] as const;

export interface DemoLogs extends LogFeed {
    setScenario(name: string): void;
}

export function createDemoLogs(stepMs = 1400): DemoLogs {
    let run = 1;
    let lines: LogLine[] = [];
    // A run numbers its lines from 1.
    let next = 1;
    let listener: ((line: unknown) => void) | null = null;
    let timer: NodeJS.Timeout | null = null;
    let scenario: string = "logs";
    /** The numbers of lines this run wrote and no longer holds. */
    let lost: number[] = [];
    let told = 0;
    let clock = Date.now() - 60_000;

    const write = ([level, source, text]: Said, announce = true): void => {
        clock += 700;
        const line: LogLine = { seq: next, at_unix_ms: clock, level, source, text };
        next += 1;
        lines.push(line);
        if (lines.length > KEPT) {
            lost.push((lines.shift() as LogLine).seq);
        }
        told += 1;
        // A pretend service with a full queue: every other line is not sent.
        if (announce && !(scenario === "logs-gaps" && told % 2 === 0)) {
            listener?.({ ...line });
        }
    };
    const start = (said: readonly Said[], times = 1): void => {
        lines = [];
        lost = [];
        next = 1;
        for (let round = 0; round < times; round++) {
            for (const entry of said) {
                write(entry, false);
            }
        }
    };
    const trickle = (): void => {
        if (timer !== null) {
            clearInterval(timer);
            timer = null;
        }
        if (listener !== null && (scenario === "logs" || scenario === "logs-gaps")) {
            timer = setInterval(
                () => write(STORY[next % STORY.length] as Said),
                Math.max(50, stepMs),
            );
        }
    };
    start(STORY);

    const diagnostics = (): Diagnostics => ({
        service_version: "0.1.0",
        protocol_version: 3,
        os: "demo",
        arch: "x86_64",
        os_version: "1.0",
        uptime_s: 3725,
        state: "disconnected",
        subnets: 0,
        dns_domains: 0,
        last_error: { code: "gateway_unreachable", message: "The gateway closed the session." },
        policy_readable: true,
        gateway: "vpn.example",
        pins: 2,
        owner_claimed: true,
    });

    return {
        watch: (onLine) => {
            listener = onLine;
            trickle();
            return Promise.resolve();
        },
        fetch: (after: LogCursor | null) => {
            if (scenario === "logs-unavailable") {
                return Promise.resolve(null);
            }
            // No cursor, or one from another run, means "after 0".
            const known = after !== null && after.run === run;
            const from = known ? after.seq : 0;
            const page = lines.filter((line) => line.seq > from).slice(0, PAGE);
            const answer: LogPage = {
                run,
                lines: page.map((line) => ({ ...line })),
                next: page.at(-1)?.seq ?? from,
                // A line of this run after the cursor existed and has gone.
                dropped: lost.some((seq) => seq > from),
            };
            return Promise.resolve(answer);
        },
        diagnostics: () => Promise.resolve(scenario === "logs-unavailable" ? null : diagnostics()),
        setScenario: (name) => {
            if (!(DEMO_LOG_SCENARIOS as readonly string[]).includes(name)) {
                return;
            }
            scenario = name;
            told = 0;
            // Every scenario is a pretend service started afresh: a new run,
            // whose numbers begin again. A real service never reuses a
            // number within one run.
            run += 1;
            if (name === "logs-new-run") {
                // The one that says so while the log is being watched.
                start(STORY.slice(0, 3));
                listener?.({ ...(lines.at(-1) as LogLine) });
            } else if (name === "logs-empty") {
                start([]);
            } else if (name === "logs-many") {
                start(STORY, 60);
            } else if (name === "logs-lost") {
                // Login lines are kept apart from the rest, and each kind is
                // let go by itself: a hole in the middle that stays.
                start(STORY);
                lost = lines.filter((line) => line.source === "login").map((line) => line.seq);
                lines = lines.filter((line) => line.source !== "login");
            } else if (name === "logs-awkward") {
                start(AWKWARD);
            } else if (name !== "logs-unavailable") {
                start(STORY);
            }
            trickle();
        },
    };
}
