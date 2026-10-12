// The diagnostics report: text a user copies, on purpose, to send to whoever
// is helping them. It is put together here, in the main process, from what
// has already been checked and cleaned, and it goes to the clipboard and
// nowhere else. Nothing writes it to disk.

import type { LinkState } from "@shared/api";
import type { ShownLine } from "@shared/logs";
import type { Diagnostics } from "@shared/protocol/Diagnostics";

/** The most log lines a report carries: the newest ones. */
export const REPORT_LINES = 200;

const when = (ms: number): string => {
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? "unknown time" : date.toISOString();
};

const count = (howMany: number, what: string): string =>
    `${howMany} ${what}${howMany === 1 ? "" : "s"}`;

function describeLink(link: LinkState): string {
    switch (link.link) {
        case "ready":
            return "reachable";
        case "unavailable":
            return `not reachable (${link.reason})`;
        default:
            return link.link;
    }
}

/**
 * The report's text. It holds the versions, the system, the state, the last
 * error and the newest log lines. It holds no password, code or session: no
 * part of the app is ever given one to put here.
 */
export function composeReport(parts: {
    appVersion: string;
    platform: string;
    arch: string;
    link: LinkState;
    diagnostics: Diagnostics | null;
    lines: readonly ShownLine[];
    dropped: boolean;
    now: number;
}): { text: string; lines: number } {
    const { diagnostics } = parts;
    const shown = parts.lines.slice(-REPORT_LINES);
    const head = [
        "UBC VPN diagnostics report",
        `Made: ${when(parts.now)}`,
        "",
        `App: ${parts.appVersion} (${parts.platform} ${parts.arch})`,
        `Service: ${describeLink(parts.link)}`,
    ];
    if (diagnostics === null) {
        head.push("The service did not give its own account of itself.");
    } else {
        head.push(
            `Service version: ${diagnostics.service_version}, protocol ${diagnostics.protocol_version}`,
            `System: ${[diagnostics.os, diagnostics.arch, diagnostics.os_version]
                .filter((part) => part !== null && part !== "")
                .join(" ")}`,
            `Service running for: ${diagnostics.uptime_s} s`,
            // Counted, as the service gives them: which subnets and which
            // domains is not for a report.
            `Connection: ${diagnostics.state}, with ${count(diagnostics.subnets, "subnet")} and ${count(
                diagnostics.dns_domains,
                "domain",
            )} through the tunnel`,
            `Last error: ${
                diagnostics.last_error === null
                    ? "none"
                    : `${diagnostics.last_error.code}: ${diagnostics.last_error.message}`
            }`,
            `Policy: ${
                diagnostics.policy_readable
                    ? `readable, gateway ${diagnostics.gateway ?? "not named"}, ${diagnostics.pins} pins`
                    : "not readable"
            }`,
            `Owner claimed: ${diagnostics.owner_claimed ? "yes" : "no"}`,
        );
    }
    const older =
        parts.dropped || shown.length < parts.lines.length ? "; older lines are not included" : "";
    const log = [
        "",
        `Log: the newest ${shown.length} lines${older}`,
        ...shown.map(
            (line) =>
                `#${line.seq} ${when(line.at_unix_ms)} ${line.level} ${line.source}  ${line.text}`,
        ),
    ];
    return { text: `${[...head, ...log].join("\n")}\n`, lines: shown.length };
}
