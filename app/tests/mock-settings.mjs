// A stand-in for `ubc-vpn settings ... --json`, for tests. It follows the
// contract in `crates/core/src/settings_cli.rs`:
//
// - each command writes exactly one line on standard output and exits: with
//   status 0 for a view or a routes reply, and with status 1 for a failure;
// - `check-routes` and `set-routes` read one line of input, a `RouteInput`.
//   A missing, over-long or undecodable line is `bad_input`;
// - `get` reads nothing.
//
// Usage: node mock-settings.mjs <config.json> settings <get|check-routes|set-routes> --json
//
// The config is `{ get, check, save, log, pids }`. Each of the first three
// says what that command answers:
//   { line: {...}, exit: n }   write this line and leave with this status
//   { raw: "...", exit: n }    write this text as it is
//   { hang: true }             say nothing and stay
//   { raw: "...", stay: true } write this text and stay
// `log` gets one entry per thing worth knowing: the arguments it was started
// with, the input line it read, and "saved" when `set-routes` answers `ok`.

import { appendFileSync, readFileSync } from "node:fs";

const MAX_LINE_BYTES = 64 * 1024;
const VERBS = { get: "get", "check-routes": "check", "set-routes": "save" };

const [, , configPath, ...args] = process.argv;
const config = JSON.parse(readFileSync(configPath, "utf8"));
const log = (entry) => appendFileSync(config.log, `${entry}\n`);
appendFileSync(config.pids, `${process.pid}\n`);
log(`args:${JSON.stringify(args)}`);

const verb = VERBS[args[1]];
if (args.length !== 3 || args[0] !== "settings" || verb === undefined || args[2] !== "--json") {
    // Started the wrong way, or handed something extra.
    process.exit(2);
}
const reply = config[verb] ?? { line: { error: "bad_input" }, exit: 1 };

function answer(chosen) {
    if (chosen.hang) {
        setInterval(() => {}, 1000);
        return;
    }
    if (verb === "save" && chosen.line?.type === "ok") {
        log("saved");
    }
    const text = chosen.raw ?? `${JSON.stringify(chosen.line)}\n`;
    process.stdout.write(text, () => {
        // `stay`: a client that has written and will not leave.
        if (chosen.stay) {
            setInterval(() => {}, 1000);
        } else {
            process.exit(chosen.exit ?? 0);
        }
    });
}

function isRouteInput(value) {
    const strings = (list) =>
        Array.isArray(list) && list.every((entry) => typeof entry === "string");
    return (
        typeof value === "object" &&
        value !== null &&
        Object.keys(value).sort().join() === "dns_domains,subnets" &&
        strings(value.subnets) &&
        strings(value.dns_domains)
    );
}

if (verb === "get") {
    log("input:not read");
    answer(reply);
} else {
    const chunks = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () => {
        const all = Buffer.concat(chunks);
        const end = all.indexOf(0x0a);
        let input;
        try {
            input =
                end === -1 || end + 1 > MAX_LINE_BYTES
                    ? undefined
                    : JSON.parse(all.subarray(0, end).toString("utf8"));
        } catch {
            input = undefined;
        }
        if (!isRouteInput(input)) {
            log("input:bad");
            answer({ line: { error: "bad_input" }, exit: 1 });
            return;
        }
        log(`input:${JSON.stringify(input)}`);
        answer(reply);
    });
}
