// A stand-in for the client's profiles commands, for tests. It follows the
// contract in `crates/cli/src/profiles.rs`:
//
// - each command reads at most one line and writes exactly one line, with
//   status 0 for a `ProfilesView` and status 1 for a refusal `{"error": …}`;
// - an input with a field the command does not know, or a missing,
//   over-long or undecodable line, is `{"error":"bad_input"}`: so no
//   `password` field could ever be sent;
// - `profiles list` reads nothing.
//
// Usage: node mock-profiles.mjs <config.json> <group> <verb> --json
//
// The config is `{ answers, log }`. `answers` maps "group verb" (for example
// "settings set-startup") to what that command answers:
//   { line: {...}, exit: n }   write this line and leave with this status
//   { raw: "...", exit: n }    write this text as it is
//   { hang: true }             say nothing and stay
// `log` gets the arguments it was started with and the input line it read.

import { appendFileSync, readFileSync } from "node:fs";

const MAX_LINE_BYTES = 64 * 1024;
/** Each command, with the fields its input may have, or `null` for none. */
const INPUTS = {
    "profiles list": null,
    "profiles create": ["name", "username", "routes", "save_password"],
    "profiles rename": ["id", "name"],
    "profiles update": ["id", "username", "save_password"],
    "profiles delete": ["id"],
    "profiles switch": ["id"],
    "profile set-routes": ["id", "subnets", "dns_domains"],
    "password forget": ["id"],
    "settings set-startup": ["start", "auto_connect"],
    "settings set-tunnel": ["mode"],
};

const [, , configPath, ...args] = process.argv;
const config = JSON.parse(readFileSync(configPath, "utf8"));
const log = (entry) => appendFileSync(config.log, `${entry}\n`);
log(`args:${JSON.stringify(args)}`);

const command = `${args[0]} ${args[1]}`;
if (args.length !== 3 || !Object.hasOwn(INPUTS, command) || args[2] !== "--json") {
    process.exit(2);
}
const fields = INPUTS[command];

function answer(chosen) {
    if (chosen.hang) {
        setInterval(() => {}, 1000);
        return;
    }
    const text = chosen.raw ?? `${JSON.stringify(chosen.line)}\n`;
    process.stdout.write(text, () => process.exit(chosen.exit ?? 0));
}
const refuse = () => answer({ line: { error: "bad_input" }, exit: 1 });
const reply = () => answer(config.answers?.[command] ?? { line: { error: "bad_input" }, exit: 1 });

if (fields === null) {
    reply();
} else {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
        input += chunk;
    });
    process.stdin.on("end", () => {
        log(`input:${input}`);
        const [line, ...rest] = input.split("\n");
        if (Buffer.byteLength(input) > MAX_LINE_BYTES || rest.some((extra) => extra !== "")) {
            refuse();
            return;
        }
        let value;
        try {
            value = JSON.parse(line);
        } catch {
            refuse();
            return;
        }
        if (
            typeof value !== "object" ||
            value === null ||
            Object.keys(value).some((key) => !fields.includes(key))
        ) {
            refuse();
            return;
        }
        reply();
    });
}
