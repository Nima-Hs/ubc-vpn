// A stand-in for `ubc-vpn connect --json`, for tests. It follows the contract
// in `crates/core/src/login.rs`:
//
// - it writes one `CliMessage` per line: prompts, then exactly one last line,
//   `done` or `error`, after which it exits;
// - it reads one `AppMessage` per line: an `answer` carrying the id of the
//   prompt it is waiting on, or `cancel`;
// - on `cancel` it stops at once, with `error` and the code `cancelled`;
// - it never writes an answer back out.
//
// Usage: node mock-cli.mjs connect --json <config.json>
//
// The config is `{ steps: [...], log, pids }`. Each step is one thing the
// client does next:
//   { prompt: { id, kind, label, message? }, expect? }  ask, and wait for the answer
//   { done: true }                                      the last line, on success
//   { error: { code, message } }                        the last line, on failure
//   { raw: "..." }                                      write this text as it is
//   { exit: n }                                         leave without a last line
//   { hang: true }                                      stay, saying nothing more
// `log` is a file that gets one entry per thing received. An answer is logged
// as its id and whether it equals `expect`, never as its text.

import { appendFileSync, existsSync, readFileSync } from "node:fs";

if (process.argv[2] !== "connect" || process.argv[3] !== "--json" || process.argv.length !== 5) {
    // Started the wrong way, or handed something extra such as a route.
    process.exit(2);
}
const config = JSON.parse(readFileSync(process.argv[4], "utf8"));
const log = (entry) => appendFileSync(config.log, `${entry}\n`);
appendFileSync(config.pids, `${process.pid}\n`);
if (config.stderr !== undefined) {
    process.stderr.write(`${config.stderr}\n`);
}
if (config.reportStart) {
    log(`cwd:${process.cwd()}`);
    log(`env:${Object.keys(process.env).sort().join(",")}`);
}

// With `laterLogins`, each start after the first takes the next list of
// steps, so a test can script one login and then a different one.
const earlier = existsSync(config.pids)
    ? readFileSync(config.pids, "utf8").split("\n").length - 2
    : 0;
const steps = [
    ...(earlier > 0 ? (config.laterLogins?.[earlier - 1] ?? config.steps) : config.steps),
];
/** The step whose prompt is waiting for its answer. */
let waiting = null;

const write = (line, then) => process.stdout.write(`${JSON.stringify(line)}\n`, then);
const last = (line, code) => write(line, () => process.exit(code));

function next() {
    const step = steps.shift();
    if (step === undefined || step.hang) {
        setInterval(() => {}, 1000);
    } else if (step.prompt !== undefined) {
        waiting = step;
        write({ type: "prompt", ...step.prompt });
    } else if (step.done) {
        last({ type: "done" }, 0);
    } else if (step.error !== undefined) {
        last({ type: "error", ...step.error }, 1);
    } else if (step.raw !== undefined) {
        process.stdout.write(step.raw, next);
    } else if (step.exit !== undefined) {
        process.exit(step.exit);
    }
}

function isAppMessage(value) {
    if (typeof value !== "object" || value === null) {
        return false;
    }
    if (value.type === "cancel") {
        return Object.keys(value).length === 1;
    }
    return (
        value.type === "answer" &&
        Object.keys(value).sort().join() === "id,type,value" &&
        Number.isInteger(value.id) &&
        value.id >= 0 &&
        typeof value.value === "string"
    );
}

let pending = "";
process.stdin.on("data", (chunk) => {
    pending += chunk.toString("utf8");
    for (;;) {
        const end = pending.indexOf("\n");
        if (end === -1) {
            return;
        }
        let message;
        try {
            message = JSON.parse(pending.slice(0, end));
        } catch {
            message = null;
        }
        pending = pending.slice(end + 1);
        if (!isAppMessage(message)) {
            log("bad_line");
            last(
                {
                    type: "error",
                    code: "internal",
                    message: "the app sent a line that is not a message",
                },
                1,
            );
            return;
        }
        if (message.type === "cancel") {
            log("cancel");
            if (!config.ignoresCancel) {
                last({ type: "error", code: "cancelled", message: "cancelled" }, 1);
            }
            return;
        }
        if (waiting === null || waiting.prompt.id !== message.id) {
            log(`answer:${message.id}:unexpected`);
            last({ type: "error", code: "internal", message: "an answer nobody asked for" }, 1);
            return;
        }
        const matches = waiting.expect === undefined || waiting.expect === message.value;
        log(`answer:${message.id}:${matches ? "as expected" : "different"}`);
        waiting = null;
        next();
    }
});
// The app has gone.
process.stdin.on("end", () => {
    log("input closed");
    if (config.ignoresCancel) {
        setInterval(() => {}, 1000);
    } else {
        process.exit(1);
    }
});

next();
