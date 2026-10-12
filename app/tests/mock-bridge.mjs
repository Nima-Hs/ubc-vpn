// A stand-in for `ubc-vpn bridge`, for tests. It follows the contract in
// `crates/core/src/bridge.rs`:
//
// - it writes exactly one first line, `ready` or the reason there is no
//   channel, and exits after any line other than `ready` and `server`;
// - it does not read standard input until it has written `ready`;
// - it answers `connect` itself with a `bad_request` error and carries on;
// - a line on standard input that is too long or is not a valid request gets
//   `bad_line`, and it exits without echoing the line;
// - when standard input closes it exits with status 0 and writes nothing;
//   every other exit has status 1.
//
// Usage: node mock-bridge.mjs bridge <config.json>
//
// The config is `{ runs: [...], counter, log }`. Each start takes the next
// entry of `runs` (the last one repeats), so a test can script "unavailable,
// then ready". `counter` is a file holding how many times it has started and
// `log` a file listing what it received, one entry per line.

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";

const MAX_LINE_BYTES = 64 * 1024;

if (process.argv[2] !== "bridge" || process.argv.length !== 4) {
    // Started the wrong way: say nothing, as a program that is not the bridge would.
    process.exit(2);
}
const config = JSON.parse(readFileSync(process.argv[3], "utf8"));
const started = existsSync(config.counter) ? Number(readFileSync(config.counter, "utf8")) : 0;
writeFileSync(config.counter, String(started + 1));
const run = config.runs[Math.min(started, config.runs.length - 1)];

const log = (entry) => appendFileSync(config.log, `${entry}\n`);
const write = (line) => process.stdout.write(`${JSON.stringify(line)}\n`);
const raw = (text, then) => process.stdout.write(text, then);
/** Writes a last line and exits, once it has been flushed. */
const finish = (line) => raw(`${JSON.stringify(line)}\n`, () => process.exit(1));
const server = (message) => write({ type: "server", message });
const event = (state) => server({ type: "event", data: { kind: "state_changed", value: state } });

let state = run.state ?? { state: "disconnected" };

// The real bridge does not read standard input until it has written `ready`.
// With `watchEarlyInput`, this one looks anyway, only to record that the app
// wrote something it should not have.
const early = () => log("early");
if (run.watchEarlyInput) {
    process.stdin.on("data", early);
}

function isRequest(value) {
    if (typeof value !== "object" || value === null) {
        return false;
    }
    const keys = Object.keys(value);
    if (keys.length !== 2 || !Number.isInteger(value.id) || value.id < 0) {
        return false;
    }
    const body = value.body;
    if (typeof body !== "object" || body === null) {
        return false;
    }
    switch (body.method) {
        case "claim":
        case "status":
        case "disconnect":
            return Object.keys(body).length === 1;
        case "connect":
            return typeof body.params === "object" && body.params !== null;
        default:
            return false;
    }
}

function answer(request) {
    const { id, body } = request;
    log(body.method);
    const respond = (outcome) => server({ type: "response", data: { id, outcome } });
    if (body.method === "connect") {
        // Never forwarded: the app must not hold a session cookie.
        respond({
            status: "error",
            value: { code: "bad_request", message: "the bridge does not forward connect" },
        });
        return;
    }
    if ((run.ignore ?? []).includes(body.method)) {
        return;
    }
    if (run.requestsRefusedAsNotOwner) {
        respond({
            status: "error",
            value: { code: "not_owner", message: "only the owner may do this" },
        });
        return;
    }
    if (run.answerWithWrongId) {
        server({
            type: "response",
            data: { id: id + 1000, outcome: { status: "ok", value: { kind: "claimed" } } },
        });
        return;
    }
    switch (body.method) {
        case "claim":
            respond({ status: "ok", value: { kind: "claimed" } });
            break;
        case "status":
            respond({ status: "ok", value: { kind: "status", value: state } });
            break;
        case "disconnect":
            respond({ status: "ok", value: { kind: "accepted" } });
            for (const next of [{ state: "disconnecting" }, { state: "disconnected" }]) {
                state = next;
                event(state);
            }
            break;
    }
}

function readRequests() {
    let pending = Buffer.alloc(0);
    process.stdin.on("data", (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        for (;;) {
            const end = pending.indexOf(0x0a);
            if (end === -1) {
                if (pending.length + 1 > MAX_LINE_BYTES) {
                    finish({ type: "bad_line" });
                }
                return;
            }
            const line = pending.subarray(0, end);
            pending = pending.subarray(end + 1);
            let request;
            try {
                request = end + 1 > MAX_LINE_BYTES ? undefined : JSON.parse(line.toString("utf8"));
            } catch {
                request = undefined;
            }
            if (!isRequest(request)) {
                log("bad_line");
                finish({ type: "bad_line" });
                return;
            }
            answer(request);
        }
    });
    // The app has gone: leave quietly.
    process.stdin.on("end", () => process.exit(0));
}

function becomeReady() {
    process.stdin.off("data", early);
    write({
        type: "ready",
        service_version: run.serviceVersion ?? "0.1.0",
        owner_claimed: run.ownerClaimed ?? false,
    });
    readRequests();
    // The service sends the current state as its first event.
    if (run.firstEvent !== false) {
        event(state);
    }
    for (const step of run.later ?? []) {
        setTimeout(() => {
            if (step.state !== undefined) {
                state = step.state;
                event(state);
            } else if (step.raw !== undefined) {
                raw(step.raw);
            } else if (step.end !== undefined) {
                // The service went away, or the bridge was refused something.
                finish({ type: step.end });
            } else if (step.exit !== undefined) {
                process.exit(step.exit);
            }
        }, step.afterMs);
    }
}

setTimeout(() => {
    switch (run.first ?? "ready") {
        case "ready":
            becomeReady();
            break;
        case "service_unavailable":
        case "untrusted_service":
        case "not_owner":
            finish({ type: run.first });
            break;
        case "update_needed":
            finish({ type: "update_needed", service_version: run.serviceVersion ?? "0.2.0" });
            break;
        case "none":
            process.exit(1);
            break;
        case "silent":
            // Stay alive and say nothing.
            setInterval(() => {}, 1000);
            break;
        case "raw":
            raw(run.raw, () => {
                if (run.exitAfterRaw !== false) {
                    process.exit(1);
                }
            });
            if (run.exitAfterRaw === false) {
                setInterval(() => {}, 1000);
            }
            break;
        default:
            process.exit(3);
    }
}, run.firstAfterMs ?? 0);
