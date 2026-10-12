// Starts the built app the way anyone can, with `--remote-debugging-port`,
// and asks that port whether a debugger is there.
//
// The production build (`out/`, from `pnpm build`) must not answer. The demo
// build (`out-demo/`) is the control: it keeps the switch, because this very
// test suite drives it through that port, so it shows the probe can tell.

import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import electronPath from "electron";

/** A port nothing is using right now. */
function freePort(): Promise<number> {
    return new Promise((done, fail) => {
        const server = createServer();
        server.once("error", fail);
        server.listen(0, "127.0.0.1", () => {
            const address = server.address();
            server.close(() =>
                done(typeof address === "object" && address !== null ? address.port : 0),
            );
        });
    });
}

/** Whether a Chromium debugger answers on this port. */
async function debuggerAnswers(port: number): Promise<boolean> {
    try {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
            signal: AbortSignal.timeout(1000),
        });
        return response.ok && "webSocketDebuggerUrl" in ((await response.json()) as object);
    } catch {
        return false;
    }
}

const running: ChildProcess[] = [];

function launch(build: "out" | "out-demo", port: number): ChildProcess {
    const child = spawn(
        electronPath as unknown as string,
        [
            resolve(build, "main/index.js"),
            `--remote-debugging-port=${port}`,
            `--user-data-dir=${mkdtempSync(join(tmpdir(), "ubc-vpn-debug-probe-"))}`,
        ],
        { stdio: "ignore" },
    );
    running.push(child);
    return child;
}

test.afterEach(() => {
    for (const child of running.splice(0)) {
        child.kill();
    }
});

test("a production build cannot be debugged from outside", async () => {
    test.setTimeout(120_000);

    // The control: with the switch kept, a debugger answers. How long that
    // takes on this machine sets how long the real check waits.
    const controlPort = await freePort();
    launch("out-demo", controlPort);
    const started = Date.now();
    await expect.poll(() => debuggerAnswers(controlPort), { timeout: 60_000 }).toBe(true);
    const startUp = Date.now() - started;

    // The same switch, on the build people install. Give it several times as
    // long as the control needed, and look the whole while.
    const port = await freePort();
    const app = launch("out", port);
    const deadline = Date.now() + Math.max(5000, startUp * 4);
    let answered = false;
    while (!answered && Date.now() < deadline) {
        answered = await debuggerAnswers(port);
        await new Promise((tick) => setTimeout(tick, 100));
    }
    expect(answered).toBe(false);
    // It was running all that time, not gone: a dead app answers nothing either.
    expect(app.exitCode).toBeNull();
});
