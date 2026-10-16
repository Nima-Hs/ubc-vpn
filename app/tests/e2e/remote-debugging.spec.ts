// Starts the built app the way anyone can, with `--remote-debugging-port`,
// and asks that port whether a debugger is there.
//
// The production build (`out/`, from `pnpm build`) must not answer. The demo
// build (`out-demo/`) is the control: it keeps the switch, because this very
// test suite drives it through that port, so it shows the probe can tell.
//
// The packaged app, as installed, is checked the same way when
// `UBC_VPN_PACKAGED_APP` names its program. The installer workflow does
// that on a CI runner; an installed app cannot be kept off the screen.

import type { ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import electronPath from "electron";
import { spawnApp } from "./launch";
import { isCi } from "./safe-env";

/**
 * Off the screen unless this is CI: a test run on someone's computer must
 * not open windows over their work. See `keepHidden` in `src/main/window.ts`.
 */
const HIDDEN = isCi(process.env) ? {} : { UBC_VPN_TEST_HIDDEN: "1" };

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

/** The packaged app's program, when this run is to check it. */
const PACKAGED_APP = process.env.UBC_VPN_PACKAGED_APP;

/** A build in this folder, run by the Electron in node_modules, or a packaged program. */
type Build = "out" | "out-demo" | { program: string };

function launch(build: Build, port: number, env: Record<string, string> = {}): ChildProcess {
    const debugging = `--remote-debugging-port=${port}`;
    const [program, args] =
        typeof build === "string"
            ? [electronPath as unknown as string, [resolve(build, "main/index.js"), debugging]]
            : [build.program, [debugging]];
    const child = spawnApp(program, args, {
        stdio: "ignore",
        // Its own profile, never the installed product's folder. A
        // packaged app ignores the variable and uses its own.
        env: {
            ...HIDDEN,
            UBC_VPN_PROFILE: mkdtempSync(join(tmpdir(), "ubc-vpn-debug-probe-")),
            ...env,
        },
    });
    running.push(child);
    return child;
}

test.afterEach(() => {
    for (const child of running.splice(0)) {
        child.kill();
    }
});

test("a production build cannot be debugged from outside", async () => {
    test.setTimeout(180_000);

    // The control: with the switch kept, a debugger answers. How long that
    // takes on this machine sets how long the real check waits.
    const controlPort = await freePort();
    launch("out-demo", controlPort);
    const started = Date.now();
    await expect.poll(() => debuggerAnswers(controlPort), { timeout: 60_000 }).toBe(true);
    const startUp = Date.now() - started;

    // The same switch, on the build people install, with the dev switch off
    // in every way it can be off. Only exactly "1" is dev mode: any other
    // value leaves the client talking to the real service, and a build that
    // does that must never be open to a debugger.
    const off = ["", "0", "true", " 1", "1 ", "yes"];
    const probes = await Promise.all(
        off.map(async (value) => {
            const port = await freePort();
            return { value, port, app: launch("out", port, { UBC_VPN_DEV: value }) };
        }),
    );
    // Give them several times as long as the control needed, and look the
    // whole while.
    const deadline = Date.now() + Math.max(5000, startUp * 4);
    const answered = new Set<string>();
    while (Date.now() < deadline) {
        for (const probe of probes) {
            if (await debuggerAnswers(probe.port)) {
                answered.add(JSON.stringify(probe.value));
            }
        }
        await new Promise((tick) => setTimeout(tick, 100));
    }
    expect([...answered]).toEqual([]);
    // They were running all that time, not gone: a dead app answers nothing either.
    for (const probe of probes) {
        expect(probe.app.exitCode, JSON.stringify(probe.value)).toBeNull();
    }
});

test("an unpackaged build in dev mode can be driven by the tests", async () => {
    test.setTimeout(120_000);
    // The run against the real client and a dev-mode service drives this very
    // build through the port. It talks to a pretend service and says so on
    // every screen; packaged, the dev switch is ignored and so is this.
    const port = await freePort();
    launch("out", port, { UBC_VPN_DEV: "1" });
    await expect.poll(() => debuggerAnswers(port), { timeout: 60_000 }).toBe(true);
});

test("the packaged app cannot be debugged from outside", async () => {
    test.skip(
        PACKAGED_APP === undefined || !isCi(process.env),
        "only on CI, with UBC_VPN_PACKAGED_APP naming the installed program",
    );
    test.setTimeout(180_000);
    const program = PACKAGED_APP as string;

    const controlPort = await freePort();
    launch("out-demo", controlPort);
    const started = Date.now();
    await expect.poll(() => debuggerAnswers(controlPort), { timeout: 60_000 }).toBe(true);
    const startUp = Date.now() - started;

    // One instance: the app allows only one. The dev switch is set to the one
    // value that turns dev mode on, which a packaged app must ignore.
    const port = await freePort();
    const app = launch({ program }, port, { UBC_VPN_DEV: "1" });
    const deadline = Date.now() + Math.max(10_000, startUp * 4);
    let answered = false;
    while (Date.now() < deadline && !answered) {
        answered = await debuggerAnswers(port);
        await new Promise((tick) => setTimeout(tick, 100));
    }
    expect(answered).toBe(false);
    expect(app.exitCode).toBeNull();
});
