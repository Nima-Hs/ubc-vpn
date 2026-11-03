// Starts the update launcher the way the app does, with a real `spawn` and the
// options it is given, then quits as the app does once it says "started". Run by
// Node, and by Electron, by the tests in `update-launcher-real.test.ts` and
// `update-real.test.ts`. The command comes from the app's own `windowsLaunch`.

// Before anything else: in Electron an uncaught error is a real dialog on the desktop.
process.on("uncaughtException", () => process.exit(1));

// And nothing here throws out of the top level, so that an error while this file
// loads never depends on how Electron passes it on.
try {
    const { spawn } = require("node:child_process");
    const { readFileSync, writeFileSync } = require("node:fs");

    const quit = process.versions.electron
        ? (code) => require("electron").app.exit(code)
        : (code) => process.exit(code);

    const { file, args, options, env, out } = JSON.parse(
        readFileSync(process.env.UBC_VPN_TEST_LAUNCH, "utf8"),
    );
    const end = (result) => {
        try {
            writeFileSync(out, JSON.stringify({ ...result, at: Date.now() }));
        } catch {
            // The test has ended and its folder has gone.
        }
        quit(0);
    };
    const child = spawn(file, args, {
        ...options,
        env: { ...env, UBC_VPN_APP_PID: String(process.pid) },
    });
    child.on("error", () => end({ outcome: "error" }));
    child.on("close", (code) => end({ outcome: "closed", code }));
    child.stdout.on("data", (chunk) => {
        if (String(chunk).includes("started")) {
            child.stdout.destroy();
            child.unref();
            end({ outcome: "started" });
        }
    });
    setTimeout(() => end({ outcome: "timed out" }), 30_000);
} catch {
    process.exit(1);
}
