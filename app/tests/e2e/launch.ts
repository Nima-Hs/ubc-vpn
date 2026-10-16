// The only way the end-to-end tests start an app. Each app's environment is
// the test runner's, filtered by `launchEnvironment` (safe-env.ts), with the
// test's own variables laid over it. A test cannot hand on the runner's
// environment itself: tests/e2e-environment.test.ts fails if a spec starts
// an app any other way.

import { type ChildProcess, type SpawnOptions, spawn } from "node:child_process";
import { type ElectronApplication, _electron as electron } from "@playwright/test";
import { launchEnvironment } from "./safe-env";

/** The runner's environment, filtered, with `own` over it. */
function environment(own: Record<string, string> = {}): Record<string, string> {
    const filtered = Object.entries(launchEnvironment(process.env)).filter(
        (entry): entry is [string, string] => entry[1] !== undefined,
    );
    return { ...Object.fromEntries(filtered), ...own };
}

type LaunchOptions = NonNullable<Parameters<typeof electron.launch>[0]>;

/** Starts the app through Playwright. `env` holds only the test's own variables. */
export function launchApp(
    options: Omit<LaunchOptions, "env"> & { env?: Record<string, string> },
): Promise<ElectronApplication> {
    return electron.launch({ ...options, env: environment(options.env) });
}

/** Starts a program as a plain process. `env` holds only the test's own variables. */
export function spawnApp(
    program: string,
    args: readonly string[],
    options: Omit<SpawnOptions, "env"> & { env?: Record<string, string> } = {},
): ChildProcess {
    return spawn(program, args, { ...options, env: environment(options.env) });
}
