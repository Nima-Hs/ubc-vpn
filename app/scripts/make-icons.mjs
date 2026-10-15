// Draws the app icon files in build/ afresh from the mark's description in
// code: `pnpm icons`. The drawing is done by tests/icons.test.ts, which in a
// normal run checks that the committed files match it.

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");
const run = spawnSync(
    process.execPath,
    [join(app, "node_modules/vitest/vitest.mjs"), "run", "tests/icons.test.ts"],
    { cwd: app, stdio: "inherit", env: { ...process.env, UPDATE_ICONS: "1" } },
);
process.exit(run.status ?? 1);
