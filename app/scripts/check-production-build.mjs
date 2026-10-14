// Fails if a production build (`pnpm build`) contains any part of demo mode.
// Run it after the build. Demo mode is a fake service for designing the
// interface; a build people install must not be able to show a fake state.
//
// With `--control`, it checks the opposite of a demo build (`out-demo/`):
// every marker must be there. That proves the markers are still the right
// ones, so a clean result on the production build means something.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const control = process.argv.includes("--control");
const folder = control ? "out-demo" : "out";
const out = fileURLToPath(new URL(`../${folder}/`, import.meta.url));

// Strings that exist only in demo code: the fake service's scenario names,
// its IPC channels, and the component gallery's headings.
const markers = [
    "connected-crowded",
    "login-password-again",
    "routes-too-long-to-save",
    "demo:set-scenario",
    "demo:list-scenarios",
    "Show a state",
    // The log screen, which no production build has yet (`__LOGS__`): its
    // IPC, its words, and the main-process code that carries lines to it.
    "logs:copy-report",
    "Copy report",
    "UBC VPN diagnostics report",
    "logs-new-run",
];

if (!existsSync(out)) {
    console.error(`${folder}/ does not exist: build it first`);
    process.exit(1);
}

const files = readdirSync(out, { recursive: true, encoding: "utf8" }).filter((file) =>
    /\.(js|html|css)$/.test(file),
);
const hits = [];
const found = new Set();
for (const file of files) {
    const text = readFileSync(join(out, file), "utf8");
    for (const marker of markers) {
        if (text.includes(marker)) {
            found.add(marker);
            hits.push(`${file} contains "${marker}"`);
        }
    }
    if (/gallery-view/.test(file)) {
        hits.push(`${file} is the demo gallery`);
    }
}

const problems = [];
// Guards the check itself: an empty folder would otherwise pass.
if (!files.some((file) => /main[\\/]index\.js$/.test(file))) {
    problems.push(`${folder}/main/index.js is missing: the build did not finish`);
}
if (control) {
    for (const marker of markers.filter((wanted) => !found.has(wanted))) {
        problems.push(`the demo build has no "${marker}": that marker no longer detects demo code`);
    }
} else {
    problems.push(...hits);
}

if (problems.length > 0) {
    console.error(problems.join("\n"));
    process.exit(1);
}
console.log(
    control
        ? `${files.length} built files, all ${markers.length} demo markers present`
        : `${files.length} built files, no demo code`,
);
