// Fails if a production build (`pnpm build`) contains any part of demo mode.
// Run it after the build. Demo mode is a fake service for designing the
// interface; a build people install must not be able to show a fake state.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const out = fileURLToPath(new URL("../out/", import.meta.url));

// Strings that exist only in demo code: the fake service's scenario names,
// its IPC channels, and the component gallery's headings.
const markers = ["connected-crowded", "demo:set-scenario", "demo:list-scenarios", "Show a state"];

if (!existsSync(out)) {
    console.error("out/ does not exist: run `pnpm build` first");
    process.exit(1);
}

const files = readdirSync(out, { recursive: true, encoding: "utf8" }).filter((file) =>
    /\.(js|html|css)$/.test(file),
);
const hits = [];
for (const file of files) {
    const text = readFileSync(join(out, file), "utf8");
    for (const marker of markers) {
        if (text.includes(marker)) {
            hits.push(`${file} contains "${marker}"`);
        }
    }
    if (/gallery-view/.test(file)) {
        hits.push(`${file} is the demo gallery`);
    }
}

// Guards the check itself: an empty folder would otherwise pass.
if (!files.some((file) => /main[\\/]index\.js$/.test(file))) {
    hits.push("out/main/index.js is missing: the build did not finish");
}

if (hits.length > 0) {
    console.error(hits.join("\n"));
    process.exit(1);
}
console.log(`${files.length} built files, no demo code`);
