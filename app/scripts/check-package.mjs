// Checks a packaged Windows app: the folder electron-builder made
// (dist/win-unpacked) or the folder it was installed to.
//
//   node scripts/check-package.mjs <app folder> [<electron-builder output folder>]
//
// It fails unless:
// - every Electron fuse is in the state written below, and the program has no
//   fuse this script does not know (a newer Electron may add one, and it must
//   be reviewed before it ships);
// - the app's code is in the archive, and the licence texts are beside it;
// - nothing an updater would read is in the app or in the output folder.
//
// The states are written out here, not read from electron-builder.yml, so a
// change to that file cannot also change what this script accepts. The
// reasons for them are in docs/architecture.md, "What the installers must do".

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { FuseState, FuseV1Options, getCurrentFuseWire } from "@electron/fuses";

const PROGRAM = "UBC VPN.exe";

/** Each fuse, by name, and the state it must be in. */
const EXPECTED_FUSES = {
    RunAsNode: FuseState.DISABLE,
    EnableCookieEncryption: FuseState.ENABLE,
    EnableNodeOptionsEnvironmentVariable: FuseState.DISABLE,
    EnableNodeCliInspectArguments: FuseState.DISABLE,
    EnableEmbeddedAsarIntegrityValidation: FuseState.ENABLE,
    OnlyLoadAppFromAsar: FuseState.ENABLE,
    LoadBrowserProcessSpecificV8Snapshot: FuseState.DISABLE,
    GrantFileProtocolExtraPrivileges: FuseState.DISABLE,
    // Electron's default, left as it is: V8 uses guard pages, not explicit
    // checks, to catch WebAssembly reading out of bounds. The app runs no
    // WebAssembly. electron-builder 26.15.3 cannot set this fuse.
    WasmTrapHandlers: FuseState.ENABLE,
};

/** Files that must be in the app folder, relative to it. */
const REQUIRED_FILES = [
    PROGRAM,
    "LICENSE.electron.txt",
    "LICENSES.chromium.html",
    "resources/app.asar",
    "resources/licenses/LICENSE-MIT",
    "resources/licenses/LICENSE-APACHE",
    "resources/licenses/fonts/geist-mono/LICENSE",
    "resources/licenses/fonts/instrument-sans/LICENSE",
];

/** What an updater reads, anywhere in the app or the output folder. */
const UPDATER_FILE = /^(latest.*\.yml|app-update\.yml|.*\.blockmap)$/;

const stateName = (state) => FuseState[state] ?? String(state);

function filesUnder(folder) {
    return readdirSync(folder, { recursive: true, withFileTypes: true })
        .filter((entry) => entry.isFile())
        .map((entry) => join(entry.parentPath, entry.name));
}

async function check(appFolder, outputFolder) {
    const problems = [];

    for (const file of REQUIRED_FILES) {
        if (!existsSync(join(appFolder, file))) {
            problems.push(`missing: ${file}`);
        }
    }
    // Electron's own default app and version file, left by a copy of
    // Electron's folder; scripts/after-pack.cjs removes them.
    for (const leftover of ["resources/default_app.asar", "version"]) {
        if (existsSync(join(appFolder, leftover))) {
            problems.push(`left over from Electron: ${leftover}`);
        }
    }
    if (existsSync(join(appFolder, "resources", "app"))) {
        problems.push("the app's code is in resources/app, outside the archive");
    }

    for (const folder of [appFolder, outputFolder].filter(Boolean)) {
        for (const file of filesUnder(folder)) {
            if (UPDATER_FILE.test(file.split(/[\\/]/).at(-1))) {
                problems.push(`a file for an updater: ${file}`);
            }
        }
    }

    const wire = await getCurrentFuseWire(join(appFolder, PROGRAM));
    const seen = new Set();
    for (const [key, state] of Object.entries(wire)) {
        if (key === "version" || key === "resetAdHocDarwinSignature") {
            continue;
        }
        const name = FuseV1Options[key];
        const expected = EXPECTED_FUSES[name];
        seen.add(name);
        if (expected === undefined) {
            problems.push(
                `fuse ${name ?? key} is not known to this script (it is ${stateName(state)})`,
            );
        } else if (state !== expected) {
            problems.push(`fuse ${name} is ${stateName(state)}, not ${stateName(expected)}`);
        } else {
            console.log(`fuse ${name}: ${stateName(state)}`);
        }
    }
    for (const name of Object.keys(EXPECTED_FUSES)) {
        if (!seen.has(name)) {
            problems.push(`fuse ${name} is not on the program's wire`);
        }
    }
    return problems;
}

const [appFolder, outputFolder] = process.argv.slice(2);
if (appFolder === undefined) {
    console.error("usage: node scripts/check-package.mjs <app folder> [<output folder>]");
    process.exit(2);
}
const problems = await check(appFolder, outputFolder);
for (const problem of problems) {
    console.error(`check-package: ${problem}`);
}
if (problems.length > 0) {
    process.exit(1);
}
console.log(`check-package: ${appFolder} is as it should be`);
