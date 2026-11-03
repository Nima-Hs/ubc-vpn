// Checks a packaged app: the folder electron-builder made (dist/win-unpacked
// on Windows) or the folder it was installed to.
//
//   node scripts/check-package.mjs <win|mac|linux> <app folder> [<electron-builder output folder>]
//
// What each system's package must hold is in scripts/package-files/<system>.mjs.
// It fails unless:
// - every Electron fuse is in the state written there, and the program has
//   no fuse that file does not know (a newer Electron may add one, and it
//   must be reviewed before it ships);
// - the app's code is in the archive, and the licence texts are beside it;
// - nothing an updater would read is in the app or in the output folder;
// - the packages in the output folder are as that file requires, where it
//   has a checkOutput function (Linux: the .deb's scripts, dependencies,
//   conffiles and links; macOS: the .pkg's scripts, owners and where it may
//   install).
//
// The states are written out in those files, not read from
// electron-builder.yml, so a change to that file cannot also change what
// this script accepts. The reasons for them are in docs/architecture.md,
// "What the installers must do".

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { FuseState, FuseV1Options, getCurrentFuseWire } from "@electron/fuses";

const SYSTEMS = ["win", "mac", "linux"];

/** What an updater reads, anywhere in the app or the output folder. */
const UPDATER_FILE = /^(latest.*\.yml|app-update\.yml|.*\.blockmap)$/;

const stateName = (state) => FuseState[state] ?? String(state);

function filesUnder(folder) {
    return readdirSync(folder, { recursive: true, withFileTypes: true })
        .filter((entry) => entry.isFile())
        .map((entry) => join(entry.parentPath, entry.name));
}

async function check(expected, appFolder, outputFolder) {
    const problems = [];

    for (const file of expected.REQUIRED_FILES) {
        if (!existsSync(join(appFolder, file))) {
            problems.push(`missing: ${file}`);
        }
    }
    for (const leftover of expected.LEFTOVER_FILES) {
        if (existsSync(join(appFolder, leftover))) {
            problems.push(`left over from Electron: ${leftover}`);
        }
    }
    if (existsSync(join(appFolder, expected.UNPACKED_APP))) {
        problems.push(`the app's code is in ${expected.UNPACKED_APP}, outside the archive`);
    }

    for (const folder of [appFolder, outputFolder].filter(Boolean)) {
        for (const file of filesUnder(folder)) {
            if (UPDATER_FILE.test(file.split(/[\\/]/).at(-1))) {
                problems.push(`a file for an updater: ${file}`);
            }
        }
    }

    const wire = await getCurrentFuseWire(join(appFolder, expected.PROGRAM));
    const seen = new Set();
    for (const [key, state] of Object.entries(wire)) {
        if (key === "version" || key === "resetAdHocDarwinSignature") {
            continue;
        }
        const name = FuseV1Options[key];
        const want = expected.EXPECTED_FUSES[name];
        seen.add(name);
        if (want === undefined) {
            problems.push(
                `fuse ${name ?? key} is not known to this script (it is ${stateName(state)})`,
            );
        } else if (state !== want) {
            problems.push(`fuse ${name} is ${stateName(state)}, not ${stateName(want)}`);
        } else {
            console.log(`fuse ${name}: ${stateName(state)}`);
        }
    }
    for (const name of Object.keys(expected.EXPECTED_FUSES)) {
        if (!seen.has(name)) {
            problems.push(`fuse ${name} is not on the program's wire`);
        }
    }
    // The packages themselves, where the system's file checks them.
    if (outputFolder !== undefined && expected.checkOutput !== undefined) {
        problems.push(...expected.checkOutput(outputFolder));
    }
    return problems;
}

const [system, appFolder, outputFolder] = process.argv.slice(2);
if (!SYSTEMS.includes(system) || appFolder === undefined) {
    console.error(
        "usage: node scripts/check-package.mjs <win|mac|linux> <app folder> [<output folder>]",
    );
    process.exit(2);
}
const expected = await import(`./package-files/${system}.mjs`);
const problems = await check(expected, appFolder, outputFolder);
for (const problem of problems) {
    console.error(`check-package: ${problem}`);
}
if (problems.length > 0) {
    process.exit(1);
}
console.log(`check-package: ${appFolder} is as it should be`);
