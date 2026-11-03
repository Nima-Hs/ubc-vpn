// What scripts/check-package.mjs requires of the packaged macOS app: the app
// electron-builder made (dist/mac-arm64/UBC VPN.app) or the one it was
// installed as (/Applications/UBC VPN.app), and, given electron-builder's
// output folder, the .pkg in it. Paths are relative to the app.
//
// The states are written out here, not read from electron-builder.mac.yml, so
// a change to that file cannot also change what the check accepts. The reasons
// for them are in docs/architecture.md, "What the installers must do".

import { execFileSync } from "node:child_process";
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FuseState } from "@electron/fuses";

/** The file whose fuses are checked: on macOS they are in the framework. */
export const PROGRAM = "Contents/Frameworks/Electron Framework.framework/Electron Framework";

/** Each fuse, by name, and the state it must be in: the same as on Windows. */
export const EXPECTED_FUSES = {
    RunAsNode: FuseState.DISABLE,
    EnableCookieEncryption: FuseState.ENABLE,
    EnableNodeOptionsEnvironmentVariable: FuseState.DISABLE,
    EnableNodeCliInspectArguments: FuseState.DISABLE,
    EnableEmbeddedAsarIntegrityValidation: FuseState.ENABLE,
    OnlyLoadAppFromAsar: FuseState.ENABLE,
    LoadBrowserProcessSpecificV8Snapshot: FuseState.DISABLE,
    GrantFileProtocolExtraPrivileges: FuseState.DISABLE,
    // Electron's default, left as it is, as on Windows (see win.mjs).
    WasmTrapHandlers: FuseState.ENABLE,
};

/** The libraries the client and the service each load, as files. */
const LIBRARIES = [
    "libgmp.10.dylib",
    "libgnutls.30.dylib",
    "libhogweed.7.dylib",
    "libnettle.9.dylib",
    "libopenconnect.5.dylib",
];

/** Files that must be in the app. */
export const REQUIRED_FILES = [
    "Contents/MacOS/UBC VPN",
    "Contents/Resources/app.asar",
    "Contents/Resources/licenses/LICENSE-MIT",
    "Contents/Resources/licenses/LICENSE-APACHE",
    "Contents/Resources/licenses/electron/LICENSE.electron.txt",
    "Contents/Resources/licenses/electron/LICENSES.chromium.html",
    "Contents/Resources/licenses/fonts/geist-mono/LICENSE",
    "Contents/Resources/licenses/fonts/instrument-sans/LICENSE",
    // packaging/macos/stage.sh: the client, the libraries and their licences.
    "Contents/Resources/bin/ubc-vpn",
    ...LIBRARIES.map((library) => `Contents/Resources/bin/${library}`),
    "Contents/Resources/licenses/SOURCES.txt",
    "Contents/Resources/licenses/native/openconnect/COPYING.LGPL",
    "Contents/Resources/licenses/native/openconnect/json-LICENSE",
    "Contents/Resources/licenses/native/gnutls/COPYING.LESSERv2",
    "Contents/Resources/licenses/native/nettle/COPYING.LESSERv3",
    "Contents/Resources/licenses/native/nettle/COPYINGv2",
    "Contents/Resources/licenses/native/nettle/COPYINGv3",
    "Contents/Resources/licenses/native/gmp/COPYING.LESSERv3",
    "Contents/Resources/licenses/native/gmp/COPYINGv2",
    "Contents/Resources/licenses/native/gmp/COPYINGv3",
];

/** Electron's own default app, left by a copy of Electron's folder. */
export const LEFTOVER_FILES = [
    "Contents/Resources/default_app.asar",
    // The service runs from a folder only root can change, never from the app.
    "Contents/Resources/bin/ubc-vpn-service",
    "Contents/Resources/policy.json",
];

/** Where the app's code would be if it were outside the archive. */
export const UNPACKED_APP = "Contents/Resources/app";

/** What the installer unpacks where only root can change it. */
const SCRIPT_FILES = ["policy.json", "postinstall", "service"];
const SERVICE_FILES = [...LIBRARIES, "ubc-vpn-service", "uninstall.sh"].sort();

/** The one component's identifier, the app's id. */
const IDENTIFIER = "io.github.nima-hs.ubc-vpn";

/** A home folder on the machine that built it. The runner's is not anyone's. */
const HOME_FOLDER = /\/Users\/(?!runner\b)[A-Za-z0-9._-]+/;

function run(program, args) {
    return execFileSync(program, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

/** Everything under `folder` that is a file, as paths relative to it. */
function filesIn(folder) {
    return readdirSync(folder, { recursive: true, withFileTypes: true })
        .filter((entry) => entry.isFile() || entry.isSymbolicLink())
        .map((entry) => join(entry.parentPath, entry.name));
}

function checkPackage(pkg) {
    const problems = [];
    const work = mkdtempSync(join(tmpdir(), "mac-pkg-"));
    const expanded = join(work, "expanded");
    try {
        run("/usr/sbin/pkgutil", ["--expand-full", pkg, expanded]);
        const component = join(expanded, `${IDENTIFIER}.pkg`);
        const scripts = join(component, "Scripts");

        const distribution = readFileSync(join(expanded, "Distribution"), "utf8");
        if (!/hostArchitectures="arm64"/.test(distribution)) {
            problems.push("the .pkg's Distribution does not name arm64 alone");
        }
        if (!/os-version min="13\.0"/.test(distribution)) {
            problems.push("the .pkg's Distribution does not require macOS 13.0");
        }
        if (!/enable_localSystem="true"/.test(distribution)) {
            problems.push("the .pkg cannot install on the startup disk");
        }
        for (const domain of ["enable_anywhere", "enable_currentUserHome"]) {
            if (!distribution.includes(`${domain}="false"`)) {
                problems.push(`the .pkg's Distribution does not set ${domain} to false`);
            }
        }

        const info = readFileSync(join(component, "PackageInfo"), "utf8");
        if (!info.includes('install-location="/Applications"')) {
            problems.push("the .pkg does not install in /Applications");
        }
        if (!info.includes('auth="root"')) {
            problems.push("the .pkg does not install as root");
        }
        if (/<relocate>/.test(info)) {
            problems.push("the .pkg can install into a copy of the app the user moved");
        }
        if (/<preinstall/.test(info)) {
            problems.push("the .pkg has a script before the install, which nothing needs");
        }
        if (!/<postinstall file="\.\/postinstall"/.test(info)) {
            problems.push("the .pkg does not run postinstall");
        }

        const names = (folder) => readdirSync(folder).sort().join(" ");
        if (names(scripts) !== SCRIPT_FILES.join(" ")) {
            problems.push(`the .pkg's scripts hold: ${names(scripts)}`);
        }
        const service = join(scripts, "service");
        if (names(service) !== SERVICE_FILES.join(" ")) {
            problems.push(`the service's folder in the .pkg holds: ${names(service)}`);
        }
        for (const file of readdirSync(service)) {
            const found = lstatSync(join(service, file));
            if (!found.isFile()) {
                problems.push(`${file} in the .pkg is not a file: the service refuses that`);
            }
        }

        // Who owns what will land, and who may change it, from the package's
        // own bill of materials: the unpacked copy here belongs to this user.
        const bom = run("/usr/bin/lsbom", ["-p", "fmUG", join(component, "Bom")]);
        for (const line of bom.split("\n").filter(Boolean)) {
            const [path, mode, user, group] = line.split("\t");
            if (user !== "root") {
                problems.push(`${path} in the .pkg belongs to ${user}, not root`);
            }
            if (group !== "wheel" && group !== "admin") {
                problems.push(`${path} in the .pkg is in group ${group}`);
            }
            const bits = Number.parseInt(mode, 8);
            // A link's own mode means nothing.
            if ((bits & 0o170000) !== 0o120000 && (bits & 0o022) !== 0) {
                problems.push(`others can change ${path} in the .pkg (${mode})`);
            }
        }

        // No home folder of whoever built it, in what describes the package or
        // in our own programs.
        const ours = [
            join(expanded, "Distribution"),
            join(component, "PackageInfo"),
            join(scripts, "postinstall"),
            join(service, "uninstall.sh"),
            join(service, "ubc-vpn-service"),
            join(service, "libopenconnect.5.dylib"),
        ];
        for (const file of ours) {
            const found = readFileSync(file, "latin1").match(HOME_FOLDER);
            if (found !== null) {
                problems.push(`${file.slice(expanded.length)} names ${found[0]}`);
            }
        }
        const payload = join(component, "Payload");
        for (const file of filesIn(payload)) {
            if (file.includes("Contents/Resources/bin/ubc-vpn")) {
                const found = readFileSync(file, "latin1").match(HOME_FOLDER);
                if (found !== null) {
                    problems.push(`the client names ${found[0]}`);
                }
            }
        }
    } finally {
        rmSync(work, { recursive: true, force: true });
    }
    return problems;
}

/** The checks of electron-builder's output folder: the .pkg, and only that. */
export function checkOutput(outputFolder) {
    const found = readdirSync(outputFolder).filter((name) => name.endsWith(".pkg"));
    const packages = found.filter((name) => /^ubc-vpn-.*-arm64\.pkg$/.test(name));
    if (packages.length !== 1 || found.length !== 1) {
        return [`expected one ubc-vpn-<version>-arm64.pkg, found: ${found.join(", ") || "none"}`];
    }
    const problems = checkPackage(join(outputFolder, packages[0]));
    // Decision G4: no .dmg or .zip.
    for (const name of readdirSync(outputFolder)) {
        if (/\.(dmg|zip)$/.test(name)) {
            problems.push(`${name} is built too: the .pkg is the only way in`);
        }
    }
    return problems;
}
