// What scripts/check-package.mjs requires of the packaged Linux app: the
// folder electron-builder made (dist/linux-unpacked) or the folder it was
// installed to (/opt/UBC VPN), and, given electron-builder's output folder,
// the .deb in it. Paths are relative to the app folder.
//
// The states are written out here, not read from electron-builder.linux.yml,
// so a change to that file cannot also change what the check accepts. The
// reasons for them are in docs/architecture.md, "What the installers must do".

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FuseState } from "@electron/fuses";

/** The program whose fuses are checked. */
export const PROGRAM = "ubc-vpn-app";

/** Each fuse, by name, and the state it must be in: the same as on Windows. */
export const EXPECTED_FUSES = {
    RunAsNode: FuseState.DISABLE,
    EnableCookieEncryption: FuseState.ENABLE,
    EnableNodeOptionsEnvironmentVariable: FuseState.DISABLE,
    EnableNodeCliInspectArguments: FuseState.DISABLE,
    // Set as on every system, but Electron checks the archive only on
    // Windows and macOS. On Linux the root-owned install folder is the only
    // protection (docs/architecture.md).
    EnableEmbeddedAsarIntegrityValidation: FuseState.ENABLE,
    OnlyLoadAppFromAsar: FuseState.ENABLE,
    LoadBrowserProcessSpecificV8Snapshot: FuseState.DISABLE,
    GrantFileProtocolExtraPrivileges: FuseState.DISABLE,
    // Electron's default, left as it is, as on Windows (see win.mjs).
    WasmTrapHandlers: FuseState.ENABLE,
};

/** Files that must be in the app folder. */
export const REQUIRED_FILES = [
    PROGRAM,
    "chrome-sandbox",
    "LICENSE.electron.txt",
    "LICENSES.chromium.html",
    "resources/app.asar",
    // electron-builder's AppArmor profile, which its install script copies
    // to /etc/apparmor.d on Ubuntu 24.04.
    "resources/apparmor-profile",
    "resources/licenses/LICENSE-MIT",
    "resources/licenses/LICENSE-APACHE",
    "resources/licenses/fonts/geist-mono/LICENSE",
    "resources/licenses/fonts/instrument-sans/LICENSE",
    // packaging/linux/stage.sh: the programs, the library they load, its
    // licences, and the policy.
    "resources/bin/ubc-vpn",
    "resources/bin/ubc-vpn-service",
    "resources/bin/libopenconnect.so.5",
    "resources/licenses/SOURCES.txt",
    "resources/licenses/native/openconnect/COPYING.LGPL",
    "resources/licenses/native/json-parser/LICENSE",
    "resources/licenses/native/libxml2/Copyright",
    "resources/policy.json",
];

/**
 * Electron's own default app and version file, left by a copy of Electron's
 * folder; scripts/after-pack.cjs removes them.
 */
export const LEFTOVER_FILES = ["resources/default_app.asar", "version"];

/** Where the app's code would be if it were outside the archive. */
export const UNPACKED_APP = "resources/app";

/** The .deb's name for the package. */
const PACKAGE = "ubc-vpn";

/**
 * The .deb's dependencies, in order: electron-builder's own list for
 * Electron, then ours (electron-builder.linux.yml says why each is there).
 */
const DEB_DEPENDS = [
    "libgtk-3-0",
    "libnotify4",
    "libnss3",
    "libxss1",
    "libxtst6",
    "xdg-utils",
    "libatspi2.0-0",
    "libuuid1",
    "libsecret-1-0",
    "systemd-resolved | systemd (<< 251.3-2~)",
    "libdbus-1-3",
    "libgnutls30 (>= 3.7.3) | libgnutls30t64",
    "zlib1g",
    "libc6 (>= 2.34)",
];

/** Where the packages put the app, and the names electron-builder fills in. */
const TEMPLATE_NAMES = { executable: PROGRAM, sanitizedProductName: "UBC VPN" };

/** The command-line client's link (decision G19), and what it points to. */
const CLIENT_LINK = "./usr/bin/ubc-vpn";
const CLIENT = "/opt/UBC VPN/resources/bin/ubc-vpn";

/** The library, as the folder check requires it: a file, never a link. */
const LIBRARY = "./opt/UBC VPN/resources/bin/libopenconnect.so.5";

/**
 * electron-builder's own install script `name` (after-install or
 * after-remove), filled in as for this app, without its first line.
 */
function electronBuilderScript(name) {
    const require = createRequire(import.meta.url);
    const builder = createRequire(require.resolve("electron-builder/package.json"));
    const lib = builder.resolve("app-builder-lib/package.json");
    const text = readFileSync(join(lib, "..", "templates", "linux", `${name}.tpl`), "utf8");
    const filled = text.replace(/\$\{([a-zA-Z]+)\}/g, (_, key) => {
        if (!(key in TEMPLATE_NAMES)) {
            throw new Error(`${name}.tpl uses \${${key}}, which this check does not know`);
        }
        return TEMPLATE_NAMES[key];
    });
    return filled.slice(filled.indexOf("\n") + 1).trimEnd();
}

/** The fields of a .deb's control file. */
function controlFields(text) {
    const fields = {};
    let key;
    for (const line of text.split("\n")) {
        const field = /^([A-Za-z-]+): ?(.*)$/.exec(line);
        if (field) {
            key = field[1];
            fields[key] = field[2];
        } else if (key && line.startsWith(" ")) {
            fields[key] += `\n${line}`;
        }
    }
    return fields;
}

/** The .deb's files, by path: mode, owner and link target. */
function debFiles(deb) {
    const files = new Map();
    const listing = execFileSync("dpkg-deb", ["--contents", deb], { encoding: "utf8" });
    for (const line of listing.split("\n").filter(Boolean)) {
        const entry = /^(\S+) (\S+)\s+\d+ \S+ \S+ (.*)$/.exec(line);
        if (!entry) {
            throw new Error(`dpkg-deb listed a line this check cannot read: ${line}`);
        }
        const [, mode, owner, rest] = entry;
        const [path, target] = mode.startsWith("l") ? rest.split(" -> ") : [rest];
        files.set(path, { mode, owner, target });
    }
    return files;
}

function checkDeb(deb) {
    const problems = [];
    const control = mkdtempSync(join(tmpdir(), "x7-control-"));
    try {
        execFileSync("dpkg-deb", ["--control", deb, control]);
        const scripts = new Set(readdirSync(control));
        const fields = controlFields(readFileSync(join(control, "control"), "utf8"));
        if (fields.Package !== PACKAGE) {
            problems.push(`the .deb is named ${fields.Package}, not ${PACKAGE}`);
        }
        if (fields.Depends !== DEB_DEPENDS.join(", ")) {
            problems.push(`the .deb depends on ${fields.Depends}, not ${DEB_DEPENDS.join(", ")}`);
        }
        // policy.json is copied to /etc/ubc-vpn by `install`; no file of the
        // package is dpkg's to keep or ask about on an update.
        if (scripts.has("conffiles")) {
            const listed = readFileSync(join(control, "conffiles"), "utf8").trim();
            if (listed !== "") {
                problems.push(`the .deb has conffiles: ${listed.split("\n").join(", ")}`);
            }
        }
        // Our scripts hold electron-builder's own, unchanged.
        const held = [
            ["postinst", "after-install"],
            ["postrm", "after-remove"],
        ];
        for (const [script, template] of held) {
            if (!scripts.has(script)) {
                problems.push(`the .deb has no ${script}`);
            } else if (
                !readFileSync(join(control, script), "utf8").includes(
                    electronBuilderScript(template),
                )
            ) {
                problems.push(`the .deb's ${script} lacks electron-builder's ${template} script`);
            }
        }
        const prerm = new URL("../../../packaging/linux/before-remove.sh", import.meta.url);
        if (!scripts.has("prerm")) {
            problems.push("the .deb has no prerm");
        } else if (readFileSync(join(control, "prerm"), "utf8") !== readFileSync(prerm, "utf8")) {
            problems.push("the .deb's prerm is not packaging/linux/before-remove.sh");
        }
    } finally {
        rmSync(control, { recursive: true, force: true });
    }

    const files = debFiles(deb);
    for (const [path, file] of files) {
        // fpm writes owners by number, which dpkg-deb lists as 0/0.
        if (file.owner !== "root/root" && file.owner !== "0/0") {
            problems.push(`${path} in the .deb belongs to ${file.owner}, not root`);
        }
    }
    const link = files.get(CLIENT_LINK);
    if (!link?.mode.startsWith("l") || link.target !== CLIENT) {
        problems.push(`${CLIENT_LINK} in the .deb is not a link to ${CLIENT}`);
    }
    if (!files.get(LIBRARY)?.mode.startsWith("-")) {
        problems.push(`${LIBRARY} in the .deb is not a file`);
    }
    return problems;
}

/** Checks the packages in electron-builder's output folder. */
export function checkOutput(outputFolder) {
    const debs = readdirSync(outputFolder).filter((name) => name.endsWith(".deb"));
    if (debs.length !== 1) {
        return [`${debs.length} .deb packages in ${outputFolder}, not 1`];
    }
    return checkDeb(join(outputFolder, debs[0]));
}
