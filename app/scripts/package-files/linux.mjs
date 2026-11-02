// What scripts/check-package.mjs requires of the packaged Linux app: the
// folder electron-builder made (dist/linux-unpacked) or the folder it was
// installed to (/opt/UBC VPN), and, given electron-builder's output folder,
// the .deb and the .rpm in it. Paths are relative to the app folder.
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

/** The packages' name. */
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
    "libgbm1",
    "libasound2 | libasound2t64",
    "systemd-resolved | systemd (<< 251.3-2~)",
    "libdbus-1-3",
    "libgnutls30 (>= 3.7.3) | libgnutls30t64",
    "zlib1g",
    "libc6 (>= 2.34)",
];

/** The .rpm's requirements, in the same order, as `rpm --requires` lists them (in any order). */
const RPM_REQUIRES = [
    "gtk3",
    "libnotify",
    "nss",
    "libXScrnSaver",
    "(libXtst or libXtst6)",
    "xdg-utils",
    "at-spi2-core",
    "(libuuid or libuuid1)",
    "systemd-resolved",
    "dbus-libs",
    "gnutls >= 3.7.3",
    "zlib",
    "glibc >= 2.34",
];

/** Where the packages put the app, and the names electron-builder fills in. */
const TEMPLATE_NAMES = { executable: PROGRAM, sanitizedProductName: "UBC VPN" };

/** The command-line client's link (decision G19), and what it points to. */
const CLIENT_LINK = "/usr/bin/ubc-vpn";
const CLIENT = "/opt/UBC VPN/resources/bin/ubc-vpn";

/** The library, as the folder check requires it: a file, never a link. */
const LIBRARY = "/opt/UBC VPN/resources/bin/libopenconnect.so.5";

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
        const [listed, target] = mode.startsWith("l") ? rest.split(" -> ") : [rest];
        // From `/`, as rpm lists them, without the trailing slash of a folder.
        const path = listed.replace(/^\./, "").replace(/(.)\/$/, "$1") || "/";
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

    return [...problems, ...checkFiles(".deb", debFiles(deb))];
}

/**
 * What every package's files must be, by path from `/` (mode as `ls`
 * shows it, owner as user/group, link target): root's, changeable by root
 * alone, the client's link, and the library a file.
 */
function checkFiles(kind, files) {
    const problems = [];
    for (const [path, file] of files) {
        // fpm writes owners by number, which dpkg-deb lists as 0/0.
        if (file.owner !== "root/root" && file.owner !== "0/0") {
            problems.push(`${path} in the ${kind} belongs to ${file.owner}, not root`);
        }
        // Only root may change what it installs (scripts/after-pack.cjs).
        if (!file.mode.startsWith("l") && (file.mode[5] === "w" || file.mode[8] === "w")) {
            problems.push(`${path} in the ${kind} can be changed by others (${file.mode})`);
        }
    }
    const link = files.get(CLIENT_LINK);
    if (!link?.mode.startsWith("l") || link.target !== CLIENT) {
        problems.push(`${CLIENT_LINK} in the ${kind} is not a link to ${CLIENT}`);
    }
    if (!files.get(LIBRARY)?.mode.startsWith("-")) {
        problems.push(`${LIBRARY} in the ${kind} is not a file`);
    }
    return problems;
}

/** rpm's answer to a query of the package `rpm`. */
function rpmQuery(rpm, ...args) {
    return execFileSync("rpm", ["--query", "--package", ...args, rpm], { encoding: "utf8" });
}

function checkRpm(rpm) {
    const problems = [];
    const name = rpmQuery(rpm, "--queryformat", "%{NAME}");
    if (name !== PACKAGE) {
        problems.push(`the .rpm is named ${name}, not ${PACKAGE}`);
    }
    // rpm adds requirements of its own (rpmlib, the scripts' shell), so
    // ours must all be there and nothing else of a package's.
    const requires = rpmQuery(rpm, "--requires")
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("rpmlib(") && !line.startsWith("/"))
        .sort();
    if (requires.join(", ") !== [...RPM_REQUIRES].sort().join(", ")) {
        problems.push(`the .rpm requires ${requires.join(", ")}, not ${RPM_REQUIRES.join(", ")}`);
    }
    const configs = rpmQuery(rpm, "--configfiles").trim();
    if (configs !== "") {
        problems.push(`the .rpm has config files: ${configs.split("\n").join(", ")}`);
    }
    const scripts = rpmQuery(rpm, "--scripts");
    for (const template of ["after-install", "after-remove"]) {
        if (!scripts.includes(electronBuilderScript(template))) {
            problems.push(`the .rpm's scripts lack electron-builder's ${template} script`);
        }
    }
    const prerm = new URL("../../../packaging/linux/before-remove.sh", import.meta.url);
    if (!scripts.includes(readFileSync(prerm, "utf8").trimEnd())) {
        problems.push("the .rpm's scripts lack packaging/linux/before-remove.sh");
    }

    const files = new Map();
    const listing = rpmQuery(
        rpm,
        "--queryformat",
        "[%{FILEMODES:perms}\t%{FILEUSERNAME}/%{FILEGROUPNAME}\t%{FILELINKTOS}\t%{FILENAMES}\n]",
    );
    for (const line of listing.split("\n").filter(Boolean)) {
        const [mode, owner, target, path] = line.split("\t");
        files.set(path, { mode, owner, target: target || undefined });
        if (path.startsWith("/usr/lib/.build-id")) {
            problems.push(`the .rpm has rpmbuild's link ${path}`);
        }
    }
    return [...problems, ...checkFiles(".rpm", files)];
}

/** Checks the packages in electron-builder's output folder. */
export function checkOutput(outputFolder) {
    const problems = [];
    const checks = [
        [".deb", checkDeb],
        [".rpm", checkRpm],
    ];
    for (const [kind, check] of checks) {
        const found = readdirSync(outputFolder).filter((name) => name.endsWith(kind));
        if (found.length !== 1) {
            problems.push(`${found.length} ${kind} packages in ${outputFolder}, not 1`);
        } else {
            problems.push(...check(join(outputFolder, found[0])));
        }
    }
    return problems;
}
