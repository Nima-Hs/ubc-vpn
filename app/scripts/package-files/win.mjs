// What scripts/check-package.mjs requires of the packaged Windows app: the
// folder electron-builder made (dist/win-unpacked) or the folder it was
// installed to. Paths are relative to that folder.
//
// The states are written out here, not read from electron-builder.yml, so a
// change to that file cannot also change what the check accepts. The
// reasons for them are in docs/architecture.md, "What the installers must do".

import { FuseState } from "@electron/fuses";

/** The program whose fuses are checked. */
export const PROGRAM = "UBC VPN.exe";

/** Each fuse, by name, and the state it must be in. */
export const EXPECTED_FUSES = {
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

/** Files that must be in the app folder. */
export const REQUIRED_FILES = [
    PROGRAM,
    "LICENSE.electron.txt",
    "LICENSES.chromium.html",
    "resources/app.asar",
    "resources/licenses/LICENSE-MIT",
    "resources/licenses/LICENSE-APACHE",
    "resources/licenses/fonts/geist-mono/LICENSE",
    "resources/licenses/fonts/instrument-sans/LICENSE",
    // packaging/windows/stage.sh: the programs, what they load, the
    // licences that go with them, and the policy.
    "resources/bin/ubc-vpn.exe",
    "resources/bin/ubc-vpn-service.exe",
    "resources/bin/libopenconnect-5.dll",
    "resources/bin/wintun.dll",
    "resources/bin/vcruntime140.dll",
    "resources/licenses/SOURCES.txt",
    "resources/licenses/wintun/LICENSE.txt",
    "resources/licenses/microsoft/microsoft-vc-runtime-NOTICE.txt",
    "resources/licenses/microsoft/microsoft-visual-studio-2026-community-license.txt",
    "resources/licenses/microsoft/microsoft-visual-studio-2026-distributable-code.txt",
    "resources/policy.json",
    // The taskbar button's state icons, the tray's own pictures (src/main/tray/tray.ts).
    ...[
        "off",
        "busy-0",
        "busy-1",
        "busy-2",
        "on",
        "busy-full-0",
        "busy-full-1",
        "busy-full-2",
        "on-full",
        "attention",
        "problem",
    ].map((name) => `resources/state-icons/${name}.ico`),
];

/**
 * Electron's own default app and version file, left by a copy of Electron's
 * folder; scripts/after-pack.cjs removes them.
 */
export const LEFTOVER_FILES = ["resources/default_app.asar", "version"];

/** Where the app's code would be if it were outside the archive. */
export const UNPACKED_APP = "resources/app";
