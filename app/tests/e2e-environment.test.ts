// Off CI, the apps the end-to-end tests launch must not inherit anything
// that could lead them to a real client, the real service, the user's
// settings or their saved password. See tests/e2e/safe-env.ts.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { isCi, launchEnvironment, leadsToRealClient } from "./e2e/safe-env";

const OWNER_SHELL = {
    PATH: "/usr/bin",
    HOME: "/home/someone",
    UBC_VPN_CLI: "C:/Program Files/UBC VPN/resources/bin/ubc-vpn.exe",
    UBC_VPN_DEV: "1",
    UBC_VPN_SYSTEM_CLI: "../target/debug/ubc-vpn",
    UBC_VPN_SYSTEM_SERVICE: "../target/debug/ubc-vpn-service",
    // Windows reads a variable's name in any case.
    Ubc_Vpn_Cli: "elsewhere/ubc-vpn.exe",
    // Harmless ones stay.
    UBC_VPN_TEST_HIDDEN: "1",
    UBC_VPN_PROFILE: "/tmp/profile",
};

describe("the environment end-to-end tests give the apps they launch", () => {
    it("leaves out everything that leads to a real client, off CI", () => {
        expect(launchEnvironment(OWNER_SHELL)).toEqual({
            PATH: "/usr/bin",
            HOME: "/home/someone",
            UBC_VPN_TEST_HIDDEN: "1",
            UBC_VPN_PROFILE: "/tmp/profile",
        });
    });

    it("names exactly those variables, in any case", () => {
        for (const name of ["UBC_VPN_CLI", "ubc_vpn_dev", "UBC_VPN_SYSTEM_ANYTHING_NEW"]) {
            expect(leadsToRealClient(name), name).toBe(true);
        }
        for (const name of ["UBC_VPN_PROFILE", "UBC_VPN_TEST_HIDDEN", "UBC_VPN_CLIENT", "PATH"]) {
            expect(leadsToRealClient(name), name).toBe(false);
        }
    });

    it("keeps everything on CI, where the machine is thrown away", () => {
        expect(launchEnvironment({ ...OWNER_SHELL, CI: "true" })).toEqual({
            ...OWNER_SHELL,
            CI: "true",
        });
    });

    it("counts only CI=true as CI", () => {
        expect(isCi({ CI: "true" })).toBe(true);
        for (const value of ["1", "TRUE", "yes", "false", "", undefined]) {
            expect(isCi({ CI: value }), String(value)).toBe(false);
            expect(launchEnvironment({ ...OWNER_SHELL, CI: value })).not.toHaveProperty(
                "UBC_VPN_CLI",
            );
        }
    });

    it("does not change the environment it is given", () => {
        const env = { ...OWNER_SHELL };
        launchEnvironment(env);
        expect(env).toEqual(OWNER_SHELL);
    });

    it("is the only way an end-to-end test starts an app", () => {
        const folder = join(__dirname, "e2e");
        const files = readdirSync(folder).filter((file) => file.endsWith(".ts"));
        const specs = files.filter((file) => file.endsWith(".spec.ts"));
        expect(specs.length).toBeGreaterThan(1);
        // Starting something, or handing on the runner's environment whole.
        const starts =
            /\belectron\.launch\b|\b_electron\b|\bspawn(Sync)?\(|\bexec(File)?(Sync)?\(|\bfork\(/;
        const handsOn = /\.\.\.process\.env\b|env:\s*process\.env\b/;
        for (const file of files) {
            const text = readFileSync(join(folder, file), "utf8");
            if (file === "launch.ts") {
                // The one place: it starts from the filtered environment.
                expect(text).toMatch(/launchEnvironment\(process\.env\)/);
                expect(text).not.toMatch(handsOn);
                continue;
            }
            expect(text, `${file} starts something itself`).not.toMatch(starts);
            expect(text, `${file} hands on the environment`).not.toMatch(handsOn);
        }
        // Every spec that starts an app does it through launch.ts: itself, or
        // through fixture.ts, which starts the spec's app with launch.ts.
        const fixture = readFileSync(join(folder, "fixture.ts"), "utf8");
        expect(fixture, "fixture.ts").toMatch(/from "\.\/launch"/);
        for (const spec of specs) {
            const text = readFileSync(join(folder, spec), "utf8");
            expect(text, spec).toMatch(/from "\.\/(launch|fixture)"/);
        }
    });

    it("checks the installed product's folder after every spec that uses the fixture", () => {
        // `useApp()` launches the spec's app and checks its window and the
        // folder after its last test; `guardInstalledFolder()` checks the
        // folder alone. A spec that imports the fixture and calls neither, or
        // calls one twice, would lose or muddle those checks unnoticed.
        const folder = join(__dirname, "e2e");
        const specs = readdirSync(folder).filter((file) => file.endsWith(".spec.ts"));
        const users = specs.filter((spec) =>
            readFileSync(join(folder, spec), "utf8").includes('from "./fixture"'),
        );
        expect(users.length).toBeGreaterThan(1);
        for (const spec of users) {
            const text = readFileSync(join(folder, spec), "utf8");
            const calls = text.match(/^(useApp|guardInstalledFolder)\(\);$/gm) ?? [];
            expect(calls, `${spec} calls useApp() or guardInstalledFolder() once`).toHaveLength(1);
        }
    });
});
