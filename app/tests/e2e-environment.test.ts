// Off CI, the apps the end-to-end tests launch must not inherit anything
// that could lead them to a real client, the real service, the user's
// settings or their saved password. See tests/e2e/safe-env.ts.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { launchEnvironment, leadsToRealClient } from "./e2e/safe-env";

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

    it("does not change the environment it is given", () => {
        const env = { ...OWNER_SHELL };
        launchEnvironment(env);
        expect(env).toEqual(OWNER_SHELL);
    });

    it("is how every end-to-end test builds an app's environment", () => {
        const folder = join(__dirname, "e2e");
        const specs = readdirSync(folder).filter((file) => file.endsWith(".spec.ts"));
        expect(specs.length).toBeGreaterThan(1);
        for (const spec of specs) {
            const text = readFileSync(join(folder, spec), "utf8");
            // The test runner's own environment is never handed on whole.
            expect(text, spec).not.toMatch(/\.\.\.process\.env\b/);
            expect(text, spec).not.toMatch(/env:\s*process\.env\b/);
            if (/electron\.launch|spawn\(/.test(text)) {
                expect(text, spec).toMatch(/launchEnvironment\(process\.env\)/);
            }
        }
    });
});
