import { defineConfig } from "@playwright/test";

// Drives the real Electron app, built in demo mode (`pnpm build:demo`).
export default defineConfig({
    testDir: "tests/e2e",
    outputDir: "test-results",
    // One Electron app at a time.
    workers: 1,
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    // A test that passes only on its retry fails the run. Each spec's
    // checks after its last test (tests/e2e/fixture.ts) fail that test, and
    // its retry starts a fresh app that would pass them.
    failOnFlakyTests: !!process.env.CI,
    timeout: 60_000,
    reporter: process.env.CI ? [["github"], ["list"]] : "list",
    use: { trace: "retain-on-failure" },
});
