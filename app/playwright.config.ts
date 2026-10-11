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
    timeout: 60_000,
    reporter: process.env.CI ? [["github"], ["list"]] : "list",
    use: { trace: "retain-on-failure" },
});
