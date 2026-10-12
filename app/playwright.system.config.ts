import { defineConfig } from "@playwright/test";

// Drives the real app (`pnpm build`) against the real command-line client
// and a real dev-mode service. See `tests/system/real.spec.ts`.
export default defineConfig({
    testDir: "tests/system",
    outputDir: "test-results/system",
    workers: 1,
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    // Never retried: a second try would hide a first meeting that went wrong.
    retries: 0,
    timeout: 180_000,
    reporter: process.env.CI ? [["github"], ["list"]] : "list",
    use: { trace: "retain-on-failure" },
});
