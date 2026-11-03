import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

// The test of the installed client in a real desktop session. Only
// packaging/linux/tests/keyring-session.sh runs it: a run that was not started
// by that script stops here, so that a run with nothing to test is never
// taken for one that passed.
if (process.env.UBC_VPN_TEST_THROWAWAY_MACHINE !== "1") {
    throw new Error("only for a throwaway CI runner: see packaging/linux/tests/keyring-session.sh");
}

export default defineConfig({
    resolve: { alias: { "@shared": resolve(__dirname, "src/shared") } },
    test: {
        include: ["tests/session/*.test.ts"],
        environment: "node",
        // One after another: they share one session and one home folder.
        fileParallelism: false,
        testTimeout: 120_000,
    },
});
