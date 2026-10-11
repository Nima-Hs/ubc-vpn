import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

// Unit tests run in plain Node: no Electron and no browser. The end-to-end
// test in `tests/e2e` is Playwright's, and is not picked up here.
export default defineConfig({
    resolve: { alias: { "@shared": resolve(__dirname, "src/shared") } },
    test: {
        include: ["tests/*.test.ts"],
        environment: "node",
        restoreMocks: true,
    },
});
