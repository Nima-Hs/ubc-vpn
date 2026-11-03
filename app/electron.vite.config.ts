import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "electron-vite";

const shared = resolve(__dirname, "src/shared");

// `--mode demo` turns on the in-memory fake service. In every other mode
// `__DEMO__` is the literal `false`, so the bundler drops the demo code and
// `scripts/check-production-build.mjs` confirms none of it was emitted.
export default defineConfig(({ mode }) => {
    const define = {
        __DEMO__: JSON.stringify(mode === "demo"),
        // The log screen and everything that carries lines to it. Its contract
        // (protocol version 3) is not on main yet, so for now only the demo
        // build has it, against a fake. Everywhere else this is the literal
        // `false`, the bundler drops the code, and the same check confirms it.
        // Turning it on for production is one change, here, once the real
        // service can be asked.
        __LOGS__: JSON.stringify(mode === "demo"),
        // The Settings screen: how the app starts, the saved password, and
        // later the profiles. On in every build since the client's commands
        // for it arrived (#208); the demo build has a fake of its own.
        __SETTINGS__: JSON.stringify(true),
        // Only the build an installer is made from (`pnpm package:win`, with
        // `--mode release`). The updater needs it as well as an installed
        // app: `ELECTRON_FORCE_IS_PACKAGED` makes any run look installed, so
        // that alone must never let a test or development run reach GitHub
        // or the updates folder.
        __RELEASE__: JSON.stringify(mode === "release"),
    };
    return {
        main: {
            define,
            resolve: { alias: { "@shared": shared } },
        },
        preload: {
            define,
            resolve: { alias: { "@shared": shared } },
        },
        renderer: {
            define,
            resolve: {
                alias: {
                    "@shared": shared,
                    "@": resolve(__dirname, "src/renderer/src"),
                },
            },
            plugins: [react(), tailwindcss()],
            build: { minify: true },
        },
    };
});
