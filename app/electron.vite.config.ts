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
