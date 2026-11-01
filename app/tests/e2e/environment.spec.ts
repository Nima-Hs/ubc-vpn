// What the app's environment can and cannot change: a dev server address,
// and development mode. Each test launches an app of its own.

import { join } from "node:path";
import { expect, test } from "@playwright/test";
import {
    guardInstalledFolder,
    launchArgs,
    launchEnv,
    launchOptions,
    newProfile,
    screenshotDir,
} from "./fixture";
import { launchApp } from "./launch";

guardInstalledFolder();

test("a built app ignores a dev server address in its environment", async () => {
    const other = await launchApp({
        ...launchOptions,
        args: launchArgs(),
        env: {
            ...launchEnv,
            UBC_VPN_PROFILE: newProfile(),
            ELECTRON_RENDERER_URL: "https://example.com/",
        },
    });
    try {
        const window = await other.firstWindow();
        await window.waitForLoadState("domcontentloaded");
        expect(window.url()).toBe("app://ui/index.html");
        await expect(window.getByRole("heading", { level: 1 })).toHaveText("Not connected");
    } finally {
        await other.close();
    }
});

test("says on every screen that it is in development mode, when it is", async () => {
    const other = await launchApp({
        ...launchOptions,
        args: launchArgs(),
        env: { ...launchEnv, UBC_VPN_PROFILE: newProfile(), UBC_VPN_DEV: "1" },
    });
    try {
        const window = await other.firstWindow();
        await window.waitForLoadState("domcontentloaded");
        await window.evaluate(() => document.fonts.ready);
        const mark = window.getByText("Development mode. This is not the real VPN.");
        await expect(mark).toBeInViewport({ ratio: 1 });
        // Directly under the title bar, above the row of screens.
        const order = await window.evaluate(() => {
            const top = (selector: string) =>
                document.querySelector(selector)?.getBoundingClientRect().top ?? -1;
            const strip = [...document.querySelectorAll("p")].find((p) =>
                p.textContent?.startsWith("Development mode"),
            );
            return {
                header: top("header"),
                strip: strip?.getBoundingClientRect().top ?? -1,
                row: top('nav[aria-label="Screens"]'),
            };
        });
        expect(order.header).toBeLessThan(order.strip);
        expect(order.strip).toBeLessThan(order.row);
        await window.screenshot({ path: join(screenshotDir, "development-mode.png") });
        await window
            .getByRole("navigation", { name: "Screens" })
            .getByRole("button", { name: "Routes", exact: true })
            .click();
        await expect(window.getByRole("heading", { level: 1 })).toHaveText("Routes");
        await expect(mark).toBeInViewport({ ratio: 1 });
        await window.screenshot({ path: join(screenshotDir, "development-mode-routes.png") });
    } finally {
        await other.close();
    }
});
