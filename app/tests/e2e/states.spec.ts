// Pictures: every state the demo can show, the icons drawn outside the
// window, and the component gallery, in the order the old spec ran them.

import { existsSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { app, heading, page, scenario, screenshotDir, shoot, tab, useApp } from "./fixture";
import { photographIcons } from "./icon-sheets";

useApp();

test("every state, photographed", async () => {
    // About a second a state, and there are more of them than fit the usual
    // minute on the slowest runner.
    test.setTimeout(120_000);
    const scenarios = (await page.evaluate(() => window.ubcVpn.demo?.listScenarios())) ?? [];
    expect(scenarios.length).toBeGreaterThan(20);
    for (const name of scenarios) {
        await scenario(name);
        // A routes state is seen on the Routes screen, opened afresh so it reads the state.
        await tab("Connection").click();
        if (name.startsWith("logs")) {
            await tab("Logs").click();
            await expect(heading()).toHaveText("Logs");
            await expect(page.getByText("Reading the log…")).toHaveCount(0);
        }
        if (name.startsWith("routes")) {
            await tab("Routes").click();
            await expect(heading()).toHaveText("Routes");
            if (name !== "routes-loading") {
                await expect(page.getByText("Reading your settings…")).toHaveCount(0);
            }
        }
        if (name.startsWith("settings")) {
            await tab("Settings").click();
            await expect(heading()).toHaveText("Settings");
            if (name !== "settings-loading") {
                await expect(page.getByText("Reading your settings…")).toHaveCount(0);
            }
        }
        await expect(heading()).toBeVisible();
        // Nothing may spill out of the window, whatever the service sends.
        const overflow = await page.evaluate(
            () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
        );
        expect(overflow, `${name} overflows sideways`).toBe(false);
        // A list too long for the window can be scrolled from the keyboard.
        const stuck = await page.evaluate(() =>
            [...document.querySelectorAll<HTMLElement>(".scroll-region")]
                .filter((region) => region.scrollHeight > region.clientHeight)
                .some((region) => {
                    // Either the region takes the keyboard itself, or something
                    // inside it does and scrolls it into view.
                    region.focus();
                    return (
                        document.activeElement !== region &&
                        region.querySelector("input, button") === null
                    );
                }),
        );
        expect(stuck, `${name} has a region the keyboard cannot scroll`).toBe(false);
        await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
        await shoot(`state-${name}`);
    }
});

test("the icons the app draws outside its window, photographed", () => {
    // The tray and the taskbar are the OS's, so they cannot be photographed
    // from here: the same drawings are, on a dark and a light taskbar.
    for (const file of photographIcons(screenshotDir)) {
        expect(existsSync(join(screenshotDir, file))).toBe(true);
    }
});

test("the taskbar button's state icons are files Electron can read", async () => {
    test.skip(process.platform !== "win32", "the taskbar follows the state on Windows only");
    // The files the window takes its icon from on Windows, one per state and
    // working frame. An unreadable one would leave the button blank.
    const folder = resolve("build/state-icons");
    const files = readdirSync(folder).sort();
    expect(files).toEqual([
        "attention.ico",
        "busy-0.ico",
        "busy-1.ico",
        "busy-2.ico",
        "busy-full-0.ico",
        "busy-full-1.ico",
        "busy-full-2.ico",
        "off.ico",
        "on-full.ico",
        "on.ico",
        "problem.ico",
    ]);
    const empty = await app.evaluate(
        ({ nativeImage }, paths) =>
            paths.filter((path) => nativeImage.createFromPath(path).isEmpty()),
        files.map((file) => join(folder, file)),
    );
    expect(empty).toEqual([]);
});

test("the component gallery", async () => {
    await page.getByRole("button", { name: "Parts" }).click();
    await expect(page.getByRole("heading", { name: "Buttons" })).toBeVisible();
    await shoot("components-1");
    for (const [index, section] of ["Status", "Panels and rows"].entries()) {
        await page.getByRole("heading", { name: section }).scrollIntoViewIfNeeded();
        await shoot(`components-${index + 2}`);
    }
    const settings = page.getByRole("button", { name: "Open settings" });
    await settings.hover();
    await expect(page.getByRole("tooltip")).toHaveText("Open settings");
    // The tooltip repeats the button's name, so it must not also be its
    // description: a screen reader would read the same words twice.
    await expect(settings).not.toHaveAttribute("aria-describedby");
    await shoot("components-tooltip");
    await page.getByRole("button", { name: "Delete route" }).last().hover();
    await shoot("components-hover");
    await page.getByRole("button", { name: "Connection" }).click();
});
