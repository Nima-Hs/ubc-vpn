// The app each end-to-end spec drives, and what every spec shares. A spec
// calls `useApp()` once, at its top: the real app, built in demo mode, is
// launched before the spec's first test and closed after its last, and the
// spec's tests then use `app`, `page` and the helpers below.
//
// Each spec gets an app of its own, as the single spec this came from did:
// its tests run in order on one app, and start from the state a fresh app
// is in, whatever spec ran before. Playwright has no fixture scoped to a
// file (a worker fixture would carry one app, and its state, from one spec
// into the next), so this is done with the spec's own hooks.
//
// After a spec's last test, two things are checked for it: nothing was
// blocked or broken in its window, and nothing was written in the installed
// product's folder. A spec that only launches apps of its own calls
// `guardInstalledFolder()` instead, for the second.
//
// Screenshots of every state go to `SCREENSHOT_DIR`, or
// `test-results/screens` when it is not set.

import { existsSync, mkdirSync, mkdtempSync, readdirSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { type ElectronApplication, expect, type Page, test } from "@playwright/test";
import { launchApp } from "./launch";
import { isCi } from "./safe-env";

/**
 * Off the screen unless this is CI: a test run on someone's computer must
 * not open windows over their work. See `keepHidden` in `src/main/window.ts`.
 */
const HIDDEN = isCi(process.env) ? {} : { UBC_VPN_TEST_HIDDEN: "1" };
/** Whether this run keeps the window off the screen, so showing and hiding it cannot be watched. */
export const offScreen = Object.keys(HIDDEN).length > 0;

export const screenshotDir = resolve(process.env.SCREENSHOT_DIR ?? "test-results/screens");

export const launchArgs = () => [
    resolve("out-demo/main/index.js"),
    // A window hidden behind others has its animations paused, and a
    // test machine's windows usually are. Keep them running.
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
];
/** A profile of its own for each launch, so it never collides with a running copy. */
export const newProfile = () => mkdtempSync(join(tmpdir(), "ubc-vpn-e2e-"));

// Where Electron would keep the profile if the app did not move it. On
// Windows and macOS that is the folder the installed command-line client
// keeps the user's settings in. Nothing here may write to it.
const installedFolder = join(
    process.platform === "win32"
        ? (process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"))
        : process.platform === "darwin"
          ? join(homedir(), "Library", "Application Support")
          : (process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config")),
    "UBC VPN",
);
/** What is in a folder: each entry's name, size and time of last change. */
const contentsOf = (folder: string): string[] =>
    existsSync(folder)
        ? readdirSync(folder)
              .sort()
              .map((name) => {
                  const entry = statSync(join(folder, name));
                  return `${name} ${entry.size} ${entry.mtimeMs}`;
              })
        : ["(no such folder)"];

export const launchEnv = {
    ...HIDDEN,
    UBC_VPN_DEMO_STEP_MS: "600",
    // Whatever desktop the test machine runs, behave as on one with a tray.
    XDG_CURRENT_DESKTOP: "e2e",
};

// On Linux the test driver turns Chromium's sandbox off unless told not to.
// The app ships with it on, so it is tested with it on.
export const launchOptions = { chromiumSandbox: true };

/** The spec's app, from its first test to its last. */
export let app: ElectronApplication;
/** The spec's app's window. */
export let page: Page;
/** The profile folder the spec's app was given. */
export let mainProfile: string;
/** A blocked script, style or request in the spec's window, or any error. */
const problems: string[] = [];

/**
 * Checks, after the spec's last test, that nothing was written in the
 * installed product's folder while it ran, by any app it launched.
 */
export function guardInstalledFolder(): void {
    let before: string[] = [];
    test.beforeAll(() => {
        before = contentsOf(installedFolder);
    });
    test.afterAll(() => {
        expect(
            contentsOf(installedFolder),
            "nothing was written in the installed product's folder",
        ).toEqual(before);
    });
}

/**
 * Launches the spec's app before its first test and closes it after its
 * last, then checks that nothing was blocked or broken in its window and
 * that nothing was written in the installed product's folder.
 */
export function useApp(): void {
    let before: string[] = [];
    test.beforeAll(async () => {
        before = contentsOf(installedFolder);
        problems.length = 0;
        mkdirSync(screenshotDir, { recursive: true });
        mainProfile = newProfile();
        app = await launchApp({
            ...launchOptions,
            args: launchArgs(),
            env: { ...launchEnv, UBC_VPN_PROFILE: mainProfile },
        });
        page = await app.firstWindow();
        // The real mouse pointer hovers whatever is under it. Put the window
        // somewhere the pointer is not, so no screenshot shows a stray hover.
        await app.evaluate(({ BrowserWindow, screen }) => {
            const window = BrowserWindow.getAllWindows()[0];
            if (window === undefined) {
                return;
            }
            const pointer = screen.getCursorScreenPoint();
            const area = screen.getDisplayNearestPoint(pointer).workArea;
            const [width = 0] = window.getSize();
            const leftHalf = pointer.x < area.x + area.width / 2;
            window.setPosition(
                leftHalf ? area.x + area.width - width - 40 : area.x + 40,
                area.y + 40,
            );
        });
        // A blocked script, style or request shows up here, as does any error.
        page.on("console", (message) => {
            if (message.type() === "error" || message.type() === "warning") {
                problems.push(message.text());
            }
        });
        page.on("pageerror", (error) => problems.push(error.message));
        await page.waitForLoadState("domcontentloaded");
        await page.evaluate(() => document.fonts.ready);
    });
    test.afterAll(async () => {
        const seen = [...problems];
        // Closing twice is harmless, and a failed launch leaves nothing to close.
        await app?.close().catch(() => {});
        // Both are checked, and both reported, whichever fails.
        expect({
            "nothing was blocked or broken along the way": seen,
            "nothing was written in the installed product's folder": contentsOf(installedFolder),
        }).toEqual({
            "nothing was blocked or broken along the way": [],
            "nothing was written in the installed product's folder": before,
        });
    });
}

export async function shoot(name: string): Promise<void> {
    // Let transitions finish, so the picture is of the state and not of the way into it.
    await page.waitForTimeout(700);
    await page.screenshot({ path: join(screenshotDir, `${name}.png`) });
}

export async function scenario(name: string): Promise<void> {
    await page.evaluate((scenarioName) => window.ubcVpn.demo?.setScenario(scenarioName), name);
}

export const heading = () => page.getByRole("heading", { level: 1 });
/** Text shown on the screen, leaving out the copy kept for screen readers. */
export const said = (text: string) =>
    page.locator('main p:not([role="status"])', { hasText: text });

/** A screen's button in the switcher under the title bar. */
export const tab = (name: string) =>
    page.getByRole("navigation", { name: "Screens" }).getByRole("button", { name, exact: true });
/** The one button on the connection screen. */
export const action = () => page.locator("main > button");
