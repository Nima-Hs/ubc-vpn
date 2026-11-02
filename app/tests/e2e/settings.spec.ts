// The Settings screen: starting at sign-in, connecting by itself, and the
// saved password.

import { expect, test } from "@playwright/test";
import { app, heading, page, scenario, shoot, tab, useApp } from "./fixture";
import { isCi } from "./safe-env";

useApp();

/** What the app would have asked the OS to start at sign-in. A demo build never asks. */
const loginItem = () => page.evaluate(() => window.ubcVpn.demo?.loginItem() ?? null);

test("settings: nothing starts at sign-in and nothing connects by itself, until asked", async () => {
    await scenario("settings");
    await tab("Settings").click();
    await expect(heading()).toHaveText("Settings");
    const startup = page.getByRole("group", { name: "Start UBC VPN when you sign in" });
    await expect(startup.getByRole("radio", { name: "Don't start it" })).toBeChecked();
    const autoConnect = page.getByRole("switch", { name: "Connect when UBC VPN starts" });
    await expect(autoConnect).toHaveAttribute("aria-checked", "false");
    // It says what turning it on costs.
    await expect(autoConnect).toHaveAccessibleDescription(/one MFA request/);
    // Nothing has been asked of the OS yet.
    expect(await loginItem()).toBeNull();
    await shoot("settings");
    await tab("Connection").click();
});

test("settings: starting in the tray registers the app with --hidden", async () => {
    test.skip(process.platform === "linux", "Linux has no start at sign-in yet");
    await scenario("settings");
    await tab("Settings").click();
    const startup = page.getByRole("group", { name: "Start UBC VPN when you sign in" });
    const tray = startup.getByRole("radio", { name: "Start it in the tray" });
    // Clicked, not checked: the screen shows the choice once it is saved,
    // the client's answer, not the click.
    await tray.click();
    await expect(tray).toBeChecked();
    const expected =
        process.platform === "darwin"
            ? { openAtLogin: true, args: [] }
            : { openAtLogin: true, args: ["--hidden"] };
    await expect.poll(loginItem).toEqual(expected);
    await shoot("settings-start-in-tray");

    const window = startup.getByRole("radio", { name: "Start it and open the window" });
    await window.click();
    await expect(window).toBeChecked();
    await expect.poll(loginItem).toEqual({ openAtLogin: true, args: [] });
    const off = startup.getByRole("radio", { name: "Don't start it" });
    await off.click();
    await expect(off).toBeChecked();
    await expect.poll(loginItem).toEqual({ openAtLogin: false, args: [] });

    // Connecting by itself is saved with the startup choice, and changes nothing at sign-in.
    const autoConnect = page.getByRole("switch", { name: "Connect when UBC VPN starts" });
    await autoConnect.click();
    await expect(autoConnect).toHaveAttribute("aria-checked", "true");
    await expect.poll(loginItem).toEqual({ openAtLogin: false, args: [] });
    await autoConnect.click();
    await expect(autoConnect).toHaveAttribute("aria-checked", "false");
    await tab("Connection").click();
});

test("settings: on Windows the tray choice becomes a Run entry with --hidden", async () => {
    // It writes the user's Run key, so only on a CI machine, which is thrown
    // away: never on someone's own computer.
    test.skip(
        !isCi(process.env) || process.platform !== "win32",
        "writes the Run key: Windows CI runners only",
    );
    // The login item the app registers for "Start it in the tray"
    // (`loginItemFor("tray", "win32")`, pinned in tests/startup.test.ts),
    // given to Electron as an installed app gives it, then read back from
    // the registry through Electron, and removed again.
    const seen = await app.evaluate(({ app: electronApp }) => {
        const item = { openAtLogin: true, args: ["--hidden"] };
        electronApp.setLoginItemSettings(item);
        // Electron compares the whole command line in the Run entry with the
        // one asked about, so this says whether `--hidden` was written.
        const withHidden = electronApp.getLoginItemSettings({ args: item.args });
        const withoutArgs = electronApp.getLoginItemSettings({ args: [] });
        electronApp.setLoginItemSettings({ openAtLogin: false, args: item.args });
        const removed = electronApp.getLoginItemSettings({ args: item.args });
        return {
            program: process.execPath,
            withHidden: withHidden.openAtLogin,
            withoutArgs: withoutArgs.openAtLogin,
            // Electron lists the entry's program, but not its arguments.
            entries: withHidden.launchItems.map(({ path, scope, enabled }) => ({
                path,
                scope,
                enabled,
            })),
            removed: removed.openAtLogin,
        };
    });
    // The Run entry starts this program, for this user, with `--hidden`.
    expect(seen.withHidden).toBe(true);
    expect(seen.withoutArgs).toBe(false);
    expect(seen.entries).toContainEqual({ path: seen.program, scope: "user", enabled: true });
    // And it is gone again once turned off.
    expect(seen.removed).toBe(false);
});

test("settings: the saved password is forgotten only once the user says so", async () => {
    await scenario("settings");
    await tab("Settings").click();
    await expect(page.getByText(/Your password is saved in/)).toBeVisible();
    const forget = page.getByRole("button", { name: "Forget saved password" });
    const question = page.getByRole("alertdialog", { name: "Forget your saved password?" });

    // From the keyboard, Enter twice: the second lands on "Keep it", so the
    // password stays. The question is named by itself and takes the keyboard,
    // on its safe answer.
    await forget.focus();
    await page.keyboard.press("Enter");
    await expect(question).toBeVisible();
    await expect(question.getByRole("button", { name: "Keep it" })).toBeFocused();
    await shoot("settings-forget-ask");
    await page.keyboard.press("Enter");
    await expect(question).toHaveCount(0);
    await expect(page.getByText(/Your password is saved in/)).toBeVisible();

    // The keyboard stays where the user puts it: the question takes it once.
    await forget.click();
    await page.keyboard.press("Shift+Tab");
    const confirm = question.getByRole("button", { name: "Forget password" });
    await expect(confirm).toBeFocused();
    await page.waitForTimeout(300);
    await expect(confirm).toBeFocused();
    // Escape keeps it too.
    await page.keyboard.press("Escape");
    await expect(question).toHaveCount(0);
    await expect(page.getByText(/Your password is saved in/)).toBeVisible();

    // Asked again, and confirmed deliberately.
    await forget.click();
    await question.getByRole("button", { name: "Forget password" }).click();
    await expect(page.getByText("No password is saved.", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: "Forget saved password" })).toHaveCount(0);
    await tab("Connection").click();
});

test("settings: without a keyring, saving a password is not offered, and says why", async () => {
    await scenario("settings-no-keyring");
    await tab("Settings").click();
    await expect(page.getByText(/no keyring UBC VPN can use/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Forget saved password" })).toHaveCount(0);
    await scenario("settings-cannot-save");
    await tab("Connection").click();
    await tab("Settings").click();
    const autoConnect = page.getByRole("switch", { name: "Connect when UBC VPN starts" });
    await autoConnect.click();
    // Refused: said plainly, and what is shown is still what is saved.
    await expect(page.getByRole("alert")).toContainText("could not be saved");
    await expect(autoConnect).toHaveAttribute("aria-checked", "false");
    await shoot("settings-cannot-save");
    await scenario("settings");
    await tab("Connection").click();
});
