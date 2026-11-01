// Profiles, in Settings, on the main screen and beside the password question.

import { expect, test } from "@playwright/test";
import { heading, page, scenario, shoot, tab, useApp } from "./fixture";

useApp();

/** The row of one profile in Settings. */
const profileRow = (name: string) =>
    page.getByRole("listitem").filter({ has: page.getByText(name, { exact: true }) });

test("profiles: added, renamed, used and deleted, with the last one kept", async () => {
    await scenario("settings");
    await tab("Settings").click();
    await expect(page.getByRole("heading", { name: "Profiles" })).toBeVisible();
    // One profile, in use, which cannot be deleted.
    await expect(profileRow("UBC VPN")).toContainText("In use");
    await page.getByRole("button", { name: "Edit UBC VPN" }).click();
    const deleteButton = page.getByRole("button", { name: "Delete profile" });
    await expect(deleteButton).toHaveAttribute("aria-disabled", "true");
    await expect(deleteButton).toHaveAccessibleDescription("The only profile can't be deleted.");
    await page.getByRole("button", { name: "Done" }).click();

    // Added: a name is needed, and it must differ, ignoring case.
    const newName = page.getByLabel("New profile's name");
    const add = page.getByRole("button", { name: "Add profile" });
    await newName.fill("ubc vpn");
    await add.click();
    await expect(page.getByText("Another profile has that name.")).toBeVisible();
    await expect(newName).toHaveAttribute("aria-invalid", "true");
    await newName.fill("Lab");
    await add.click();
    await expect(profileRow("Lab")).toBeVisible();
    await expect(newName).toHaveValue("");
    await expect(profileRow("Lab")).toContainText("No username yet");
    await shoot("profiles-two");

    // Renamed, and given a username.
    await page.getByRole("button", { name: "Edit Lab" }).click();
    const name = page.getByLabel("Name", { exact: true });
    await name.fill("Lab 2");
    await page.getByRole("button", { name: "Rename" }).click();
    await expect(profileRow("Lab 2")).toBeVisible();
    await page.getByLabel("CWL username").fill("someone.lab@app");
    await page.getByRole("button", { name: "Save username" }).click();
    await expect(profileRow("Lab 2")).toContainText("someone.lab@app");
    await shoot("profiles-editing");
    await page.getByRole("button", { name: "Done" }).click();

    // Used: it is the one in use now.
    await page.getByRole("button", { name: "Use Lab 2" }).click();
    await expect(profileRow("Lab 2")).toContainText("In use");
    await expect(profileRow("UBC VPN")).not.toContainText("In use");

    // Deleted, only once the user says so.
    await page.getByRole("button", { name: "Edit Lab 2" }).click();
    // From the keyboard, Enter twice: the question takes the keyboard on
    // "Keep it", so the second Enter keeps the profile.
    await page.getByRole("button", { name: "Delete profile" }).focus();
    await page.keyboard.press("Enter");
    const question = page.getByRole("alertdialog", { name: /Delete “Lab 2”\?/ });
    await expect(question).toBeVisible();
    await expect(question.getByRole("button", { name: "Keep it" })).toBeFocused();
    await shoot("profiles-delete-ask");
    await page.keyboard.press("Enter");
    await expect(question).toHaveCount(0);
    await expect(profileRow("Lab 2")).toBeVisible();
    // Escape keeps it too.
    await page.getByRole("button", { name: "Delete profile" }).click();
    await page.keyboard.press("Escape");
    await expect(question).toHaveCount(0);
    await expect(profileRow("Lab 2")).toBeVisible();
    // Deleted deliberately.
    await page.getByRole("button", { name: "Delete profile" }).click();
    await question.getByRole("button", { name: "Delete profile" }).click();
    await expect(profileRow("Lab 2")).toHaveCount(0);
    // The one left is in use.
    await expect(profileRow("UBC VPN")).toContainText("In use");
    await scenario("settings");
    await tab("Connection").click();
});

test("profiles: chosen from the main screen, for the next connect while connected", async () => {
    await scenario("settings-profiles");
    await scenario("disconnected");
    await tab("Settings").click();
    await tab("Connection").click();
    const switcher = page.getByLabel("Profile", { exact: true });
    await expect(switcher).toHaveValue(
        (await switcher.locator("option", { hasText: "UBC VPN" }).getAttribute("value")) ?? "",
    );
    await switcher.selectOption({ label: "Lab" });
    await expect(switcher.locator("option:checked")).toHaveText("Lab");
    // Not connected: nothing more to say.
    await expect(page.getByText("Takes effect the next time you connect.")).toHaveCount(0);
    await shoot("profiles-switcher");
    // Connected: a choice now applies to the next connect, and it says so.
    await scenario("connected");
    await expect(heading()).toHaveText("Connected");
    await expect(switcher).toHaveAccessibleDescription("Takes effect the next time you connect.");
    await shoot("profiles-switcher-connected");
    // Settings shows the same choice: one source for both.
    await tab("Settings").click();
    await expect(profileRow("Lab")).toContainText("In use");
    await scenario("settings");
    await scenario("disconnected");
    await tab("Connection").click();
    // With one profile there is nothing to choose.
    await expect(page.getByLabel("Profile", { exact: true })).toHaveCount(0);
});

test("profiles: saving stays off when an old saved password could not be removed", async () => {
    const stuck = "UBC VPN couldn't remove the old saved password, so saving stays off.";
    // In Settings, under the switch.
    await scenario("settings-old-password-stuck");
    await tab("Settings").click();
    await page.getByRole("button", { name: "Edit UBC VPN" }).click();
    const save = page.getByRole("switch", { name: "Save password" });
    await expect(save).toHaveAttribute("aria-checked", "false");
    await save.click();
    await expect(save).toHaveAccessibleDescription(stuck);
    await expect(save).toHaveAttribute("aria-checked", "false");
    await shoot("profiles-password-stuck");
    await page.getByRole("button", { name: "Done" }).click();
    // Beside the password question too.
    await tab("Connection").click();
    await scenario("login-password");
    const box = page.getByRole("checkbox", { name: "Save password" });
    await expect(box).not.toBeChecked();
    await box.click();
    await expect(box).toHaveAccessibleDescription(stuck);
    await expect(box).not.toBeChecked();
    await scenario("settings");
    await scenario("disconnected");
});

test("profiles: the password question offers to save it, and says why when it can't", async () => {
    await scenario("settings");
    await scenario("login-password");
    const save = page.getByRole("checkbox", { name: "Save password" });
    await expect(save).toBeChecked();
    await expect(save).toHaveAccessibleDescription(/once this login works/);
    await shoot("login-save-password");
    // Turned off: the profile stops saving it.
    await save.click();
    await expect(save).not.toBeChecked();
    await scenario("settings-no-keyring");
    await scenario("login-password");
    const disabled = page.getByRole("checkbox", { name: "Save password" });
    await expect(disabled).toBeDisabled();
    await expect(disabled).not.toBeChecked();
    await expect(disabled).toHaveAccessibleDescription(/no keyring UBC VPN can use/);
    await scenario("settings");
    await scenario("disconnected");
});
