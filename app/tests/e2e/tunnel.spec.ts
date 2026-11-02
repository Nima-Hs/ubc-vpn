// Split and full tunnel.

import { expect, test } from "@playwright/test";
import { action, heading, page, said, scenario, shoot, tab, useApp } from "./fixture";

useApp();

/** The main screen's split or full choice. */
const tunnelGroup = () => page.getByRole("radiogroup", { name: "Tunnel" });
const tunnelRadio = (name: "Split tunnel" | "Full tunnel") =>
    tunnelGroup().getByRole("radio", { name });
const diagramMode = () => page.locator("svg[data-mode]").getAttribute("data-mode");
/** Chooses a mode as a pointer does: on its visible label. The radio itself is hidden. */
const chooseTunnel = (name: "Split tunnel" | "Full tunnel") =>
    tunnelGroup().locator("label", { hasText: name }).click();

/** Puts the tunnel setting back as it starts: split, with full allowed. */
async function resetTunnel(): Promise<void> {
    await scenario("settings");
    await scenario("disconnected");
    await tab("Connection").click();
    await expect(tunnelRadio("Split tunnel")).toBeChecked();
}

test("tunnel: switched while connected, without disconnecting, and back", async () => {
    await scenario("connected");
    await tab("Connection").click();
    await expect(heading()).toHaveText("Connected");
    await expect(tunnelRadio("Split tunnel")).toBeChecked();
    // Said before anyone switches.
    await expect(tunnelGroup()).toHaveAccessibleDescription(
        "You stay connected. Connections outside UBC may reset.",
    );
    await expect(said("Split tunnel: traffic to 2 UBC subnets")).toBeVisible();
    expect(await diagramMode()).toBe("split");
    await shoot("tunnel-split-connected");

    const states: string[] = [];
    await page.exposeFunction("recordHeading", (text: string) => states.push(text));
    await page.evaluate(() => {
        const record = () =>
            (window as unknown as { recordHeading(text: string): void }).recordHeading(
                document.querySelector("h1")?.textContent ?? "",
            );
        new MutationObserver(record).observe(document.body, {
            subtree: true,
            childList: true,
            characterData: true,
        });
    });
    await chooseTunnel("Full tunnel");
    await expect(heading()).toHaveText("Connected");
    await expect(said("Full tunnel: all your traffic goes through UBC")).toBeVisible();
    await expect(tunnelRadio("Full tunnel")).toBeChecked();
    expect(await diagramMode()).toBe("full");
    // It went through "Switching", and never through disconnecting.
    expect(states).toContain("Switching");
    expect(states.some((text) => /Disconnect|Not connected|Connecting/.test(text))).toBe(false);
    await expect(page.getByRole("button", { name: "Disconnect" })).toBeEnabled();
    // The details say so too: everything goes through, the lists are the user's own.
    const details = page.getByRole("group", { name: "Connection details" });
    await expect(details).toContainText("All your traffic");
    await expect(details).toContainText("Your saved subnets");
    await expect(details).not.toContainText("Subnets through the VPN");
    await shoot("tunnel-full-connected");

    // The keyboard switches it too.
    await tunnelRadio("Full tunnel").focus();
    await page.keyboard.press("ArrowLeft");
    await expect(said("Split tunnel: traffic to 2 UBC subnets")).toBeVisible();
    expect(await diagramMode()).toBe("split");
    await resetTunnel();
});

test("tunnel: a switch under way shows switching, and nothing can be changed meanwhile", async () => {
    await scenario("tunnel-switch-held");
    // Started from Settings with the keyboard: the radio it moved to keeps
    // focus, stays reachable, and the reason it is locked is its description.
    await tab("Settings").click();
    const settingsSplit = page.getByRole("radio", { name: /^Split tunnel/ });
    const settingsFull = page.getByRole("radio", { name: /^Full tunnel/ });
    await settingsSplit.focus();
    await page.keyboard.press("ArrowDown");
    await expect(settingsFull).toBeChecked();
    await expect(settingsFull).toBeFocused();
    expect(await settingsFull.evaluate((radio) => (radio as HTMLInputElement).disabled)).toBe(
        false,
    );
    await expect(settingsFull).toHaveAttribute("aria-disabled", "true");
    await expect(settingsSplit).toBeDisabled();
    await expect(page.getByRole("group", { name: "Tunnel" })).toHaveAccessibleDescription(
        "You stay connected. Connections outside UBC may reset.",
    );
    // Pressing on does nothing while it is locked.
    await page.keyboard.press("ArrowUp");
    await expect(settingsFull).toBeChecked();
    await tab("Connection").click();
    await expect(heading()).toHaveText("Switching");
    await expect(said("Moving to full tunnel. The VPN stays connected.")).toBeVisible();
    // The note under the choice stays as it was, so nothing moves.
    await expect(tunnelGroup()).toHaveAccessibleDescription(
        "You stay connected. Connections outside UBC may reset.",
    );
    await expect(tunnelRadio("Full tunnel")).toBeChecked();
    await expect(tunnelRadio("Split tunnel")).toBeDisabled();
    // One line of title, as when connected.
    const titleLines = await heading().evaluate(
        (title) =>
            title.getBoundingClientRect().height /
            Number.parseFloat(getComputedStyle(title).lineHeight),
    );
    expect(Math.round(titleLines)).toBe(1);
    // The picture shows the way being opened through UBC.
    await expect
        .poll(() =>
            page
                .locator('[data-pulse="full"]')
                .evaluate((pulse) =>
                    Number.parseFloat(getComputedStyle(pulse.parentElement ?? pulse).opacity),
                ),
        )
        .toBe(1);
    await shoot("tunnel-switching");
    // The next scenario answers the held switch, for the next connect.
    await resetTunnel();
});

test("tunnel: a refused switch keeps the old mode and says why", async () => {
    await scenario("tunnel-refused");
    await tab("Connection").click();
    await chooseTunnel("Full tunnel");
    await expect(said("Still on split tunnel")).toBeVisible();
    await expect(said("its router is not on a network this computer is on")).toBeVisible();
    await expect(tunnelRadio("Split tunnel")).toBeChecked();
    await expect(heading()).toHaveText("Connected");
    await expect(said("Split tunnel: traffic to 2 UBC subnets")).toBeVisible();
    expect(await diagramMode()).toBe("split");
    await expect(page.getByRole("status").first()).toContainText("Still on split tunnel");
    // Said right under the choice, and the main button stays in view.
    await expect(tunnelGroup()).toHaveAccessibleDescription(/^Still on split tunnel: /);
    await expect(action()).toBeInViewport({ ratio: 1 });
    await shoot("tunnel-refused");
    // Saved back as it was: Settings says split too.
    await tab("Settings").click();
    await expect(page.getByRole("radio", { name: /^Split tunnel/ })).toBeChecked();
    await resetTunnel();
});

test("tunnel: full tunnel the policy forbids cannot be chosen, and it says why", async () => {
    await scenario("tunnel-forbidden");
    await tab("Connection").click();
    await expect(tunnelRadio("Full tunnel")).toBeDisabled();
    await expect(tunnelGroup()).toHaveAccessibleDescription(
        "Full tunnel is turned off by this computer’s VPN policy.",
    );
    await shoot("tunnel-forbidden");
    await tab("Settings").click();
    await expect(page.getByRole("radio", { name: /^Full tunnel/ })).toBeDisabled();
    await expect(page.getByRole("radio", { name: /^Split tunnel/ })).toBeChecked();
    const forbiddenNote = page.getByText(
        "Full tunnel is turned off by this computer’s VPN policy.",
    );
    await forbiddenNote.scrollIntoViewIfNeeded();
    await expect(forbiddenNote).toBeInViewport();
    await expect(page.getByRole("group", { name: "Tunnel" })).toBeInViewport();
    await shoot("tunnel-forbidden-settings");
    await resetTunnel();
});

test("tunnel: in full tunnel the routes are kept and shown, but not in use", async () => {
    await scenario("tunnel-full-off");
    await tab("Connection").click();
    await expect(tunnelRadio("Full tunnel")).toBeChecked();
    expect(await diagramMode()).toBe("full");
    await shoot("tunnel-full-off");
    await tab("Routes").click();
    await expect(heading()).toHaveText("Routes");
    await expect(page.getByText("Reading your settings…")).toHaveCount(0);
    await expect(page.getByText("Not in use")).toBeVisible();
    // The opening line does not say the list is in use.
    await expect(
        said("In split tunnel, only traffic to these subnets goes through the VPN."),
    ).toBeVisible();
    await expect(said("Everything else uses your normal connection.")).toHaveCount(0);
    const first = page.getByLabel("Subnet 1", { exact: true });
    await expect(first).toBeDisabled();
    await expect(first).not.toHaveValue("");
    await expect(page.getByRole("button", { name: "Add subnet" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Save routes" })).toBeDisabled();
    await shoot("tunnel-full-routes");
    // Back to split from Settings: the list is in use again, as it was.
    await tab("Settings").click();
    await page.getByRole("radio", { name: /^Split tunnel/ }).check();
    await tab("Routes").click();
    await expect(page.getByText("Not in use")).toHaveCount(0);
    await expect(page.getByLabel("Subnet 1", { exact: true })).toBeEnabled();
    await resetTunnel();
});

test("tunnel: connecting in full tunnel shows the way through UBC", async () => {
    await scenario("tunnel-full-connecting");
    await tab("Connection").click();
    await expect(heading()).toHaveText("Connecting");
    expect(await diagramMode()).toBe("full");
    await expect(said("all your traffic will go through UBC")).toBeVisible();
    // The mode a connection uses is fixed while it is being made.
    await expect(tunnelRadio("Split tunnel")).toBeDisabled();
    await expect(tunnelGroup()).toHaveAccessibleDescription(
        "You can change the tunnel once the VPN has connected or disconnected.",
    );
    await shoot("tunnel-full-connecting");
    await scenario("tunnel-full");
    await expect(heading()).toHaveText("Connected");
    await shoot("tunnel-full-details");
    await resetTunnel();
});

test("the details' first rows are shown whole at the default size, in either mode", async () => {
    // How much of an element the scrolling details show, from 0 to 1.
    const shownOf = (label: string) =>
        page.evaluate((name) => {
            const region = document.querySelector('[aria-label="Connection details"]');
            const term = [...(region?.querySelectorAll("dt, h2") ?? [])].find(
                (element) => element.textContent === name,
            );
            // The row: a value's own line, or a group's heading line.
            const row = term?.closest("div") ?? null;
            if (region === null || row === null) {
                return -1;
            }
            const outer = region.getBoundingClientRect();
            const inner = row.getBoundingClientRect();
            const seen =
                Math.max(0, Math.min(outer.bottom, inner.bottom) - Math.max(outer.top, inner.top)) /
                inner.height;
            return Math.round(seen * 100) / 100;
        }, label);
    for (const [name, rows] of [
        ["connected", ["Your VPN address", "Subnets through the VPN"]],
        ["tunnel-full", ["Through the VPN", "Your VPN address"]],
    ] as const) {
        await scenario(name);
        await tab("Connection").click();
        await expect(heading()).toHaveText("Connected");
        await page.waitForTimeout(400);
        for (const row of rows) {
            expect(await shownOf(row), `${name}: ${row}`).toBe(1);
        }
        await expect(action()).toBeInViewport({ ratio: 1 });
    }
    await shoot("details-full-default-size");
    await resetTunnel();
});
