// The Logs screen and the diagnostics report.

import { expect, test } from "@playwright/test";
import { app, heading, offScreen, page, scenario, shoot, tab, useApp } from "./fixture";

useApp();

/** The log's lines, as the page shows them. */
const logLines = () => page.getByRole("log", { name: "Log lines" }).locator("li");
/**
 * Stands in for the clipboard, in the main process, so the test never
 * touches the real one. Returns what has been "copied" since.
 */
async function watchClipboard(): Promise<() => Promise<string[]>> {
    await app.evaluate(({ clipboard }) => {
        const copied: string[] = [];
        (globalThis as unknown as { copied: string[] }).copied = copied;
        (clipboard as unknown as { writeText(text: string): void }).writeText = (text) => {
            copied.push(text);
        };
    });
    return () => app.evaluate(() => (globalThis as unknown as { copied: string[] }).copied);
}

test("logs: lines are shown oldest first, and the list keeps to the newest", async () => {
    await scenario("logs");
    await tab("Connection").click();
    await tab("Logs").click();
    await expect(heading()).toHaveText("Logs");
    await expect(logLines().first()).toContainText("ubc-vpn-service 0.1.0 is running");
    // A level is said in a word, not by colour alone; a plain line says none.
    const failed = logLines().filter({ hasText: "The gateway closed the session" }).first();
    await expect(failed).toContainText("Error");
    await expect(failed).toContainText("Engine");
    await expect(logLines().first()).not.toContainText("Error");
    // The newest line is in view, and stays in view as more arrive.
    const count = await logLines().count();
    await expect(logLines().last()).toBeInViewport({ ratio: 0.9 });
    await expect.poll(() => logLines().count()).toBeGreaterThan(count);
    await expect(logLines().last()).toBeInViewport({ ratio: 0.9 });
    await shoot("logs-following");

    // Scrolled up to read, the list stays put while lines arrive, and offers a way back.
    const list = page.getByRole("log", { name: "Log lines" });
    await list.focus();
    await page.keyboard.press("Home");
    await expect(logLines().first()).toBeInViewport({ ratio: 1 });
    const before = await logLines().count();
    await expect.poll(() => logLines().count()).toBeGreaterThan(before);
    await expect(logLines().first()).toBeInViewport({ ratio: 1 });
    const newest = page.getByRole("button", { name: "Newest lines" });
    await expect(newest).toBeVisible();
    // Said as well as shown, for someone who cannot see the button appear.
    await expect(
        page.locator('[aria-live="polite"]', { hasText: "newer lines below" }),
    ).toHaveCount(1);
    await shoot("logs-scrolled-up");
    await newest.click();
    await expect(logLines().last()).toBeInViewport({ ratio: 0.9 });
    await expect(newest).toHaveCount(0);
    await scenario("disconnected");
    await tab("Connection").click();
});

test("logs: put away and shown again, the screen carries on following the log", async () => {
    test.skip(offScreen, "needs a window on screen; runs in CI");
    await scenario("logs");
    await tab("Connection").click();
    await tab("Logs").click();
    await expect.poll(() => logLines().count()).toBeGreaterThan(3);
    const shown = (visible: boolean) =>
        app.evaluate(({ BrowserWindow }, on) => {
            const window = BrowserWindow.getAllWindows()[0];
            if (on) {
                window?.show();
            } else {
                window?.hide();
            }
        }, visible);
    await shown(false);
    await page.waitForTimeout(500);
    await shown(true);
    // Lines written after it was shown again reach the screen.
    const newest = await logLines().last().textContent();
    await expect.poll(() => logLines().last().textContent(), { timeout: 10_000 }).not.toBe(newest);
    await scenario("disconnected");
    await tab("Connection").click();
});

test("logs: a line is put on the page as text, whatever it holds", async () => {
    await scenario("logs-awkward");
    await tab("Connection").click();
    await tab("Logs").click();
    const list = page.getByRole("log", { name: "Log lines" });
    await expect(list).toContainText("<b>not bold</b> <img src=x onerror=alert(1)>");
    await expect(list.locator("img, b, a")).toHaveCount(0);
    // Made one plain line in the main process before it was sent here.
    await expect(list).toContainText("A line with a newline, a tab and a direction override");
    const shown = await list.evaluate((element) => element.textContent ?? "");
    expect(shown).not.toMatch(/[\u202e\t\n]/);
    await expect(list).toContainText("[a line with nothing that can be shown]");
    // Nothing spills out sideways, however long a line without a break is.
    const overflow = await list.evaluate((element) => element.scrollWidth > element.clientWidth);
    expect(overflow).toBe(false);
    await scenario("disconnected");
    await tab("Connection").click();
});

test("logs: empty, unreadable, long, and a service started again", async () => {
    await scenario("logs-empty");
    await tab("Connection").click();
    await tab("Logs").click();
    await expect(page.getByText("Nothing has been logged yet.")).toBeVisible();

    await scenario("logs-unavailable");
    await tab("Connection").click();
    await tab("Logs").click();
    await expect(page.getByText("The log could not be read")).toBeInViewport({ ratio: 1 });
    await scenario("logs");
    await page.getByRole("button", { name: "Try again" }).click();
    await expect(logLines().first()).toContainText("ubc-vpn-service 0.1.0 is running");

    // The service started again while the log is open: what was shown is gone.
    await expect.poll(() => logLines().count()).toBeGreaterThan(3);
    await scenario("logs-new-run");
    await expect(logLines()).toHaveCount(3);

    // A hole the service can no longer fill: said where it is, and not
    // as the start of the log having gone.
    await scenario("logs-lost");
    await tab("Connection").click();
    await tab("Logs").click();
    const afterHole = logLines().filter({ hasText: "Some lines here are no longer kept." });
    await expect(afterHole).toHaveCount(1);
    await expect(afterHole).toContainText("Connecting to vpn.example");
    await expect(page.getByText("Older lines are no longer kept.")).toHaveCount(0);
    await shoot("logs-lost-lines");

    // A long log: a bounded number of lines, and a word that older ones have gone.
    await scenario("logs-many");
    await tab("Connection").click();
    await tab("Logs").click();
    await expect(logLines()).toHaveCount(500);
    await expect(page.getByText("Older lines are no longer kept.")).toBeVisible();
    await expect(logLines().last()).toBeInViewport({ ratio: 0.9 });
    await scenario("disconnected");
    await tab("Connection").click();
});

test("logs: the report is copied only after the user is told what it holds, and says yes", async () => {
    // The main process copies only for the window in use, and a window kept
    // off the screen is never in use: this runs in CI.
    test.skip(offScreen, "needs a window on screen; runs in CI");
    await app.evaluate(({ app: electronApp, BrowserWindow }) => {
        electronApp.focus({ steal: true });
        BrowserWindow.getAllWindows()[0]?.focus();
    });
    const copied = await watchClipboard();
    await scenario("logs-awkward");
    await tab("Connection").click();
    await tab("Logs").click();
    await expect(logLines().first()).toBeVisible();
    await page.getByRole("button", { name: "Copy report", exact: true }).click();
    // Said first: what the report holds, and what it may name.
    await expect(page.getByText("Log lines can name folders on this computer")).toBeInViewport({
        ratio: 1,
    });
    await expect(page.getByRole("button", { name: "Copy to clipboard" })).toBeFocused();
    // Read out as it appears, before the button that copies.
    await expect(page.getByRole("alert")).toContainText("It holds no password, code or session.");
    await shoot("logs-report-asked");
    expect(await copied()).toEqual([]);
    // Saying no copies nothing.
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(page.getByText("Log lines can name folders")).toHaveCount(0);
    expect(await copied()).toEqual([]);

    await page.getByRole("button", { name: "Copy report", exact: true }).click();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status")).toContainText(/Report copied, with \d+ log lines\./);
    const reports = await copied();
    expect(reports).toHaveLength(1);
    expect(reports[0]).toContain("UBC VPN diagnostics report");
    expect(reports[0]).toContain("Service version: 0.1.0, protocol 3");
    expect(reports[0]).toContain("A line with a newline, a tab and a direction override");
    await shoot("logs-report-copied");
    await scenario("disconnected");
    await tab("Connection").click();
});
