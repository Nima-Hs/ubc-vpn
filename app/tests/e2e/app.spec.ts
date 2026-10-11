// Launches the real app in demo mode and looks at it. Screenshots of every
// state go to `SCREENSHOT_DIR`, or `test-results/screens` when it is not set.

import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
    type ElectronApplication,
    _electron as electron,
    expect,
    type Page,
    test,
} from "@playwright/test";

const screenshotDir = resolve(process.env.SCREENSHOT_DIR ?? "test-results/screens");

let app: ElectronApplication;
let page: Page;
const problems: string[] = [];

test.beforeAll(async () => {
    mkdirSync(screenshotDir, { recursive: true });
    app = await electron.launch({
        args: [
            resolve("out-demo/main/index.js"),
            // A window hidden behind others has its animations paused, and a
            // test machine's windows usually are. Keep them running.
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            // Its own profile, so it never collides with a running copy.
            `--user-data-dir=${mkdtempSync(join(tmpdir(), "ubc-vpn-e2e-"))}`,
        ],
        env: { ...process.env, UBC_VPN_DEMO_STEP_MS: "600" },
    });
    page = await app.firstWindow();
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
    await app.close();
});

async function shoot(name: string): Promise<void> {
    // Let transitions finish, so the picture is of the state and not of the way into it.
    await page.waitForTimeout(700);
    await page.screenshot({ path: join(screenshotDir, `${name}.png`) });
}

async function scenario(name: string): Promise<void> {
    await page.evaluate((scenarioName) => window.ubcVpn.demo?.setScenario(scenarioName), name);
}

const heading = () => page.getByRole("heading", { level: 1 });
/** The one button on the connection screen. */
const action = () => page.getByRole("main").getByRole("button");

test("the window renders, locked down", async () => {
    await expect(heading()).toHaveText("Not connected");
    await expect(action()).toHaveText("Connect");

    // The interface has no Node, no Electron, and only its own small API.
    const exposed = await page.evaluate(() => ({
        require: typeof (globalThis as { require?: unknown }).require,
        process: typeof (globalThis as { process?: unknown }).process,
        api: Object.keys(window.ubcVpn).sort(),
    }));
    expect(exposed.require).toBe("undefined");
    expect(exposed.process).toBe("undefined");
    expect(exposed.api).toEqual([
        "connect",
        "demo",
        "disconnect",
        "getSnapshot",
        "hideWindow",
        "minimizeWindow",
        "onSnapshot",
        "platform",
        "retry",
    ]);
});

test("connect and disconnect, by keyboard", async () => {
    await scenario("disconnected");
    await action().focus();

    await page.keyboard.press("Enter");
    await expect(heading()).toHaveText("Connecting");
    await expect(action()).toHaveAttribute("aria-busy", "true");
    await expect(heading()).toHaveText("Connected");
    await expect(page.getByText("198.51.100.42")).toBeVisible();
    await expect(page.getByRole("status")).toContainText(
        "Traffic to 2 UBC subnets goes through the VPN",
    );

    // The same button, still focused, now disconnects.
    await expect(action()).toBeFocused();
    await expect(action()).toHaveText("Disconnect");
    await shoot("keyboard-focus");
    await page.keyboard.press("Space");
    await expect(heading()).toHaveText("Disconnecting");
    await expect(heading()).toHaveText("Not connected");
});

test("every state, photographed", async () => {
    const scenarios = (await page.evaluate(() => window.ubcVpn.demo?.listScenarios())) ?? [];
    expect(scenarios.length).toBeGreaterThan(20);
    for (const name of scenarios) {
        await scenario(name);
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
                    region.focus();
                    return document.activeElement !== region;
                }),
        );
        expect(stuck, `${name} has a region the keyboard cannot scroll`).toBe(false);
        await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
        await shoot(`state-${name}`);
    }
});

test("the component gallery", async () => {
    await page.getByRole("button", { name: "Components" }).click();
    await expect(page.getByRole("heading", { name: "Buttons" })).toBeVisible();
    await shoot("components-1");
    for (const [index, section] of ["Status", "Panels and rows"].entries()) {
        await page.getByRole("heading", { name: section }).scrollIntoViewIfNeeded();
        await shoot(`components-${index + 2}`);
    }
    await page.getByRole("button", { name: "Open settings" }).hover();
    await expect(page.getByRole("tooltip")).toHaveText("Open settings");
    await shoot("components-tooltip");
    await page.getByRole("button", { name: "Delete route" }).last().hover();
    await shoot("components-hover");
    await page.getByRole("button", { name: "Connection" }).click();
});

test("closing the window keeps the app in the tray", async () => {
    await page.evaluate(() => window.ubcVpn.hideWindow());
    await expect
        .poll(() =>
            app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.isVisible()),
        )
        .toBe(false);
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.show());
});

test("nothing was blocked or broken along the way", () => {
    expect(problems).toEqual([]);
});

// Last, because a refused navigation leaves the test driver waiting on the page.
test("it cannot reach the network, open a window or leave its page", async () => {
    const fetched = await page.evaluate(() =>
        fetch("https://example.com/").then(
            () => "sent",
            () => "blocked",
        ),
    );
    expect(fetched).toBe("blocked");
    const opened = await page.evaluate(() => window.open("https://example.com/") !== null);
    expect(opened).toBe(false);
    await page.evaluate(() => {
        window.location.href = "https://example.com/";
    });
    await page.waitForTimeout(500);
    const urls = await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().map((window) => window.webContents.getURL()),
    );
    expect(urls).toEqual(["app://ui/index.html"]);
});
