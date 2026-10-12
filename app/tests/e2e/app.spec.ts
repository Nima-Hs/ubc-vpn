// Launches the real app in demo mode and looks at it. Screenshots of every
// state go to `SCREENSHOT_DIR`, or `test-results/screens` when it is not set.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

const launchArgs = () => [
    resolve("out-demo/main/index.js"),
    // A window hidden behind others has its animations paused, and a
    // test machine's windows usually are. Keep them running.
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    // Its own profile, so it never collides with a running copy.
    `--user-data-dir=${mkdtempSync(join(tmpdir(), "ubc-vpn-e2e-"))}`,
];
const launchEnv = {
    ...process.env,
    UBC_VPN_DEMO_STEP_MS: "600",
    // Whatever desktop the test machine runs, behave as on one with a tray.
    XDG_CURRENT_DESKTOP: "e2e",
};

// On Linux the test driver turns Chromium's sandbox off unless told not to.
// The app ships with it on, so it is tested with it on.
const launchOptions = { chromiumSandbox: true };

let app: ElectronApplication;
let page: Page;
const problems: string[] = [];

test.beforeAll(async () => {
    mkdirSync(screenshotDir, { recursive: true });
    app = await electron.launch({
        ...launchOptions,
        args: launchArgs(),
        env: launchEnv,
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
        window.setPosition(leftHalf ? area.x + area.width - width - 40 : area.x + 40, area.y + 40);
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
    // The last test closes the app itself; closing twice is harmless.
    await app.close().catch(() => {});
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
        "answerPrompt",
        "cancelLogin",
        "closeWindow",
        "connect",
        "demo",
        "disconnect",
        "getSnapshot",
        "minimizeWindow",
        "onSnapshot",
        "platform",
        "retry",
    ]);
});

test("a login answer is checked before the main process takes it", async () => {
    // The one function that takes arguments. Anything but a prompt id and
    // text is refused, whatever the page sends.
    const sent = await page.evaluate(async () => {
        const answer = window.ubcVpn.answerPrompt as (...args: unknown[]) => Promise<void>;
        const outcome = (...args: unknown[]) =>
            answer(...args).then(
                () => "taken",
                () => "refused",
            );
        return {
            proper: await outcome(1, "an answer"),
            noText: await outcome(1, { toString: () => "an answer" }),
            noId: await outcome("1", "an answer"),
            tooLong: await outcome(1, "x".repeat(5000)),
        };
    });
    expect(sent).toEqual({
        proper: "taken",
        noText: "refused",
        noId: "refused",
        tooLong: "refused",
    });
    // The state the interface is sent has a place for a login, and it is idle.
    expect(await page.evaluate(() => window.ubcVpn.getSnapshot())).toMatchObject({
        login: { phase: "idle" },
    });
});

test("the interface's process is confined", async () => {
    const seen = await app.evaluate(({ app: electronApp, BrowserWindow, Menu }) => {
        const contents = BrowserWindow.getAllWindows()[0]?.webContents;
        // Electron keeps the preferences a window was made with; the method
        // is real but missing from its type definitions.
        const preferences = (
            contents as unknown as
                | { getLastWebPreferences(): Record<string, unknown> | null }
                | undefined
        )?.getLastWebPreferences();
        const items = Menu.getApplicationMenu()?.items ?? [];
        return {
            sandbox: preferences?.sandbox,
            contextIsolation: preferences?.contextIsolation,
            nodeIntegration: preferences?.nodeIntegration,
            webSecurity: preferences?.webSecurity,
            webviewTag: preferences?.webviewTag,
            noSandboxSwitch: electronApp.commandLine.hasSwitch("no-sandbox"),
            pid: contents?.getOSProcessId(),
            // Every role the menu offers, at any depth.
            menuRoles: items.flatMap((item) => [
                item.role,
                ...(item.submenu?.items.map((entry) => entry.role) ?? []),
            ]),
        };
    });
    expect(seen).toMatchObject({
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
        webviewTag: false,
        noSandboxSwitch: false,
    });
    // No menu entry reloads the page or opens developer tools.
    for (const role of ["reload", "forcereload", "toggledevtools", "viewmenu"]) {
        expect(seen.menuRoles.map((entry) => String(entry).toLowerCase())).not.toContain(role);
    }
    // On Linux the kernel says whether the process is really sandboxed:
    // Chromium's sandbox puts a seccomp filter (mode 2) on it.
    if (process.platform === "linux") {
        expect(readFileSync(`/proc/${seen.pid}/status`, "utf8")).toMatch(/^Seccomp:\s*2$/m);
    }
});

test("no permission is granted", async () => {
    const answers = await page.evaluate(async () => ({
        check: (await navigator.permissions.query({ name: "notifications" })).state,
        request: await Notification.requestPermission(),
    }));
    expect(answers).toEqual({ check: "denied", request: "denied" });
});

test("only the interface's own files are served, with their headers", async () => {
    // A real file of a kind the interface is not made of, placed in its
    // folder: only the list of allowed kinds stands between it and a reader.
    const stray = resolve("out-demo/renderer/stray-notes.txt");
    writeFileSync(stray, "not part of the interface");
    const fetched = await app
        .evaluate(async ({ session }) => {
            const get = async (url: string) => {
                try {
                    const response = await session.defaultSession.fetch(url);
                    return {
                        status: response.status,
                        csp: response.headers.get("content-security-policy"),
                        sniff: response.headers.get("x-content-type-options"),
                    };
                } catch {
                    return { status: 0, csp: null, sniff: null };
                }
            };
            return {
                index: await get("app://ui/index.html"),
                climbing: await get("app://ui/..%2f..%2fpackage.json"),
                otherMain: await get("app://ui/..%2fmain%2findex.js"),
                otherHost: await get("app://elsewhere/index.html"),
                otherType: await get("app://ui/stray-notes.txt"),
            };
        })
        // Whatever happens, the stray file does not outlive the test.
        .finally(() => rmSync(stray, { force: true }));
    expect(fetched.index.status).toBe(200);
    expect(fetched.index.csp).toContain("default-src 'none'");
    expect(fetched.index.csp).toContain("connect-src 'none'");
    expect(fetched.index.csp).toContain("script-src 'self';");
    expect(fetched.index.sniff).toBe("nosniff");
    // The main process's own code sits beside the interface's folder.
    expect(fetched.otherMain.status).toBe(404);
    expect(fetched.climbing.status).toBe(404);
    // Refused before it is even looked up: no such host is ever requested.
    expect(fetched.otherHost.status).toBe(0);
    expect(fetched.otherType.status).toBe(404);
});

test("another window cannot use the interface's functions", async () => {
    const answer = await app.evaluate(async ({ BrowserWindow }, preload) => {
        // The same page and the same preload, in a window the app did not make.
        const other = new BrowserWindow({
            show: false,
            webPreferences: { preload, sandbox: true },
        });
        try {
            await other.loadURL("app://ui/index.html");
            // Every function the interface has, each with arguments its own
            // check would accept, so that only the sender can be the reason.
            return await other.webContents.executeJavaScript(`(async () => {
                const api = window.ubcVpn;
                const calls = {
                    getSnapshot: () => api.getSnapshot(),
                    connect: () => api.connect(),
                    disconnect: () => api.disconnect(),
                    retry: () => api.retry(),
                    answerPrompt: () => api.answerPrompt(1, "an answer"),
                    cancelLogin: () => api.cancelLogin(),
                    minimizeWindow: () => api.minimizeWindow(),
                    closeWindow: () => api.closeWindow(),
                    listScenarios: () => api.demo.listScenarios(),
                    setScenario: () => api.demo.setScenario("connected"),
                };
                const out = {};
                for (const [name, call] of Object.entries(calls)) {
                    out[name] = await call().then(() => "answered", () => "refused");
                }
                return out;
            })()`);
        } finally {
            other.destroy();
        }
    }, resolve("out-demo/preload/index.js"));
    expect(answer).toEqual({
        getSnapshot: "refused",
        connect: "refused",
        disconnect: "refused",
        retry: "refused",
        answerPrompt: "refused",
        cancelLogin: "refused",
        minimizeWindow: "refused",
        closeWindow: "refused",
        listScenarios: "refused",
        setScenario: "refused",
    });
    // The interface's own window is still served.
    expect(await page.evaluate(() => window.ubcVpn.getSnapshot())).toHaveProperty("state");
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

test("keyboard focus on the scrolling details is visible", async () => {
    await scenario("connected-crowded");
    const details = page.getByRole("group", { name: "Connection details" });
    await expect(details).toBeVisible();
    // Reach it the way a keyboard user does: Tab through the title bar,
    // whose controls differ by OS, until focus lands on it.
    await page.locator("body").click({ position: { x: 1, y: 1 } });
    for (let presses = 0; presses < 8; presses++) {
        await page.keyboard.press("Tab");
        if (await details.evaluate((region) => region === document.activeElement)) {
            break;
        }
    }
    await expect(details).toBeFocused();
    const ring = await details.evaluate((region) => {
        const style = getComputedStyle(region);
        return {
            keyboard: region.matches(":focus-visible"),
            style: style.outlineStyle,
            width: Number.parseFloat(style.outlineWidth),
            offset: Number.parseFloat(style.outlineOffset),
        };
    });
    // Drawn inside the region, where the panel's rounded edge cannot clip it.
    expect(ring.keyboard).toBe(true);
    expect(ring.style).toBe("solid");
    expect(ring.width).toBeGreaterThanOrEqual(2);
    expect(ring.offset).toBe(-ring.width);
    await shoot("keyboard-focus-details");
    await page.keyboard.press("ArrowDown");
    await expect.poll(() => details.evaluate((region) => region.scrollTop)).toBeGreaterThan(0);
    await scenario("disconnected");
});

test("the component gallery", async () => {
    await page.getByRole("button", { name: "Components" }).click();
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

test("the keyboard enlarges, shrinks and resets the interface", async () => {
    const view = () =>
        app.evaluate(({ BrowserWindow }) => {
            const window = BrowserWindow.getAllWindows()[0];
            return {
                zoom: window?.webContents.getZoomFactor(),
                width: window?.getContentSize()[0],
            };
        });
    // Sent through the app, as a real key press is: the shortcut is handled
    // before the page sees the key.
    const chord = (key: string) =>
        app.evaluate(({ BrowserWindow }, keyCode) => {
            BrowserWindow.getAllWindows()[0]?.webContents.sendInputEvent({
                type: "keyDown",
                keyCode,
                modifiers: [process.platform === "darwin" ? "meta" : "control"],
            });
        }, key);
    await scenario("disconnected");
    const start = await view();
    expect(start.zoom).toBe(1);

    await chord("=");
    await chord("=");
    await expect.poll(async () => (await view()).zoom).toBe(1.25);
    // The window grows with the text, so nothing is cut off.
    expect((await view()).width).toBeGreaterThan(start.width ?? 0);
    await expect(action()).toBeInViewport({ ratio: 1 });

    await chord("-");
    await expect.poll(async () => (await view()).zoom).toBe(1.1);
    await chord("0");
    await expect.poll(view).toEqual(start);
});

test("a connection in progress does not trap the user", async () => {
    await scenario("connecting");
    await expect(action()).toHaveAttribute("aria-busy", "true");
    // The window can still be put away, and the app can still be quit.
    await page.evaluate(() => window.ubcVpn.closeWindow());
    await expect
        .poll(() =>
            app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.isVisible()),
        )
        .toBe(false);
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.show());
    await scenario("disconnected");
});

test("closing the window keeps the app in the tray", async () => {
    await page.evaluate(() => window.ubcVpn.closeWindow());
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
    // Ask the page to leave, and wait for the app's answer to that very
    // request: the navigation is offered to the app, which must refuse it.
    const navigation = await app.evaluate(({ BrowserWindow }) => {
        const contents = BrowserWindow.getAllWindows()[0]?.webContents;
        return new Promise<{ url: string; refused: boolean; stayedAt: string | undefined }>(
            (done) => {
                // Added after the app's own listener, so it sees the decision.
                contents?.once("will-navigate", (event) => {
                    done({
                        url: event.url,
                        refused: event.defaultPrevented,
                        stayedAt: contents.getURL(),
                    });
                });
                void contents?.executeJavaScript("window.location.href = 'https://example.com/'");
            },
        );
    });
    expect(navigation).toEqual({
        url: "https://example.com/",
        refused: true,
        stayedAt: "app://ui/index.html",
    });
});

test("a built app ignores a dev server address in its environment", async () => {
    await app.close();
    const other = await electron.launch({
        ...launchOptions,
        args: launchArgs(),
        env: { ...launchEnv, ELECTRON_RENDERER_URL: "https://example.com/" },
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
