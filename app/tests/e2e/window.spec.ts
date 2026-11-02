// The window: where its profile is kept, how it is locked down and confined,
// what it serves, and how it is shown, hidden and put away.

import { readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import {
    action,
    app,
    heading,
    launchArgs,
    launchEnv,
    launchOptions,
    mainProfile,
    newProfile,
    offScreen,
    page,
    scenario,
    shoot,
    tab,
    useApp,
} from "./fixture";
import { launchApp } from "./launch";

useApp();

test("an app that is not installed keeps its profile out of the installed product's folder", async () => {
    const userData = await app.evaluate(({ app: electronApp }) => electronApp.getPath("userData"));
    expect(realpathSync(userData)).toBe(realpathSync(mainProfile));
    // Chromium has written its profile there, so the check below means something.
    expect(readdirSync(mainProfile).length).toBeGreaterThan(0);
    // And it is not in dev mode, so it does not say it is.
    await expect(page.getByText("Development mode")).toHaveCount(0);
});

test("a second copy with a profile of its own runs beside the first", async () => {
    // One copy at a time is kept by a lock, which on macOS and Linux is a
    // file in the profile folder. Were the profile chosen after the lock is
    // taken, both copies would use Electron's own folder, and this second
    // one would find the first one's lock and leave at once.
    const other = await launchApp({
        ...launchOptions,
        args: launchArgs(),
        env: { ...launchEnv, UBC_VPN_PROFILE: newProfile() },
    });
    try {
        const window = await other.firstWindow();
        await window.waitForLoadState("domcontentloaded");
        await expect(window.getByRole("heading", { level: 1 })).toHaveText("Not connected");
        // And the first is still here.
        await expect(heading()).toBeVisible();
    } finally {
        await other.close();
    }
});

test("the screens are switched from a row of their own, with every one named", async () => {
    const nav = page.getByRole("navigation", { name: "Screens" });
    const layout = await nav.evaluate((row) => {
        const box = (element: Element) => element.getBoundingClientRect();
        const buttons = [...row.querySelectorAll("button")];
        const header = document.querySelector("header");
        const main = document.querySelector("main");
        return {
            names: buttons.map((button) => button.textContent),
            widths: buttons.map((button) => Math.round(box(button).width)),
            // How wide each name is when nothing limits it.
            natural: buttons.map((button) => {
                const range = document.createRange();
                range.selectNodeContents(button);
                return Math.ceil(range.getBoundingClientRect().width);
            }),
            cut: buttons.some((button) => button.scrollWidth > button.clientWidth),
            inner: buttons.reduce((sum, button) => sum + box(button).width, 0),
            underTitleBar: header !== null && box(header).bottom <= box(row).top + 0.5,
            aboveScreen: main !== null && box(row).bottom <= box(main).top + 0.5,
            current: buttons.filter((button) => button.getAttribute("aria-current") === "page")
                .length,
        };
    });
    expect(layout.names.slice(0, 2)).toEqual(["Connection", "Routes"]);
    expect(layout.underTitleBar).toBe(true);
    expect(layout.aboveScreen).toBe(true);
    expect(layout.current).toBe(1);
    // The screens share the row equally, and no name is cut short.
    expect(new Set(layout.widths).size).toBe(1);
    expect(layout.cut).toBe(false);
    // Room for four: a quarter of the row holds the longest name whole.
    expect(layout.inner / 4).toBeGreaterThan(Math.max(...layout.natural) + 8);
    // With the switcher out of it, the title bar always has room for the name.
    await expect(page.locator("header").getByText("UBC VPN", { exact: true })).toBeVisible();
    // The keyboard reaches each screen's button and switches with it.
    await tab("Connection").focus();
    await page.keyboard.press("Tab");
    await expect(tab("Routes")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(heading()).toHaveText("Routes");
    await expect(tab("Routes")).toHaveAttribute("aria-current", "page");
    await shoot("switcher-row-routes");
    await tab("Connection").click();
    await expect(heading()).not.toHaveText("Routes");
    await shoot("switcher-row-connection");
});

test("the window renders, locked down", async () => {
    await expect(heading()).toHaveText("Not connected");
    await expect(action()).toHaveText("Connect");

    // The interface has no Node, no Electron, and only its own small API.
    const exposed = await page.evaluate(() => ({
        require: typeof (globalThis as { require?: unknown }).require,
        process: typeof (globalThis as { process?: unknown }).process,
        api: Object.keys(window.ubcVpn).sort(),
        profiles: Object.keys(window.ubcVpn.profiles ?? {}).sort(),
    }));
    expect(exposed.require).toBe("undefined");
    expect(exposed.process).toBe("undefined");
    expect(exposed.api).toEqual([
        "answerPrompt",
        "cancelLogin",
        "checkRoutes",
        "closeWindow",
        "connect",
        "demo",
        "disconnect",
        "getSettings",
        "getSnapshot",
        "logs",
        "minimizeWindow",
        "onSnapshot",
        "platform",
        "profiles",
        "retry",
        "saveRoutes",
        "setTunnel",
    ]);
    // The Settings screen's: none takes or returns a password.
    expect(exposed.profiles).toEqual([
        "create",
        "forgetPassword",
        "list",
        "onChange",
        "remove",
        "rename",
        "setStartup",
        "switchTo",
        "update",
    ]);
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
                    getSettings: () => api.getSettings(),
                    checkRoutes: () => api.checkRoutes({ subnets: [], dns_domains: [] }),
                    saveRoutes: () => api.saveRoutes({ subnets: [], dns_domains: [] }),
                    minimizeWindow: () => api.minimizeWindow(),
                    closeWindow: () => api.closeWindow(),
                    openLogs: () => api.logs.open(),
                    closeLogs: () => api.logs.close(),
                    copyReport: () => api.logs.copyReport(),
                    listScenarios: () => api.demo.listScenarios(),
                    setScenario: () => api.demo.setScenario("connected"),
                    loginItem: () => api.demo.loginItem(),
                    listProfiles: () => api.profiles.list(),
                    setStartup: () => api.profiles.setStartup("off", false),
                    forgetPassword: () => api.profiles.forgetPassword(null),
                    createProfile: () => api.profiles.create("Lab"),
                    renameProfile: () =>
                        api.profiles.rename("0a1b2c3d4e5f60718293a4b5c6d7e8f9", "Lab"),
                    updateProfile: () =>
                        api.profiles.update("0a1b2c3d4e5f60718293a4b5c6d7e8f9", { username: null }),
                    removeProfile: () => api.profiles.remove("0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
                    switchProfile: () => api.profiles.switchTo("0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
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
        getSettings: "refused",
        checkRoutes: "refused",
        saveRoutes: "refused",
        minimizeWindow: "refused",
        closeWindow: "refused",
        openLogs: "refused",
        closeLogs: "refused",
        copyReport: "refused",
        listScenarios: "refused",
        setScenario: "refused",
        loginItem: "refused",
        listProfiles: "refused",
        setStartup: "refused",
        forgetPassword: "refused",
        createProfile: "refused",
        renameProfile: "refused",
        updateProfile: "refused",
        removeProfile: "refused",
        switchProfile: "refused",
    });
    // The interface's own window is still served.
    expect(await page.evaluate(() => window.ubcVpn.getSnapshot())).toHaveProperty("state");
});

test("a connection in progress does not trap the user", async () => {
    test.skip(offScreen, "needs a window on screen; runs in CI");
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
    test.skip(offScreen, "needs a window on screen; runs in CI");
    await page.evaluate(() => window.ubcVpn.closeWindow());
    await expect
        .poll(() =>
            app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.isVisible()),
        )
        .toBe(false);
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.show());
});

test("a test run can keep the window off the screen, and only a test run", async () => {
    const other = await launchApp({
        ...launchOptions,
        args: launchArgs(),
        env: { ...launchEnv, UBC_VPN_PROFILE: newProfile(), UBC_VPN_TEST_HIDDEN: "1" },
    });
    try {
        const offPage = await other.firstWindow();
        await offPage.waitForLoadState("domcontentloaded");
        // It is drawn and can be driven, and it is not on screen.
        await expect(offPage.getByRole("heading", { level: 1 })).toHaveText("Not connected");
        const shown = () =>
            other.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.isVisible());
        expect(await shown()).toBe(false);
        // Asked to come forward, as a second launch asks, it stays away.
        await other.evaluate(({ app }) => app.emit("second-instance"));
        await offPage.waitForTimeout(300);
        expect(await shown()).toBe(false);
        // The page runs as if it were on screen.
        expect(await offPage.evaluate(() => document.visibilityState)).toBe("visible");
        // And there is no tray icon: with none, closing the window would quit.
        // (Not on macOS, where the Dock brings a closed window back, so closing
        // hides it whether or not there is a tray, and this cannot tell.)
        if (process.platform !== "darwin") {
            expect(
                await offPage.evaluate(async () => (await window.ubcVpn.getSnapshot()).closeHides),
            ).toBe(false);
        }
    } finally {
        await other.close();
    }
});

// On an app of its own, which it closes: a refused navigation leaves the
// test driver waiting on the page, and the page’s blocked request would be
// counted against the spec’s own window, which is checked for problems.
test("it cannot reach the network, open a window or leave its page", async () => {
    const app = await launchApp({
        ...launchOptions,
        args: launchArgs(),
        env: { ...launchEnv, UBC_VPN_PROFILE: newProfile() },
    });
    try {
        const page = await app.firstWindow();
        await page.waitForLoadState("domcontentloaded");
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
                    void contents?.executeJavaScript(
                        "window.location.href = 'https://example.com/'",
                    );
                },
            );
        });
        expect(navigation).toEqual({
            url: "https://example.com/",
            refused: true,
            stayedAt: "app://ui/index.html",
        });
    } finally {
        await app.close();
    }
});
