// Launches the real app in demo mode and looks at it. Screenshots of every
// state go to `SCREENSHOT_DIR`, or `test-results/screens` when it is not set.

import {
    existsSync,
    mkdirSync,
    mkdtempSync,
    readdirSync,
    readFileSync,
    realpathSync,
    rmSync,
    statSync,
    writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { type ElectronApplication, expect, type Locator, type Page, test } from "@playwright/test";
import { photographIcons } from "./icon-sheets";
import { launchApp } from "./launch";
import { isCi } from "./safe-env";

/**
 * Off the screen unless this is CI: a test run on someone's computer must
 * not open windows over their work. See `keepHidden` in `src/main/window.ts`.
 */
const HIDDEN = isCi(process.env) ? {} : { UBC_VPN_TEST_HIDDEN: "1" };
/** Whether this run keeps the window off the screen, so showing and hiding it cannot be watched. */
const offScreen = Object.keys(HIDDEN).length > 0;

const screenshotDir = resolve(process.env.SCREENSHOT_DIR ?? "test-results/screens");

const launchArgs = () => [
    resolve("out-demo/main/index.js"),
    // A window hidden behind others has its animations paused, and a
    // test machine's windows usually are. Keep them running.
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
];
/** A profile of its own for each launch, so it never collides with a running copy. */
const newProfile = () => mkdtempSync(join(tmpdir(), "ubc-vpn-e2e-"));
const mainProfile = newProfile();

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
const installedFolderBefore = contentsOf(installedFolder);
const launchEnv = {
    ...HIDDEN,
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
/** Text shown on the screen, leaving out the copy kept for screen readers. */
const said = (text: string) => page.locator('main p:not([role="status"])', { hasText: text });
type Side = "top" | "right" | "bottom" | "left";

/**
 * How much of each side of a focused field's ring is really drawn, from 0 to
 * 1. The field is photographed with the keyboard on it and again without,
 * and the two are compared along each edge, so it is the pixels on screen
 * that count and not what the styles say. A ring that something clips shows
 * up as a side near 0.
 */
async function ringDrawn(field: Locator): Promise<Record<Side, number>> {
    await expect(field).toBeFocused();
    const box = await field.boundingBox();
    if (box === null) {
        throw new Error("the field is not on screen");
    }
    const view = await page.evaluate(() => ({ width: innerWidth, height: innerHeight }));
    // From a little outside the field to a little inside it, on every side.
    const OUT = 6;
    const IN = 3;
    const x = Math.max(0, Math.floor(box.x) - OUT);
    const y = Math.max(0, Math.floor(box.y) - OUT);
    const clip = {
        x,
        y,
        width: Math.min(view.width, Math.ceil(box.x + box.width) + OUT) - x,
        height: Math.min(view.height, Math.ceil(box.y + box.height) + OUT) - y,
    };
    const focused = await page.screenshot({ clip });
    await field.evaluate((element) => (element as HTMLElement).blur());
    const plain = await page.screenshot({ clip });
    await field.focus();
    const { width, height, a, b } = await app.evaluate(
        ({ nativeImage }, [first, second]) => {
            const one = nativeImage.createFromBuffer(Buffer.from(first as string, "base64"));
            const two = nativeImage.createFromBuffer(Buffer.from(second as string, "base64"));
            return {
                ...one.getSize(),
                a: one.toBitmap().toString("base64"),
                b: two.toBitmap().toString("base64"),
            };
        },
        [focused.toString("base64"), plain.toString("base64")],
    );
    const one = Buffer.from(a, "base64");
    const two = Buffer.from(b, "base64");
    const scale = width / clip.width;
    const differs = (px: number, py: number) => {
        if (px < 0 || py < 0 || px >= width || py >= height) {
            return false;
        }
        const at = (py * width + px) * 4;
        let sum = 0;
        for (let channel = 0; channel < 3; channel++) {
            sum += Math.abs((one[at + channel] ?? 0) - (two[at + channel] ?? 0));
        }
        return sum > 40;
    };
    const left = (box.x - clip.x) * scale;
    const top = (box.y - clip.y) * scale;
    const right = left + box.width * scale;
    const bottom = top + box.height * scale;
    // Along each edge, leaving the rounded corners out: is anything drawn
    // across the edge at this point?
    const CORNER = 10 * scale;
    const along = (from: number, to: number, hit: (at: number, across: number) => boolean) => {
        let drawn = 0;
        let total = 0;
        for (let at = Math.ceil(from + CORNER); at < to - CORNER; at++) {
            total += 1;
            for (let across = -OUT * scale; across <= IN * scale; across++) {
                if (hit(at, across)) {
                    drawn += 1;
                    break;
                }
            }
        }
        return total === 0 ? 0 : drawn / total;
    };
    return {
        top: along(left, right, (at, across) => differs(at, Math.round(top + across))),
        bottom: along(left, right, (at, across) => differs(at, Math.round(bottom - 1 - across))),
        left: along(top, bottom, (at, across) => differs(Math.round(left + across), at)),
        right: along(top, bottom, (at, across) => differs(Math.round(right - 1 - across), at)),
    };
}

/** A screen's button in the switcher under the title bar. */
const tab = (name: string) =>
    page.getByRole("navigation", { name: "Screens" }).getByRole("button", { name, exact: true });
/** The one button on the connection screen. */
const action = () => page.locator("main > button");

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
        "retry",
        "saveRoutes",
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
    // Routes are checked the same way before anything is started for them.
    const routes = await page.evaluate(async () => {
        const save = window.ubcVpn.saveRoutes as (...args: unknown[]) => Promise<unknown>;
        const check = window.ubcVpn.checkRoutes as (...args: unknown[]) => Promise<unknown>;
        const outcome = (call: Promise<unknown>) =>
            call.then(
                () => "taken",
                () => "refused",
            );
        return {
            proper: await outcome(check({ subnets: ["203.0.113.0/24"], dns_domains: [] })),
            extraField: await outcome(save({ subnets: [], dns_domains: [], path: "/etc/passwd" })),
            notLists: await outcome(save({ subnets: "203.0.113.0/24", dns_domains: [] })),
            notText: await outcome(check({ subnets: [42], dns_domains: [] })),
        };
    });
    expect(routes).toEqual({
        proper: "taken",
        extraField: "refused",
        notLists: "refused",
        notText: "refused",
    });
    // The state the interface is sent has a place for a login, and it is idle.
    expect(await page.evaluate(() => window.ubcVpn.getSnapshot())).toMatchObject({
        login: { phase: "idle" },
    });
});

const passwordField = () => page.getByLabel("Password", { exact: true });

test("a password is hidden until shown, and hidden again when sent or the window is left", async () => {
    await scenario("login-password");
    const field = passwordField();
    await expect(field).toBeFocused();
    // Hidden by default, with a button that says what it does.
    await expect(field).toHaveAttribute("type", "password");
    const show = page.getByRole("button", { name: "Show password" });
    await expect(show).toBeVisible();
    // Nothing typed is offered to be kept or filled in.
    await expect(field).toHaveAttribute("autocomplete", "off");
    await expect(page.locator("form")).toHaveAttribute("autocomplete", "off");

    await field.fill("hunter2-not-real");
    await show.click();
    await expect(field).toHaveAttribute("type", "text");
    const hide = page.getByRole("button", { name: "Hide password" });
    await expect(hide).toBeVisible();
    await shoot("login-password-shown");
    await hide.click();
    await expect(field).toHaveAttribute("type", "password");

    // Leaving the window hides it again.
    await page.getByRole("button", { name: "Show password" }).click();
    await expect(field).toHaveAttribute("type", "text");
    await page.evaluate(() => window.dispatchEvent(new Event("blur")));
    await expect(field).toHaveAttribute("type", "password");

    // So does sending it; the next question starts hidden too.
    await page.getByRole("button", { name: "Show password" }).click();
    await expect(field).toHaveAttribute("type", "text");
    await field.press("Enter");
    // Taken: the field is gone, and the next question's answer starts hidden.
    await expect(field).toHaveCount(0);
    const code = page.getByLabel("Enter the code from your authenticator");
    await expect(code).toHaveAttribute("type", "password");
    await expect(page.getByRole("button", { name: "Show code" })).toBeVisible();
    await scenario("disconnected");
});

test("a typed password is kept nowhere: not in a message, a log or the profile", async () => {
    // A copy of its own, with a profile of its own, so the whole profile can
    // be read once it has closed: a running app holds some of its files.
    const profile = newProfile();
    const other = await launchApp({
        ...launchOptions,
        args: launchArgs(),
        env: { ...launchEnv, UBC_VPN_PROFILE: profile },
    });
    const printed: string[] = [];
    for (const stream of [other.process().stdout, other.process().stderr]) {
        stream?.on("data", (chunk: Buffer) => printed.push(chunk.toString("utf8")));
    }
    const secret = "Sentinel-pw-7Q2x-not-real";
    // A control: something the page does keep, so the search below is shown
    // to find what Chromium writes to the profile.
    const kept = "Control-kept-9Fz1";
    let sent: string[] = [];
    try {
        const shown = await other.firstWindow();
        const logged: string[] = [];
        shown.on("console", (message) => logged.push(message.text()));
        await shown.waitForLoadState("domcontentloaded");
        // Every message the main process sends the window, from here on.
        await other.evaluate(({ BrowserWindow }) => {
            const contents = BrowserWindow.getAllWindows()[0]?.webContents;
            const recorded: string[] = [];
            (globalThis as { sentToWindow?: string[] }).sentToWindow = recorded;
            if (contents !== undefined) {
                const send = contents.send.bind(contents);
                contents.send = (channel: string, ...args: unknown[]) => {
                    recorded.push(JSON.stringify([channel, ...args]));
                    send(channel, ...args);
                };
            }
        });
        await shown.evaluate(() => window.ubcVpn.demo?.setScenario("login-password"));
        const field = shown.getByLabel("Password", { exact: true });
        await field.fill(secret);
        // Shown and hidden again on the way, as a user might.
        await shown.getByRole("button", { name: "Show password" }).click();
        await shown.getByRole("button", { name: "Hide password" }).click();
        await field.press("Enter");
        // Taken by the main process: the login moves on to the next question.
        await expect(field).toHaveCount(0);
        await expect(shown.getByLabel("Enter the code from your authenticator")).toBeVisible();
        // Not in the page, now that it has been sent.
        expect(await shown.content()).not.toContain(secret);
        await shown.evaluate((value) => localStorage.setItem("e2e-control", value), kept);
        // The spellchecker, which reads what is typed, is off for the session.
        expect(
            await other.evaluate(({ session }) => session.defaultSession.isSpellCheckerEnabled()),
        ).toBe(false);
        await other.evaluate(({ session }) => session.defaultSession.flushStorageData());
        sent = await other.evaluate(
            () => (globalThis as { sentToWindow?: string[] }).sentToWindow ?? [],
        );
        expect(logged.filter((line) => line.includes(secret))).toEqual([]);
    } finally {
        await other.close();
    }

    // Not in any message the window was sent, nor in anything printed.
    expect(sent.length, "messages recorded").toBeGreaterThan(0);
    expect(sent.filter((message) => message.includes(secret))).toEqual([]);
    expect(printed.filter((line) => line.includes(secret))).toEqual([]);
    // Nor anywhere in the app's profile, where Chromium would keep saved
    // passwords, form entries or anything else, in UTF-8 or UTF-16.
    const filesHolding = (text: string) => {
        const needles = [Buffer.from(text, "utf8"), Buffer.from(text, "utf16le")];
        return readdirSync(profile, { recursive: true, encoding: "utf8" }).filter((name) => {
            const path = join(profile, name);
            if (!statSync(path).isFile()) {
                return false;
            }
            const bytes = readFileSync(path);
            return needles.some((needle) => bytes.includes(needle));
        });
    };
    expect(filesHolding(kept).length, "the search finds what is kept").toBeGreaterThan(0);
    expect(filesHolding(secret)).toEqual([]);
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
    });
    // The interface's own window is still served.
    expect(await page.evaluate(() => window.ubcVpn.getSnapshot())).toHaveProperty("state");
});

/** Obviously fake. Typed at the login prompts, then looked for where it must not be. */
const FAKE_PASSWORD = "not-a-real-password-0123456789";

test("log in, connect and disconnect, by keyboard", async () => {
    await scenario("disconnected");
    await action().focus();

    // Connect starts a login. The first question takes the keyboard.
    await page.keyboard.press("Enter");
    await expect(heading()).toHaveText("Logging in");
    await expect(heading()).toHaveText("Your password");
    const password = page.getByLabel("Password", { exact: true });
    await expect(password).toBeFocused();
    await expect(password).toHaveAttribute("type", "password");
    await expect(password).toHaveAttribute("autocomplete", "off");
    // Nothing to send yet.
    const next = page.getByRole("button", { name: "Continue" });
    await expect(next).toHaveAttribute("aria-disabled", "true");
    await page.keyboard.press("Enter");
    await expect(heading()).toHaveText("Your password");

    // Pasting is allowed; typing and Enter sends it.
    await password.evaluate((field, text) => {
        const data = new DataTransfer();
        data.setData("text/plain", text);
        field.dispatchEvent(
            new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }),
        );
    }, "pasted");
    await password.fill("");
    await page.keyboard.type(FAKE_PASSWORD);
    await expect(next).not.toHaveAttribute("aria-disabled", "true");
    await page.keyboard.press("Enter");

    // The second question, a one-time code, with a field of its own.
    await expect(heading()).toHaveText("Your one-time code");
    const code = page.getByLabel("Enter the code from your authenticator");
    await expect(code).toBeFocused();
    await expect(code).toHaveValue("");
    await expect(code).toHaveAttribute("type", "password");
    await expect(code).toHaveAttribute("inputmode", "numeric");

    // What was typed is gone from the page and was never in the app's state.
    const kept = await page.evaluate(async (secret) => {
        const snapshot = JSON.stringify(await window.ubcVpn.getSnapshot());
        return {
            inPage: document.documentElement.outerHTML.includes(secret),
            inFields: [...document.querySelectorAll("input")].some((field) =>
                field.value.includes(secret),
            ),
            inState: snapshot.includes(secret),
        };
    }, FAKE_PASSWORD);
    expect(kept).toEqual({ inPage: false, inFields: false, inState: false });

    await page.keyboard.type("000000");
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

test("a login can be given up, and the keyboard goes back to Connect", async () => {
    await scenario("disconnected");
    await action().focus();
    await page.keyboard.press("Enter");
    await expect(heading()).toHaveText("Your password");
    await page.keyboard.type("half an ans");
    await page.keyboard.press("Escape");
    await expect(heading()).toHaveText("Not connected");
    await expect(action()).toBeFocused();

    // The Cancel button does the same, also while the app is waiting.
    await page.keyboard.press("Enter");
    await expect(heading()).toHaveText("Logging in");
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(heading()).toHaveText("Not connected");
});

test("putting the window away gives a login up", async () => {
    test.skip(offScreen, "needs a window on screen; runs in CI");
    await scenario("disconnected");
    await action().click();
    await expect(heading()).toHaveText("Your password");
    await page.evaluate(() => window.ubcVpn.closeWindow());
    await expect
        .poll(() =>
            app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.isVisible()),
        )
        .toBe(false);
    // Nobody is there to answer, so the login does not carry on behind it.
    await expect
        .poll(() => page.evaluate(async () => (await window.ubcVpn.getSnapshot()).login.phase))
        .toBe("idle");
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.show());
    await expect(heading()).toHaveText("Not connected");
});

test("a failed login says why, and can be tried again or closed", async () => {
    await scenario("login-failed-wrong-password");
    await expect(heading()).toHaveText("Login refused");
    await expect(page.getByRole("status")).toContainText("UBC did not accept");
    await page.getByRole("button", { name: "Back" }).click();
    await expect(heading()).toHaveText("Not connected");

    await scenario("login-failed-gateway-unreachable");
    await page.getByRole("button", { name: "Try again" }).click();
    await expect(heading()).toHaveText("Your password");
    await page.keyboard.press("Escape");

    // When the VPN is already in use there is nothing to try again, only the way back.
    await scenario("login-failed-busy");
    await expect(heading()).toHaveText("VPN is busy");
    await expect(page.getByRole("button", { name: "Try again" })).toHaveCount(0);
    await page.getByRole("button", { name: "Back" }).click();
    await expect(heading()).toHaveText("Not connected");
    await scenario("login-failed-not-owner");
    await expect(heading()).toHaveText("Managed by another user");
    await expect(page.getByRole("button", { name: "Try again" })).toHaveCount(0);

    // A notice from the gateway is shown as text, never as markup.
    await scenario("login-password-again");
    await expect(page.getByRole("group", { name: "Message from UBC" })).toHaveText(
        "Login failed. Enter your password again.",
    );
    await scenario("disconnected");
});

test("a login being wound up says so, or says what has happened to the service", async () => {
    await scenario("disconnected");
    await scenario("login-cancelling");
    await expect(heading()).toHaveText("Cancelling");
    await expect(page.getByRole("status")).toContainText("Cancelling. Stopping the login.");
    // Nothing to press: it ends by itself.
    await expect(page.getByRole("main").getByRole("button")).toHaveCount(0);
    await shoot("login-cancelling");
    // With the service gone the wind-up waits for it, and the screen says
    // that the service is gone, which is what the user needs to know.
    await scenario("service-unavailable");
    await scenario("login-cancelling");
    await expect(heading()).toHaveText("Service not running");
    await shoot("login-cancelling-service-gone");
    await scenario("disconnected");
});

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

test("routes: a problem is marked on its own row, and only checked routes can be saved", async () => {
    await scenario("routes");
    await tab("Connection").click();
    await tab("Routes").click();
    const save = page.getByRole("button", { name: "Save routes" });
    await expect(page.getByLabel("Subnet 1", { exact: true })).toHaveValue("203.0.113.0/24");
    // Nothing has changed, so there is nothing to save.
    await expect(save).toHaveAttribute("aria-disabled", "true");
    // The limits are said before anything is typed.
    await expect(page.getByText("A subnet can be no larger than /8")).toBeVisible();
    await expect(page.getByText("203.0.113.0/24, 198.51.100.0/24")).toBeVisible();

    // A new row takes the keyboard. What is typed is checked a moment later.
    await page.getByRole("button", { name: "Add subnet" }).click();
    const added = page.getByLabel("Subnet 3", { exact: true });
    await expect(added).toBeFocused();
    await page.keyboard.type("not a subnet");
    // While the check runs, the reason Save is not available is on screen.
    // (The other "Checking…" on the page is the one read out, which is not shown.)
    await expect(
        page.locator('main [aria-hidden="true"] p', { hasText: "Checking…" }),
    ).toBeInViewport({ ratio: 1 });
    await expect(added).toHaveAttribute("aria-invalid", "true");
    await expect(said("Write a network as address/length")).toHaveCount(1);
    // The rows that were fine are left alone.
    await expect(page.getByLabel("Subnet 1", { exact: true })).not.toHaveAttribute("aria-invalid");
    await expect(save).toHaveAttribute("aria-disabled", "true");

    // Put right, it can be saved; once saved there is again nothing to save.
    await added.fill("203.0.113.128/25");
    await expect(added).not.toHaveAttribute("aria-invalid");
    await expect(save).not.toHaveAttribute("aria-disabled");
    await save.click();
    await expect(page.getByRole("status")).toContainText("Saved.");
    await expect(save).toHaveAttribute("aria-disabled", "true");

    // Removing every subnet is a problem with the whole list, said once.
    for (const name of ["Remove subnet 3", "Remove subnet 2", "Remove subnet 1"]) {
        await page.getByRole("button", { name }).click();
    }
    await expect(said("Add at least one subnet.")).toHaveCount(1);
    await expect(page.getByText("No subnets yet.")).toBeVisible();
    await expect(save).toHaveAttribute("aria-disabled", "true");
    await shoot("routes-no-subnets");
    // Leave it as it was found: those changes are thrown away.
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();
    await expect(heading()).not.toHaveText("Routes");
});

test("routes: stored routes are checked on opening, before anything is typed", async () => {
    await scenario("routes-problems");
    await tab("Connection").click();
    await tab("Routes").click();
    // Each stored entry the client refuses is marked on its own row.
    await expect(page.getByLabel("Subnet 2", { exact: true })).toHaveAttribute(
        "aria-invalid",
        "true",
    );
    await expect(said("This subnet is too large. Use /8 or a larger number")).toHaveCount(1);
    await expect(said("This range is reserved for special uses")).toHaveCount(1);
    await expect(page.getByLabel("Subnet 1", { exact: true })).not.toHaveAttribute("aria-invalid");
    // Nothing was changed, so nothing can be saved, and leaving asks nothing.
    await expect(page.getByRole("button", { name: "Save routes" })).toHaveAttribute(
        "aria-disabled",
        "true",
    );
    await tab("Connection").click();
    await expect(heading()).not.toHaveText("Routes");
    await scenario("routes");
});

test("routes: unsaved changes are not lost by leaving the screen", async () => {
    await scenario("routes");
    await tab("Connection").click();
    await tab("Routes").click();
    await page.getByLabel("Domain 1", { exact: true }).fill("lab.campus.example");

    // Asked to leave, the screen stays and asks first.
    await tab("Connection").click();
    await expect(heading()).toHaveText("Routes");
    await expect(page.getByText("You have changes that are not saved.")).toBeVisible();
    const keep = page.getByRole("button", { name: "Keep editing" });
    await expect(keep).toBeFocused();
    await shoot("routes-unsaved");
    await keep.click();
    await expect(page.getByLabel("Domain 1", { exact: true })).toHaveValue("lab.campus.example");

    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();
    await expect(heading()).not.toHaveText("Routes");
    // Coming back shows what is saved, not what was thrown away.
    await tab("Routes").click();
    await expect(page.getByLabel("Domain 1", { exact: true })).toHaveValue("campus.example");
});

test("routes: what the user needs to know is said on the form", async () => {
    // While connected, a change waits for the next connection.
    await scenario("connected");
    await tab("Connection").click();
    await tab("Routes").click();
    await page.getByLabel("Domain 1", { exact: true }).fill("lab.campus.example");
    await expect(page.getByText("Changes apply the next time you connect.")).toBeVisible();
    await shoot("routes-while-connected");
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();

    // A save can be refused for routes the check accepted: said once, on the form.
    await scenario("routes-too-long-to-save");
    await tab("Routes").click();
    await page.getByLabel("Domain 1", { exact: true }).fill("lab.campus.example");
    const save = page.getByRole("button", { name: "Save routes" });
    await expect(save).not.toHaveAttribute("aria-disabled");
    await save.click();
    await expect(said("These routes are too long to save.")).toHaveCount(1);
    await expect(page.getByLabel("Domain 1", { exact: true })).not.toHaveAttribute("aria-invalid");
    await shoot("routes-too-long-to-save-refused");
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();

    // Settings that cannot be read: said plainly, with a way to try again.
    await scenario("routes-unreadable");
    await tab("Routes").click();
    await expect(page.getByText("Your settings file is damaged")).toBeInViewport({ ratio: 1 });
    await scenario("routes");
    await page.getByRole("button", { name: "Try again" }).click();
    await expect(page.getByLabel("Subnet 1", { exact: true })).toBeVisible();

    // A missing policy is said up front.
    await scenario("routes-no-policy");
    await tab("Connection").click();
    await tab("Routes").click();
    // In view and whole, not merely there: a panel squeezed flat is "visible".
    const warning = page.getByText("The VPN’s policy file is missing or damaged");
    await expect(warning).toBeInViewport({ ratio: 1 });
    const squeezed = await warning.evaluate((text) => {
        const panel = text.closest(".scroll-region")?.parentElement;
        return panel === null || panel === undefined
            ? true
            : panel.getBoundingClientRect().height < text.getBoundingClientRect().height;
    });
    expect(squeezed).toBe(false);
    await scenario("disconnected");
    await tab("Connection").click();
});

test("routes: a list of 256 rows stays usable", async () => {
    await scenario("routes-crowded");
    await tab("Connection").click();
    await tab("Routes").click();
    await expect(page.getByLabel("Subnet 256", { exact: true })).toHaveValue("203.0.113.255/32");
    // Typing in the middle of it answers at once, and the check still comes back.
    const middle = page.getByLabel("Subnet 128", { exact: true });
    const started = Date.now();
    await middle.fill("not a subnet");
    await expect(middle).toHaveValue("not a subnet");
    expect(Date.now() - started).toBeLessThan(2000);
    await expect(said("Write a network as address/length")).toHaveCount(1);

    // The keyboard reaches everything without scrolling by hand. Tab from the
    // last subnet lands on its remove button, then on Add, and each comes
    // into view as it takes focus.
    const add = page.getByRole("button", { name: "Add subnet" });
    await expect(add).not.toBeInViewport();
    await page.getByLabel("Subnet 256", { exact: true }).focus();
    await expect(page.getByLabel("Subnet 256", { exact: true })).toBeInViewport();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await expect(add).toBeFocused();
    await expect(add).toBeInViewport({ ratio: 1 });
    // Too many rows is a problem with the whole list. It is said above Save,
    // which does not scroll, so it is on screen wherever the list is.
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Subnet 257", { exact: true })).toBeFocused();
    await page.keyboard.type("203.0.112.0/24");
    await expect(said("There are more than 256 subnets")).toBeInViewport({ ratio: 1 });
    await expect(page.getByRole("button", { name: "Save routes" })).toBeInViewport({ ratio: 1 });
    await shoot("routes-too-many");
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();
    await scenario("disconnected");
});

test("routes: the focus ring is drawn whole around a field, wherever its row is", async () => {
    await scenario("routes-crowded");
    await tab("Connection").click();
    await tab("Routes").click();
    const subnet = (row: number) => page.getByLabel(`Subnet ${row}`, { exact: true });
    await expect(subnet(256)).toHaveValue("203.0.113.255/32");
    const whole = { top: 1, right: 1, bottom: 1, left: 1 };

    // The first row.
    await subnet(1).focus();
    expect(await ringDrawn(subnet(1)), "the first row").toEqual(whole);
    await shoot("routes-focus-first-row");

    // A row in the middle, reached by Tab from the rows before it, so it is
    // scrolled only as far as it must be and sits against the area's edge.
    for (let row = 1; row < 12; row++) {
        await page.keyboard.press("Tab");
        await page.keyboard.press("Tab");
    }
    await expect(subnet(12)).toBeFocused();
    expect(await ringDrawn(subnet(12)), "a middle row").toEqual(whole);
    await shoot("routes-focus-middle-row");

    // The last row, come to from above in the same way.
    await subnet(255).focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await expect(subnet(256)).toBeFocused();
    expect(await ringDrawn(subnet(256)), "the last row").toEqual(whole);
    await shoot("routes-focus-last-row");
    await tab("Connection").click();
    await scenario("disconnected");
});

/**
 * How the rows of a list in the connection details sit: each row's box and
 * text, whether a line divides it from the row above, and whether anything in
 * it is cut off or reaches past the details.
 */
async function rowsOf(list: Locator) {
    return list.evaluate((section) => {
        const details = section.closest('[role="group"]')?.getBoundingClientRect();
        return [...section.querySelectorAll("li")].map((row) => {
            const box = row.getBoundingClientRect();
            const entry = row.querySelector("span")?.getBoundingClientRect();
            return {
                text: row.textContent ?? "",
                top: box.top,
                bottom: box.bottom,
                lineAbove: Number.parseFloat(getComputedStyle(row).borderTopWidth) > 0,
                lineBelow: Number.parseFloat(getComputedStyle(row).borderBottomWidth) > 0,
                cut: row.scrollWidth > row.clientWidth,
                outside:
                    details === undefined ||
                    box.left < details.left ||
                    box.right > details.right + 0.5,
                startsAt: entry?.left ?? null,
            };
        });
    });
}

test("connection details: one entry per row, grouped, aligned, and nothing spills", async () => {
    await scenario("connected-pieces");
    const details = page.getByRole("group", { name: "Connection details" });
    const subnets = details.getByRole("region", { name: "Subnets through the VPN" });
    const domains = details.getByRole("region", { name: "Domains looked up through the VPN" });
    await expect(subnets).toBeVisible();
    // Counted, where the group is named.
    await expect(subnets).toContainText("21 subnets");
    await expect(domains).toContainText("1 domain");
    await expect(domains.getByRole("listitem")).toHaveText(["campus.example"]);

    // The range saved in 16 pieces is shown as one row, saying so.
    await expect(subnets.getByRole("listitem")).toHaveText([
        "198.51.100.0/24",
        "10.20.0.0/16Saved as 16 subnets, leaving out 10.20.255.254",
        "10.30.0.0/16",
        "10.40.8.0/22",
        "192.0.2.0/24",
        "203.0.113.128/25",
    ]);
    const check = async (expected: number) => {
        const rows = await rowsOf(subnets);
        expect(rows).toHaveLength(expected);
        rows.forEach((row, index) => {
            expect(row.cut, `${row.text} is cut off`).toBe(false);
            expect(row.outside, `${row.text} reaches past the details`).toBe(false);
            if (index > 0) {
                // Its own row, under the last, with a line between.
                expect(row.top).toBeGreaterThanOrEqual((rows[index - 1]?.bottom ?? 0) - 0.5);
                const divided = row.lineAbove || rows[index - 1]?.lineBelow;
                expect(divided, `${row.text} has no line above it`).toBe(true);
            }
        });
        // Every address starts on one edge, the group name's.
        const heading = await subnets.getByRole("heading").boundingBox();
        const edges = new Set(rows.map((row) => Math.round(row.startsAt ?? -1)));
        expect([...edges]).toEqual([Math.round(heading?.x ?? 0)]);
    };
    await check(6);
    await shoot("details-combined");

    // The saved list is one press away, and back.
    await details.getByRole("button", { name: "Show all 21 saved subnets" }).click();
    await check(21);
    await expect(subnets.getByRole("listitem").nth(1)).toHaveText("10.20.0.0/17");
    // Scrolled, the group keeps its name in view.
    await details.evaluate((region) => {
        region.scrollTop = 240;
    });
    await expect(subnets.getByRole("heading")).toBeInViewport({ ratio: 1 });
    await shoot("details-each");
    await details.evaluate((region) => {
        region.scrollTop = 0;
    });
    await details.getByRole("button", { name: "Show combined ranges" }).click();
    await check(6);

    // The details scroll inside the window; the button below stays in view.
    const overflow = await page.evaluate(
        () =>
            document.documentElement.scrollWidth > document.documentElement.clientWidth ||
            document.documentElement.scrollHeight > document.documentElement.clientHeight,
    );
    expect(overflow).toBe(false);
    await expect(action()).toBeInViewport({ ratio: 1 });

    // The longest list allowed, and a domain with nowhere to break.
    await scenario("connected-crowded");
    await expect(subnets).toContainText("256 subnets");
    await details.getByRole("button", { name: "Show all 256 saved subnets" }).click();
    await check(256);
    const domainRows = await rowsOf(domains);
    expect(domainRows).toHaveLength(41);
    for (const row of domainRows) {
        expect(row.cut, `${row.text} is cut off`).toBe(false);
        expect(row.outside, `${row.text} reaches past the details`).toBe(false);
    }
    await expect(action()).toBeInViewport({ ratio: 1 });
    await scenario("disconnected");
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

test("the mark in the title bar takes the colour of each state, and moves to it smoothly", async () => {
    const mark = page.locator("header svg[data-tone]");
    const tunnel = mark.locator("path").first();
    const colours = new Map<string, string>();
    for (const [name, tone] of [
        ["disconnected", "idle"],
        ["connecting", "busy"],
        ["connected", "on"],
        ["login-needed", "attention"],
        ["failed-engine-failed", "problem"],
    ] as const) {
        await scenario(name);
        await expect(mark).toHaveAttribute("data-tone", tone);
        // Once the change has run its course.
        await page.waitForTimeout(400);
        colours.set(tone, await tunnel.evaluate((path) => getComputedStyle(path).stroke));
        await page
            .locator("header")
            .screenshot({ path: join(screenshotDir, `title-bar-${tone}.png`) });
    }
    // Each state its own colour.
    expect(new Set(colours.values()).size).toBe(5);
    // A change of colour is a transition, which carries on from the colour
    // it is at, never a jump.
    const transition = await tunnel.evaluate((path) => {
        const style = getComputedStyle(path);
        return { property: style.transitionProperty, duration: style.transitionDuration };
    });
    expect(transition.property).toBe("stroke");
    expect(Number.parseFloat(transition.duration)).toBeGreaterThan(0);
    await scenario("disconnected");
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
        "off.ico",
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

/** One frame of the "working" pulse, as the page drew it. */
type PulseFrame = {
    /** The page's clock, in milliseconds: the time the frame was drawn for. */
    time: number;
    /** How far along the tunnel the pulse is, from 0 to 1, or null when it is not on the page. */
    at: number | null;
    /** Whether the pulse is moving. */
    moving: boolean;
    opacity: number;
    /** Whether it is fading in or out. */
    fading: boolean;
    /** The endless animations on the page that do not run on the page's clock. */
    offClock: string[];
};

test("the working animations carry on through every change, never jumping", async () => {
    await scenario("connecting");
    await expect(heading()).toHaveText("Connecting");
    // Faded in: the page has drawn since it opened.
    await expect
        .poll(() =>
            page
                .locator("[data-pulse]")
                .evaluate((pulse) =>
                    Number.parseFloat(getComputedStyle(pulse.parentElement ?? pulse).opacity),
                ),
        )
        .toBe(1);
    // How long one lap takes, in milliseconds.
    const lap = await page
        .locator("[data-pulse]")
        .evaluate((pulse) =>
            Number(pulse.getAnimations()[0]?.effect?.getComputedTiming().duration),
        );
    expect(lap).toBeGreaterThan(0);
    // Every frame from here on is recorded, while the state and the screen change under it.
    await page.evaluate(() => {
        const frames: PulseFrame[] = [];
        const record = { frames, stop: false };
        (window as unknown as { pulseRecord: typeof record }).pulseRecord = record;
        const tick = () => {
            const pulse = document.querySelector<SVGPathElement>("[data-pulse]");
            frames.push({
                time: Number(document.timeline.currentTime),
                at:
                    pulse === null
                        ? null
                        : ((-Number.parseFloat(getComputedStyle(pulse).strokeDashoffset) % 1) + 1) %
                          1,
                moving: pulse !== null && pulse.getAnimations().length > 0,
                opacity:
                    pulse?.parentElement === null || pulse === null
                        ? 0
                        : Number.parseFloat(getComputedStyle(pulse.parentElement).opacity),
                fading:
                    pulse?.parentElement
                        ?.getAnimations()
                        .some(
                            (animation) =>
                                animation instanceof CSSTransition &&
                                animation.transitionProperty === "opacity",
                        ) ?? false,
                offClock: document
                    .getAnimations()
                    .filter(
                        (animation) =>
                            animation instanceof CSSAnimation &&
                            animation.effect?.getTiming().iterations === Number.POSITIVE_INFINITY &&
                            animation.startTime !== 0,
                    )
                    .map((animation) => (animation as CSSAnimation).animationName),
            });
            if (!record.stop) {
                setTimeout(tick, 15);
            }
        };
        // A timer, not animation frames: a window kept off the screen draws
        // none, and its animations still run on the page's clock.
        tick();
    });
    const marks: { label: string; time: number }[] = [];
    const step = async (label: string, change: () => Promise<unknown>) => {
        marks.push({
            label,
            time: await page.evaluate(() => Number(document.timeline.currentTime)),
        });
        await change();
        await page.waitForTimeout(500);
    };
    await page.waitForTimeout(500);
    // A login starts, asks a question, and gives way to the connection.
    await step("login working", () => scenario("login-working"));
    await step("login question", () => scenario("login-password"));
    await step("connecting again", () => scenario("connecting"));
    // Another screen and back: the diagram is made afresh.
    await step("another screen", () => tab("Routes").click());
    await step("back", () => tab("Connection").click());
    // Connected: the pulse fades out where it is going.
    await step("connected", () => scenario("connected"));
    await expect(heading()).toHaveText("Connected");
    await page.waitForTimeout(500);
    const frames = await page.evaluate(() => {
        const record = (
            window as unknown as { pulseRecord: { frames: PulseFrame[]; stop: boolean } }
        ).pulseRecord;
        record.stop = true;
        return record.frames;
    });
    const connectedAt = marks.at(-1)?.time ?? 0;

    expect(frames.length, "frames recorded").toBeGreaterThan(100);
    // Wherever the pulse is moving, it is exactly where the page's clock puts
    // it: it never starts a lap again, falls back or skips ahead, whatever
    // happened just before.
    const around = (a: number, b: number) => Math.min(Math.abs(a - b), 1 - Math.abs(a - b));
    const misplaced = frames
        .filter(
            (frame) =>
                frame.moving &&
                frame.at !== null &&
                around(frame.at, (frame.time % lap) / lap) > 0.02,
        )
        .map(
            (frame) =>
                `at ${frame.time.toFixed(0)} ms: ${frame.at?.toFixed(3)}, expected ${((frame.time % lap) / lap).toFixed(3)}`,
        );
    expect(misplaced, `frames where the pulse jumped (marks: ${JSON.stringify(marks)})`).toEqual(
        [],
    );
    // Every frame of the working states had it moving.
    const workingFrames = frames.filter((frame) => frame.time < connectedAt && frame.at !== null);
    expect(workingFrames.length).toBeGreaterThan(60);
    expect(workingFrames.filter((frame) => !frame.moving || frame.opacity < 0.99)).toEqual([]);
    // Nothing that loops, the status mark's breath and the spinner included,
    // runs on a clock of its own.
    expect(frames.flatMap((frame) => frame.offClock)).toEqual([]);
    // Once connected it fades out, still moving, instead of vanishing; then it stops.
    const after = frames.filter((frame) => frame.time >= connectedAt);
    expect(after.some((frame) => frame.moving && frame.fading)).toBe(true);
    expect(after.at(-1)?.moving).toBe(false);
    await shoot("connected-after-connecting");
});

test("with reduced motion the working pulse rests and nothing loops", async () => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    try {
        await scenario("connecting");
        await expect(heading()).toHaveText("Connecting");
        const looping = await page.evaluate(() =>
            document
                .getAnimations()
                .filter(
                    (animation) =>
                        animation.effect?.getTiming().iterations === Number.POSITIVE_INFINITY,
                )
                .map((animation) => (animation as CSSAnimation).animationName),
        );
        expect(looping).toEqual([]);
        // It rests mid-way, so the state can still be seen.
        const offset = await page
            .locator("[data-pulse]")
            .evaluate((pulse) => Number.parseFloat(getComputedStyle(pulse).strokeDashoffset));
        expect(offset).toBeCloseTo(-0.42);
        await shoot("connecting-reduced-motion");
    } finally {
        await page.emulateMedia({ reducedMotion: null });
        await scenario("disconnected");
    }
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

// Last of all, after every launch above has come and gone.
test("nothing was written in the installed product's folder", () => {
    expect(contentsOf(installedFolder)).toEqual(installedFolderBefore);
});
