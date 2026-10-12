// Launches the real app in demo mode and looks at it. Screenshots of every
// state go to `SCREENSHOT_DIR`, or `test-results/screens` when it is not set.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
    type ElectronApplication,
    _electron as electron,
    expect,
    type Locator,
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

/** A screen's button in the title bar's switcher. */
const tab = (name: string) =>
    page.getByRole("navigation", { name: "Screens" }).getByRole("button", { name, exact: true });
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
        "checkRoutes",
        "closeWindow",
        "connect",
        "demo",
        "disconnect",
        "getSettings",
        "getSnapshot",
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
    const password = page.getByLabel("Password");
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

test("every state, photographed", async () => {
    const scenarios = (await page.evaluate(() => window.ubcVpn.demo?.listScenarios())) ?? [];
    expect(scenarios.length).toBeGreaterThan(20);
    for (const name of scenarios) {
        await scenario(name);
        // A routes state is seen on the Routes screen, opened afresh so it reads the state.
        await tab("Connection").click();
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
