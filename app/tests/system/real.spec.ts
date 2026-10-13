// The real app, the real command-line client and a real service, together.
// Nothing here is a mock or a demo: the app is the production build, started
// unpackaged with `UBC_VPN_CLI` and `UBC_VPN_DEV=1`; the client is
// `ubc-vpn --dev`; the service is `ubc-vpn-service --dev`, run as this user.
// Only routing, DNS and the gateway are pretend, as dev mode makes them.
//
// It runs only when `UBC_VPN_SYSTEM_SERVICE` and `UBC_VPN_SYSTEM_CLI` name
// the two programs, built with their `dev-mode` features, and prints
// `RAN: app-system` when it has run to the end. The workflow checks for that
// line, so a skip cannot pass there.
//
// What keeps this apart from a real UBC VPN on the same machine (the same
// way `crates/cli/tests/system.rs` does it):
//
// - Every program runs in dev mode, whose files and channel are never the
//   installed product's.
// - Every program gets a home of its own under one temporary folder, which
//   is removed at the end, however the test ends.
// - The app keeps its profile in that folder too.
// - On Windows the dev channel is named after the user, so it is shared
//   with any other dev-mode service this user runs. The test checks first
//   that none is running, and stops if one is.
//
// The window is driven through the test driver. The real mouse, the real
// tray and the real desktop are not touched.

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
    chmodSync,
    existsSync,
    mkdirSync,
    mkdtempSync,
    readdirSync,
    rmSync,
    statSync,
    writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
    type ElectronApplication,
    _electron as electron,
    expect,
    type Page,
    test,
} from "@playwright/test";

/**
 * Off the screen unless this is CI: a test run on someone's computer must
 * not open windows over their work. See `keepHidden` in `src/main/window.ts`.
 */
const HIDDEN = process.env.CI ? {} : { UBC_VPN_TEST_HIDDEN: "1" };

const SERVICE = process.env.UBC_VPN_SYSTEM_SERVICE;
const CLI = process.env.UBC_VPN_SYSTEM_CLI;

/** What the pretend gateway of dev mode accepts. All made up. */
const USERNAME = "alice";
const PASSWORD = "correct-horse-battery";
const CODE = "123456";
const WRONG_PASSWORD = "wrong-password-0000";
/** What the pretend gateway issues. The app must never see it. */
const COOKIE = "Zq7-made-up-0123456789";
const SUBNET = "10.255.0.0/24";
const DOMAIN = "ece.example.test";

const windows = process.platform === "win32";
const screenshotDir = resolve(process.env.SCREENSHOT_DIR ?? "test-results/system-screens");

// Made here and now, with a name nobody can guess beforehand and open to
// this user alone. Short, because a socket's path has to fit in a socket
// address. The workflow looks for anything left with this name.
const root = mkdtempSync(join(windows ? tmpdir() : "/tmp", "ubcvpn-app-"));
const at = (name: string) => join(root, name);
/** The variables that give every program its own home. */
const home: Record<string, string> = windows
    ? { USERPROFILE: at("profile") }
    : {
          HOME: at("home"),
          XDG_CONFIG_HOME: at("config"),
          XDG_RUNTIME_DIR: at("run"),
          TMPDIR: at("tmp"),
      };
/** Where dev mode keeps its files, by the platform crate's table. */
const devFolder = windows
    ? join(at("profile"), "AppData", "Local", "UBC VPN Dev")
    : process.platform === "darwin"
      ? join(at("home"), "Library", "Application Support", "UBC VPN Dev")
      : join(at("config"), "ubc-vpn-dev");

// The installed product's own folder for this user. Nothing may change in it.
const installedFolder = join(
    windows
        ? (process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"))
        : process.platform === "darwin"
          ? join(homedir(), "Library", "Application Support")
          : (process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config")),
    process.platform === "linux" ? "ubc-vpn" : "UBC VPN",
);
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

/** Everything the service and the client wrote, and the app's own output. */
let said = "";
const children: ChildProcess[] = [];
let app: ElectronApplication | undefined;
let page: Page;
let shots = 0;

/** A line in the test's own output: what the workflow reads to see that it ran. */
const tell = (line: string) => void process.stdout.write(`${line}\n`);

function makeHome(): void {
    // Only this user may read or write them: the client refuses a settings
    // folder that its group or anyone else can write to.
    const folders = [...Object.values(home), join(devFolder, "policy"), at("app-profile")];
    if (windows) {
        folders.push(join(at("profile"), "AppData", "Roaming"));
    }
    for (const folder of folders) {
        mkdirSync(folder, { recursive: true, mode: 0o700 });
    }
    if (!windows) {
        // `mode` is cut down by the umask, and covers only the last folder made.
        const all = (folder: string): string[] => [
            folder,
            ...readdirSync(folder, { withFileTypes: true })
                .filter((entry) => entry.isDirectory())
                .flatMap((entry) => all(join(folder, entry.name))),
        ];
        for (const folder of all(root)) {
            chmodSync(folder, 0o700);
        }
    }
    // A developer writes the dev policy by hand; so does this test.
    const pin = `pin-sha256:${"A".repeat(43)}=`;
    writeFileSync(
        join(devFolder, "policy", "policy.json"),
        JSON.stringify({ gateway: "vpn.example.test", pins: [pin] }),
    );
}

/** Runs the client to its end, apart from the app, and returns what it said. */
function client(args: string[], input = ""): { status: number | null; out: string } {
    const run = spawnSync(CLI as string, ["--dev", ...args], {
        env: { ...process.env, ...home },
        input,
        encoding: "utf8",
        timeout: 30_000,
        windowsHide: true,
    });
    said += `${run.stdout}${run.stderr}`;
    return { status: run.status, out: run.stdout.trim() };
}

function startService(): ChildProcess {
    const child = spawn(SERVICE as string, ["--dev"], {
        env: { ...process.env, ...home },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
    });
    children.push(child);
    for (const stream of [child.stdout, child.stderr]) {
        stream?.on("data", (chunk: Buffer) => {
            said += chunk.toString("utf8");
        });
    }
    return child;
}

function stopEverything(): void {
    for (const child of children.splice(0)) {
        child.kill("SIGKILL");
    }
    rmSync(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
// Whatever happens, even if the test runner itself is stopped.
process.on("exit", stopEverything);

async function shoot(name: string): Promise<void> {
    // Let what is arriving arrive: a screenshot half-way through a fade
    // shows a screen nobody ever sees. (What repeats for ever is not waited for.)
    await page.evaluate(() =>
        Promise.all(
            document
                .getAnimations()
                .filter(
                    (animation) => animation.effect?.getComputedTiming().iterations !== Infinity,
                )
                .map((animation) => animation.finished.catch(() => {})),
        ),
    );
    shots += 1;
    const number = String(shots).padStart(2, "0");
    await page.screenshot({ path: join(screenshotDir, `real-${number}-${name}.png`) });
}

const heading = () => page.getByRole("heading", { level: 1 });
const tab = (name: string) =>
    page.getByRole("navigation", { name: "Screens" }).getByRole("button", { name, exact: true });
const button = (name: string) => page.getByRole("button", { name, exact: true });
/** The one field of a login question. */
const field = () => page.locator('main input[name^="login-"]');
/** Which question is on screen: the client's own kind for it. */
const asked = async () => (await field().getAttribute("name"))?.slice("login-".length);

/** The connection states the app has been told of since this was called. */
async function watchStates(): Promise<() => Promise<string[]>> {
    await page.evaluate(() => {
        const seen: string[] = [];
        (window as unknown as { seenStates: string[] }).seenStates = seen;
        // Only changes count: where it stands now is not one.
        let last = "";
        const stateOf = (snapshot: Awaited<ReturnType<typeof window.ubcVpn.getSnapshot>>) =>
            snapshot.state.link === "ready" ? snapshot.state.conn.state : snapshot.state.link;
        const note = (state: string, first: boolean) => {
            if (!first && state !== last) {
                seen.push(state);
            }
            last = state;
        };
        return window.ubcVpn.getSnapshot().then((snapshot) => {
            note(stateOf(snapshot), true);
            window.ubcVpn.onSnapshot((next) => note(stateOf(next), false));
        });
    });
    return () => page.evaluate(() => (window as unknown as { seenStates: string[] }).seenStates);
}

/** Answers one login question, having checked it is the one expected. */
async function answer(kind: string, value: string, shot: string): Promise<void> {
    await expect(field()).toBeFocused();
    expect(await asked()).toBe(kind);
    await page.keyboard.type(value);
    await shoot(shot);
    await page.keyboard.press("Enter");
}

/**
 * Presses Connect and answers the username if it is asked. The client
 * remembers the username after a login that worked, so it is asked the
 * first time only; this passes either way.
 */
async function connectToPassword(round: string): Promise<boolean> {
    await button("Connect").click();
    await expect(field()).toBeVisible();
    const askedUsername = (await asked()) === "username";
    if (askedUsername) {
        await expect(heading()).toHaveText("Your CWL username");
        await answer("username", USERNAME, `${round}-username`);
    }
    await expect(heading()).toHaveText("Your password");
    return askedUsername;
}

test.beforeAll(() => {
    mkdirSync(screenshotDir, { recursive: true });
});

test.afterAll(async () => {
    await app?.close().catch(() => {});
    stopEverything();
    if (test.info().errors.length > 0) {
        // Every value in it is made up, and the test has just failed.
        tell(`What the programs wrote:\n${said}`);
    }
});

test("the app, the client and a dev-mode service work together", async () => {
    if (SERVICE === undefined || CLI === undefined) {
        tell(
            "SKIPPED: app-system: UBC_VPN_SYSTEM_SERVICE and UBC_VPN_SYSTEM_CLI do not name the dev-mode programs",
        );
        test.skip();
        return;
    }
    makeHome();
    tell("STEP: app-system: a home of its own is made");

    // Nothing is running yet. On Windows this also shows that no other
    // dev-mode service of this user holds the channel.
    expect(client(["status"]).status, "a dev-mode service is running already").toBe(3);
    startService();
    // Deliberately not asked through the client: the app is to be the first
    // to reach the service, and so the one that claims it.
    await expect
        .poll(() => said.includes("is running"), { message: "the service starting" })
        .toBe(true);

    tell("STEP: app-system: the service is running");
    app = await electron.launch({
        chromiumSandbox: true,
        timeout: 30_000,
        args: [
            resolve("out/main/index.js"),
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
        ],
        env: {
            ...process.env,
            ...HIDDEN,
            ...home,
            UBC_VPN_CLI: CLI,
            UBC_VPN_DEV: "1",
            UBC_VPN_PROFILE: at("app-profile"),
            // Whatever desktop the test machine runs, behave as on one with a tray.
            XDG_CURRENT_DESKTOP: "e2e",
        },
    });
    const output = app.process();
    for (const stream of [output.stdout, output.stderr]) {
        stream?.on("data", (chunk: Buffer) => {
            said += chunk.toString("utf8");
        });
    }
    tell("STEP: app-system: the app is started");
    page = await app.firstWindow();
    tell("STEP: app-system: the window is open");
    const problems: string[] = [];
    page.on("console", (message) => {
        if (message.type() === "error" || message.type() === "warning") {
            problems.push(message.text());
        }
    });
    page.on("pageerror", (error) => problems.push(error.message));
    // Keep the window clear of the real pointer, which hovers what is under it.
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
    await page.waitForLoadState("domcontentloaded");
    await page.evaluate(() => document.fonts.ready);

    // --- The app finds the service and claims it.
    await expect(heading()).toHaveText("Not connected");
    await expect(page.getByText("Development mode. This is not the real VPN.")).toBeInViewport({
        ratio: 1,
    });
    // This is the production build: it has no log screen yet, and no way
    // to ask for one.
    await expect(tab("Logs")).toHaveCount(0);
    expect(await page.evaluate(() => window.ubcVpn.logs === undefined)).toBe(true);
    const snapshot = await page.evaluate(() => window.ubcVpn.getSnapshot());
    expect(snapshot.development).toBe(true);
    expect(snapshot.state).toEqual({ link: "ready", conn: { state: "disconnected" } });
    await shoot("service-found");
    // The app's profile is in the test's folder, not the product's.
    const userData = await app.evaluate(({ app: electronApp }) => electronApp.getPath("userData"));
    expect(resolve(userData)).toBe(resolve(at("app-profile")));

    // --- Routes: none yet. Add a subnet and a domain, see them checked, save.
    await tab("Routes").click();
    await expect(heading()).toHaveText("Routes");
    await expect(page.getByText("No subnets yet.")).toBeVisible();
    await shoot("routes-empty");
    const save = button("Save routes");
    await button("Add subnet").click();
    await page.keyboard.type("not a subnet");
    const subnet = page.getByLabel("Subnet 1", { exact: true });
    await expect(subnet).toHaveAttribute("aria-invalid", "true");
    await expect(save).toHaveAttribute("aria-disabled", "true");
    await shoot("routes-refused-by-the-client");
    await subnet.fill(SUBNET);
    await expect(subnet).not.toHaveAttribute("aria-invalid");
    await button("Add domain").click();
    await page.keyboard.type(DOMAIN);
    await expect(save).not.toHaveAttribute("aria-disabled");
    await shoot("routes-checked");
    await save.click();
    await expect(page.getByRole("status")).toContainText("Saved.");
    await shoot("routes-saved");
    // The client itself, asked apart from the app, has them.
    const stored = client(["settings", "get", "--json"]);
    expect(stored.status).toBe(0);
    expect(JSON.parse(stored.out).settings.routes).toEqual({
        subnets: [SUBNET],
        dns_domains: [DOMAIN],
    });

    // --- Connect: the questions the pretend gateway asks, then connected.
    await tab("Connection").click();
    await expect(heading()).toHaveText("Not connected");
    let states = await watchStates();
    const askedFirstTime = await connectToPassword("connect");
    await answer("password", PASSWORD, "connect-password");
    await expect(heading()).toHaveText("Your one-time code");
    await answer("code", CODE, "connect-code");
    await expect(heading()).toHaveText("Connected");
    const details = page.getByRole("group", { name: "Connection details" });
    await expect(details).toContainText(SUBNET);
    await expect(details).toContainText(DOMAIN);
    expect(await states()).toEqual(["connecting", "connected"]);
    await shoot("connected");
    expect(client(["status"]).out).toContain("Connected");

    // --- Disconnect.
    states = await watchStates();
    await button("Disconnect").click();
    await expect(heading()).toHaveText("Not connected");
    expect(await states()).toEqual(["disconnecting", "disconnected"]);
    await shoot("disconnected");
    expect(client(["status"]).out).toBe("Disconnected");

    // --- Connect again: the pretend gateway takes a new login after a log-off.
    states = await watchStates();
    const askedSecondTime = await connectToPassword("again");
    await answer("password", PASSWORD, "again-password");
    await answer("code", CODE, "again-code");
    await expect(heading()).toHaveText("Connected");
    expect(await states()).toEqual(["connecting", "connected"]);
    await shoot("connected-again");
    await button("Disconnect").click();
    await expect(heading()).toHaveText("Not connected");
    tell(
        `NOTE: app-system: the username was asked ${askedFirstTime ? "the first time" : "never"}${askedSecondTime ? " and again the second time" : ""}`,
    );

    // --- Cancel at the password: nothing is connected.
    states = await watchStates();
    await connectToPassword("cancel");
    await shoot("cancel-at-the-password");
    await button("Cancel").click();
    await expect(heading()).toHaveText("Not connected");
    await expect(button("Connect")).toBeFocused();
    await shoot("cancelled");
    expect(client(["status"]).out).toBe("Disconnected");

    // --- A wrong password: said plainly, and nothing is connected.
    await connectToPassword("wrong");
    await answer("password", WRONG_PASSWORD, "wrong-password");
    if ((await asked()) === "code") {
        await answer("code", CODE, "wrong-code");
    }
    await expect(heading()).toHaveText("Login refused");
    await shoot("login-refused");
    expect(client(["status"]).out).toBe("Disconnected");
    await button("Back").click();
    await expect(heading()).toHaveText("Not connected");

    // --- The interface saw nothing it should not, and nothing went wrong in it.
    expect(problems).toEqual([]);

    // --- The app quits: its clients go with it, and the service stays.
    await app.close();
    app = undefined;
    expect(client(["status"]).out).toBe("Disconnected");

    // Security rule: no password, code or cookie in anything any program
    // wrote, the app included.
    expect(said).toContain("is running");
    for (const secret of [PASSWORD, CODE, COOKIE, WRONG_PASSWORD]) {
        expect(said.includes(secret), `${secret} was written`).toBe(false);
    }

    // Nothing is left behind, and the installed product's folder is as it was.
    stopEverything();
    expect(existsSync(root)).toBe(false);
    expect(contentsOf(installedFolder)).toEqual(installedFolderBefore);
    tell("RAN: app-system");
});
