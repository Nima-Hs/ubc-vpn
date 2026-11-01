// Logging in: the answers the main process takes, the password field, where
// a password is never kept, and giving a login up.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import {
    action,
    app,
    heading,
    launchArgs,
    launchEnv,
    launchOptions,
    newProfile,
    offScreen,
    page,
    scenario,
    shoot,
    useApp,
} from "./fixture";
import { launchApp } from "./launch";

useApp();

test("a login answer is checked before the main process takes it", async () => {
    // What the main process's handler is given, and whether it took it: its
    // check throws for anything it refuses. Put back at the end.
    await app.evaluate(({ ipcMain }) => {
        type Handler = (event: unknown, ...args: unknown[]) => unknown;
        const invoke = (ipcMain as unknown as { _invokeHandlers: Map<string, Handler> })
            ._invokeHandlers;
        const original = invoke.get("login:answer") as Handler;
        const seen: string[] = [];
        Object.assign(globalThis, { answerSeen: seen, answerHandler: original });
        // Awaited, so a refusal is caught whether the check throws or rejects.
        invoke.set("login:answer", async (event, ...args) => {
            try {
                const result = await original(event, ...args);
                seen.push(JSON.stringify(["taken", ...args]));
                return result;
            } catch (error) {
                seen.push(JSON.stringify(["refused", typeof args[0], typeof args[1]]));
                throw error;
            }
        });
    });
    // The one function that takes arguments. Anything but a prompt id and
    // text is refused, whatever the page sends. A value Electron cannot send
    // at all is refused before it leaves the page: as a rejected promise up
    // to Electron 44, and thrown at once by `ipcRenderer.invoke` from 45,
    // which the preload turns back into a rejected promise. Both count.
    const sent = await page.evaluate(async () => {
        const answer = window.ubcVpn.answerPrompt as (...args: unknown[]) => Promise<void>;
        const outcome = async (...args: unknown[]) => {
            let call: unknown;
            try {
                call = answer(...args);
            } catch {
                return "thrown";
            }
            if (!(call instanceof Promise)) {
                return "no promise";
            }
            try {
                await call;
                return "taken";
            } catch {
                return "refused";
            }
        };
        return {
            proper: await outcome(1, "an answer"),
            noText: await outcome(1, { toString: () => "an answer" }),
            noId: await outcome("1", "an answer"),
            tooLong: await outcome(1, "x".repeat(5000)),
        };
    });
    const seen = await app.evaluate(({ ipcMain }) => {
        type Handler = (event: unknown, ...args: unknown[]) => unknown;
        const kept = globalThis as unknown as { answerSeen: string[]; answerHandler: Handler };
        (ipcMain as unknown as { _invokeHandlers: Map<string, Handler> })._invokeHandlers.set(
            "login:answer",
            kept.answerHandler,
        );
        return kept.answerSeen;
    });
    // Refused as a rejected promise, never as an exception the page did not expect.
    expect(sent).toEqual({
        proper: "taken",
        noText: "refused",
        noId: "refused",
        tooLong: "refused",
    });
    // Only the proper answer was taken. The one that could not be sent never
    // reached the main process; the others reached it and were refused.
    expect(seen).toEqual([
        JSON.stringify(["taken", 1, "an answer"]),
        JSON.stringify(["refused", "string", "string"]),
        JSON.stringify(["refused", "number", "string"]),
    ]);
    // Routes are checked the same way before anything is started for them.
    const routes = await page.evaluate(async () => {
        const save = window.ubcVpn.saveRoutes as (...args: unknown[]) => Promise<unknown>;
        const check = window.ubcVpn.checkRoutes as (...args: unknown[]) => Promise<unknown>;
        // Thrown or rejected, a refusal is a refusal.
        const outcome = async (call: () => Promise<unknown>) => {
            try {
                await call();
                return "taken";
            } catch {
                return "refused";
            }
        };
        return {
            proper: await outcome(() => check({ subnets: ["203.0.113.0/24"], dns_domains: [] })),
            extraField: await outcome(() =>
                save({ subnets: [], dns_domains: [], path: "/etc/passwd" }),
            ),
            notLists: await outcome(() => save({ subnets: "203.0.113.0/24", dns_domains: [] })),
            notText: await outcome(() => check({ subnets: [42], dns_domains: [] })),
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
    // The button sits inside the field, at its end and in its middle.
    const fieldBox = await field.boundingBox();
    const buttonBox = await show.boundingBox();
    expect(fieldBox).not.toBeNull();
    expect(buttonBox).not.toBeNull();
    if (fieldBox !== null && buttonBox !== null) {
        expect(buttonBox.y).toBeGreaterThanOrEqual(fieldBox.y);
        expect(buttonBox.y + buttonBox.height).toBeLessThanOrEqual(fieldBox.y + fieldBox.height);
        expect(buttonBox.x).toBeGreaterThanOrEqual(fieldBox.x);
        expect(buttonBox.x + buttonBox.width).toBeLessThanOrEqual(fieldBox.x + fieldBox.width);
        const middle = (box: { y: number; height: number }) => box.y + box.height / 2;
        expect(Math.abs(middle(buttonBox) - middle(fieldBox))).toBeLessThanOrEqual(1);
    }
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
        // Every message the main process sends the window, from here on: what
        // it pushes, and every reply to a call the window makes.
        const handlers = await other.evaluate(({ BrowserWindow, ipcMain }) => {
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
            // Electron keeps each `ipcMain.handle` handler in this map. Each is
            // wrapped, so what it answers is recorded on its way back.
            type Handler = (event: unknown, ...args: unknown[]) => unknown;
            const invoke = (ipcMain as unknown as { _invokeHandlers?: Map<string, Handler> })
                ._invokeHandlers;
            for (const [channel, handler] of invoke ?? []) {
                invoke?.set(channel, async (event, ...args) => {
                    const reply = await handler(event, ...args);
                    recorded.push(JSON.stringify(["reply", channel, reply ?? null]));
                    return reply;
                });
            }
            return invoke?.size ?? 0;
        });
        // The replies are recorded: there are handlers, and they were wrapped.
        expect(handlers).toBeGreaterThan(5);
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
    // The answer's own call was among the replies recorded.
    expect(sent.some((message) => message.startsWith('["reply","login:answer"'))).toBe(true);
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
        "Split tunnel: traffic to 2 UBC subnets goes through the VPN",
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
