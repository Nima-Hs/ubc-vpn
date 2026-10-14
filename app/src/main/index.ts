import { join } from "node:path";
import { DEMO_IPC } from "@shared/api";
import { app, type BrowserWindow, clipboard, Menu, protocol, session } from "electron";
import { bridgeCommand, connectCommand, settingsCommand } from "./channel/cli";
import { SettingsRunner, type SettingsService } from "./channel/settings";
import { Controller, type LoginFactory } from "./controller";
import { handleFromInterface, registerIpc } from "./ipc";
import { createServiceLink, type ServiceLink } from "./link";
import { clientLogin } from "./login";
import type { LogFeed } from "./logs/book";
import { profileFolder } from "./profile";
import { holdQuitForCancel, stopForQuit } from "./quit";
import {
    allowsRemoteDebugging,
    applicationMenu,
    devServerUrlFor,
    refuseRemoteDebugging,
    registerAppScheme,
    secureSession,
} from "./security";
import { createTray, trayImage } from "./tray";
import { closeHidesWindow, connectFromTray } from "./tray-icon";
import { createWindow, keepHidden, showWindow } from "./window";

// First of all, before the profile is read or anything is written to it.
// Electron's own choice is the folder that holds the user's settings file,
// which belongs to the command-line client.
app.setPath("userData", profileFolder(app, process));

// How the client is started, and with it whether this run is in dev mode.
// Decided once, and everything that depends on dev mode takes it from here:
// what the client is told, the mark in the window, and whether the run may
// be debugged. They cannot then disagree, and a run that may be debugged is
// never one whose client talks to the real service.
const bridge = bridgeCommand(app, process);

registerAppScheme(protocol);
// Before anything else reads the command line: no fuse turns these switches
// off, so the app takes them off itself.
refuseRemoteDebugging(
    app.commandLine,
    allowsRemoteDebugging({
        isPackaged: app.isPackaged,
        demo: __DEMO__,
        development: import.meta.env.DEV,
        devMode: bridge.dev,
    }),
);

// One copy of the app at a time: a second launch brings the first one's
// window forward and exits.
if (app.requestSingleInstanceLock()) {
    void app.whenReady().then(start);
} else {
    app.quit();
}

async function start(): Promise<void> {
    // Set only by `electron-vite dev`, and read only in development builds.
    // Decided once, here. Everything that differs in development takes
    // this one value: the dev server, the menu and developer tools.
    const developmentBuild = import.meta.env.DEV;
    const devServerUrl = devServerUrlFor(developmentBuild, process.env);
    const entryUrl = secureSession(
        { app, protocol, session: session.defaultSession },
        join(__dirname, "../renderer"),
        devServerUrl,
    );

    // Whichever kind of build this is, it has a service to follow and a way
    // to log in, and both go to the one controller below.
    let link: ServiceLink;
    let login: LoginFactory;
    let demoSettings: SettingsService | undefined;
    let logFeed: LogFeed | undefined;
    let registerDemo: ((window: BrowserWindow) => void) | null = null;
    if (__DEMO__) {
        const { createDemoLink, DEMO_SCENARIOS } = await import("./demo/demo-link");
        const { createDemoLogin, DEMO_LOGIN_SCENARIOS } = await import("./demo/demo-login");
        const { createDemoSettings, DEMO_SETTINGS_SCENARIOS } = await import(
            "./demo/demo-settings"
        );
        const { createDemoLogs, DEMO_LOG_SCENARIOS } = await import("./demo/demo-logs");
        const fakeSettings = createDemoSettings();
        demoSettings = fakeSettings;
        const stepMs = Number(process.env.UBC_VPN_DEMO_STEP_MS);
        const step = Number.isFinite(stepMs) && stepMs > 0 ? stepMs : undefined;
        const fakeLogs = createDemoLogs(step);
        logFeed = fakeLogs;
        const demo = createDemoLink(step);
        link = demo;
        let demoLogin: ReturnType<typeof createDemoLogin> | undefined;
        login = (onState) => {
            demoLogin = createDemoLogin(onState, () => void demo.connect(), step);
            return demoLogin;
        };
        registerDemo = (window) => {
            handleFromInterface(window, devServerUrl, DEMO_IPC.listScenarios, () => [
                ...DEMO_SCENARIOS,
                ...DEMO_LOGIN_SCENARIOS,
                ...DEMO_SETTINGS_SCENARIOS,
                ...DEMO_LOG_SCENARIOS,
            ]);
            handleFromInterface(window, devServerUrl, DEMO_IPC.setScenario, (name) => {
                if (typeof name === "string") {
                    // A login state, or a connection state with no login under way.
                    demoLogin?.setScenario(name);
                    demo.setScenario(name);
                    fakeSettings.setScenario(name);
                    fakeLogs.setScenario(name);
                }
            });
        };
    } else {
        // A login given up after the service accepted it is undone through
        // the link, which is made just below and is there before any login.
        login = clientLogin(
            {
                disconnect: () => link.disconnect(),
                getState: () => link.getState(),
                subscribe: (listener) => link.subscribe(listener),
            },
            connectCommand(app, process),
        );
        link = createServiceLink({
            ...bridge,
            appVersion: app.getVersion(),
            // The text is fixed and holds nothing that was sent or received.
            // biome-ignore lint/suspicious/noConsole: the app's only log line, for a bug in the app itself.
            onFault: (fault) => console.error(`ubc-vpn: ${fault}`),
        });
    }
    // Shown in the window for as long as it is on, so that a session with a
    // pretend service is never taken for a real one.
    const controller = new Controller(link, login, bridge.dev);
    // The user's settings are read and written by the command-line client.
    // A demo build has a fake of its own, made above.
    const settings: SettingsService =
        demoSettings ?? new SettingsRunner(settingsCommand(app, process));

    // The default menu offers reload, zoom and developer tools. A built app
    // has no use for them; macOS keeps the entries every Mac app has.
    const menu = applicationMenu(process.platform, developmentBuild);
    if (menu !== undefined) {
        Menu.setApplicationMenu(menu === null ? null : Menu.buildFromTemplate(menu));
    }

    // Only for the end-to-end tests: the window is never put on screen.
    const hidden = keepHidden(app, process);
    const window = createWindow(entryUrl, trayImage("on", 64), developmentBuild, hidden);
    registerIpc(window, controller, settings, devServerUrl);
    // The log screen: in no production build until its contract is on main.
    // Until then the only service that can be asked for its log is the
    // demo's pretend one.
    if (__LOGS__ && logFeed !== undefined) {
        const { registerLogs } = await import("./logs/ipc");
        registerLogs(window, devServerUrl, logFeed, {
            appVersion: app.getVersion(),
            platform: process.platform,
            arch: process.arch,
            link: () => controller.getSnapshot().state,
            // Only reached through the gate in `logs/ipc.ts`.
            copy: (text) => clipboard.writeText(text),
            focused: () => window.isFocused(),
        });
    }
    registerDemo?.(window);

    let quitting = false;
    const quit = () => {
        quitting = true;
        app.quit();
    };
    const show = () => {
        if (!hidden) {
            showWindow(window);
        }
    };

    // Kept off the screen for a test run, the tray icon included. Without a
    // tray, closing the window quits, as on a desktop that has none.
    const tray = hidden
        ? null
        : createTray(
              {
                  showWindow: show,
                  connect: () => connectFromTray(show, () => controller.connect()),
                  // An action that does not start explains itself in the window.
                  disconnect: () => void controller.disconnect().then(showIfNotice),
                  retry: () => controller.retry(),
                  quit,
              },
              controller.getSnapshot().state,
          );
    function showIfNotice(): void {
        if (controller.getSnapshot().notice !== null) {
            show();
        }
    }
    controller.subscribe((snapshot) => tray?.update(snapshot.state));

    // Closing the window leaves the app running in the tray, but only where
    // there is a way back to a hidden window. Elsewhere closing quits.
    const closeHides = closeHidesWindow(process.platform, process.env, tray !== null);
    controller.setCloseHides(closeHides);
    // A login does not carry on behind a window the user has put away:
    // nobody would be there to answer it.
    window.on("hide", () => controller.cancelLogin());
    window.on("close", (event) => {
        if (!quitting && closeHides) {
            event.preventDefault();
            window.hide();
        }
    });
    // A login the user gave up is wound up before the app goes.
    const holdQuit = holdQuitForCancel(controller, () => app.quit());
    app.on("before-quit", (event) => {
        quitting = true;
        holdQuit(event);
    });
    app.on("second-instance", show);
    app.on("activate", show);
    app.on("window-all-closed", () => app.quit());
    app.on("will-quit", () => stopForQuit(controller, settings, tray));

    // If the interface's process dies, start it again, but not in a loop.
    let restarts = 0;
    window.webContents.on("render-process-gone", () => {
        if (!quitting && restarts++ < 3) {
            window.reload();
        }
    });
}
