import { join } from "node:path";
import { DEMO_IPC } from "@shared/api";
import { app, type BrowserWindow, Menu, protocol, session } from "electron";
import { bridgeCommand, connectCommand, settingsCommand } from "./channel/cli";
import { ConnectRunner } from "./channel/connect";
import { SettingsRunner, type SettingsService } from "./channel/settings";
import { Controller, type LoginFactory } from "./controller";
import { handleFromInterface, registerIpc } from "./ipc";
import { createServiceLink, type ServiceLink } from "./link";
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
import { createWindow, showWindow } from "./window";

registerAppScheme(protocol);
// Before anything else reads the command line: no fuse turns these switches
// off, so the app takes them off itself.
refuseRemoteDebugging(
    app.commandLine,
    allowsRemoteDebugging({
        isPackaged: app.isPackaged,
        demo: __DEMO__,
        development: import.meta.env.DEV,
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
    let registerDemo: ((window: BrowserWindow) => void) | null = null;
    if (__DEMO__) {
        const { createDemoLink, DEMO_SCENARIOS } = await import("./demo/demo-link");
        const { createDemoLogin, DEMO_LOGIN_SCENARIOS } = await import("./demo/demo-login");
        const { createDemoSettings } = await import("./demo/demo-settings");
        demoSettings = createDemoSettings();
        const stepMs = Number(process.env.UBC_VPN_DEMO_STEP_MS);
        const step = Number.isFinite(stepMs) && stepMs > 0 ? stepMs : undefined;
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
            ]);
            handleFromInterface(window, devServerUrl, DEMO_IPC.setScenario, (name) => {
                if (typeof name === "string") {
                    // A login state, or a connection state with no login under way.
                    demoLogin?.setScenario(name);
                    demo.setScenario(name);
                }
            });
        };
    } else {
        login = (onState) => new ConnectRunner({ ...connectCommand(app, process), onState });
        link = createServiceLink({
            ...bridgeCommand(app, process),
            appVersion: app.getVersion(),
            // The text is fixed and holds nothing that was sent or received.
            // biome-ignore lint/suspicious/noConsole: the app's only log line, for a bug in the app itself.
            onFault: (fault) => console.error(`ubc-vpn: ${fault}`),
        });
    }
    const controller = new Controller(link, login);
    // The user's settings are read and written by the command-line client.
    // A demo build has a fake of its own, made above.
    const settings: SettingsService =
        demoSettings ?? new SettingsRunner({ command: settingsCommand(app, process) });

    // The default menu offers reload, zoom and developer tools. A built app
    // has no use for them; macOS keeps the entries every Mac app has.
    const menu = applicationMenu(process.platform, developmentBuild);
    if (menu !== undefined) {
        Menu.setApplicationMenu(menu === null ? null : Menu.buildFromTemplate(menu));
    }

    const window = createWindow(entryUrl, trayImage("on", 64), developmentBuild);
    registerIpc(window, controller, settings, devServerUrl);
    registerDemo?.(window);

    let quitting = false;
    const quit = () => {
        quitting = true;
        app.quit();
    };
    const show = () => showWindow(window);

    const tray = createTray(
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
    app.on("before-quit", () => {
        quitting = true;
    });
    app.on("second-instance", show);
    app.on("activate", show);
    app.on("window-all-closed", () => app.quit());
    app.on("will-quit", () => {
        controller.dispose();
        settings.stop();
        tray?.destroy();
    });

    // If the interface's process dies, start it again, but not in a loop.
    let restarts = 0;
    window.webContents.on("render-process-gone", () => {
        if (!quitting && restarts++ < 3) {
            window.reload();
        }
    });
}
