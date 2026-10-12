import { join } from "node:path";
import { DEMO_IPC } from "@shared/api";
import { app, type BrowserWindow, Menu, protocol, session } from "electron";
import { bridgeCommand, connectCommand } from "./channel/cli";
import { ConnectRunner } from "./channel/connect";
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
import { closeHidesWindow } from "./tray-icon";
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

/** Whether the interface can show a login's questions yet. */
const LOGIN_SCREENS_READY = false;

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

    let link: ServiceLink;
    let login: LoginFactory | undefined;
    let registerDemo: ((window: BrowserWindow) => void) | null = null;
    if (__DEMO__) {
        const { createDemoLink, DEMO_SCENARIOS } = await import("./demo/demo-link");
        const stepMs = Number(process.env.UBC_VPN_DEMO_STEP_MS);
        const demo = createDemoLink(Number.isFinite(stepMs) && stepMs > 0 ? stepMs : undefined);
        link = demo;
        registerDemo = (window) => {
            handleFromInterface(window, devServerUrl, DEMO_IPC.listScenarios, () => [
                ...DEMO_SCENARIOS,
            ]);
            handleFromInterface(window, devServerUrl, DEMO_IPC.setScenario, (name) => {
                if (typeof name === "string") {
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
    // The command-line client does the logging in. The screens that show its
    // questions come in the next change; until they are there, Connect says
    // that this build cannot log in, so nobody is left at a prompt they
    // cannot see.
    const controller = new Controller(link, LOGIN_SCREENS_READY ? login : undefined);

    // The default menu offers reload, zoom and developer tools. A built app
    // has no use for them; macOS keeps the entries every Mac app has.
    const menu = applicationMenu(process.platform, developmentBuild);
    if (menu !== undefined) {
        Menu.setApplicationMenu(menu === null ? null : Menu.buildFromTemplate(menu));
    }

    const window = createWindow(entryUrl, trayImage("on", 64), developmentBuild);
    registerIpc(window, controller, devServerUrl);
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
            // An action that does not start explains itself in the window.
            connect: () => void controller.connect().then(showIfNotice),
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
        tray?.destroy();
        controller.dispose();
    });

    // If the interface's process dies, start it again, but not in a loop.
    let restarts = 0;
    window.webContents.on("render-process-gone", () => {
        if (!quitting && restarts++ < 3) {
            window.reload();
        }
    });
}
