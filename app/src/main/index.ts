import { join } from "node:path";
import { DEMO_IPC } from "@shared/api";
import { app, type BrowserWindow, Menu, protocol, session } from "electron";
import { serviceChannelPath } from "./channel/endpoint";
import { Controller } from "./controller";
import { handleFromInterface, registerIpc } from "./ipc";
import { createServiceLink, type ServiceLink } from "./link";
import { applicationMenu, devServerUrlFor, registerAppScheme, secureSession } from "./security";
import { createTray, trayImage } from "./tray";
import { closeHidesWindow } from "./tray-icon";
import { createWindow, showWindow } from "./window";

registerAppScheme(protocol);

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

    let link: ServiceLink;
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
        link = createServiceLink({ path: serviceChannelPath(), appVersion: app.getVersion() });
    }
    const controller = new Controller(link);

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
