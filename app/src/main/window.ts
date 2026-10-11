import { join } from "node:path";
import { WINDOW_BACKGROUND } from "@shared/api";
import { BrowserWindow } from "electron";

/** A compact, fixed-size window: the app lives in the tray. */
const WIDTH = 380;
const HEIGHT = 620;

export function createWindow(entryUrl: string, icon: Electron.NativeImage): BrowserWindow {
    const mac = process.platform === "darwin";
    const window = new BrowserWindow({
        width: WIDTH,
        height: HEIGHT,
        useContentSize: true,
        resizable: false,
        maximizable: false,
        fullscreenable: false,
        show: false,
        title: "UBC VPN",
        icon,
        backgroundColor: WINDOW_BACKGROUND,
        // The interface draws its own title bar so it looks the same on every
        // OS. macOS keeps its own window buttons, placed inside that bar.
        ...(mac ? { titleBarStyle: "hiddenInset" as const } : { frame: false }),
        webPreferences: {
            preload: join(__dirname, "../preload/index.js"),
            contextIsolation: true,
            sandbox: true,
            nodeIntegration: false,
            webSecurity: true,
            webviewTag: false,
            spellcheck: false,
            devTools: import.meta.env.DEV,
        },
    });
    window.once("ready-to-show", () => window.show());
    void window.loadURL(entryUrl);
    return window;
}

export function showWindow(window: BrowserWindow): void {
    if (window.isMinimized()) {
        window.restore();
    }
    window.show();
    window.focus();
}
