import { join } from "node:path";
import { WINDOW_BACKGROUND } from "@shared/api";
import { BrowserWindow, screen } from "electron";
import { webPreferences } from "./security";

/** A compact, fixed-size window: the app lives in the tray. */
const WIDTH = 380;
const HEIGHT = 620;

export function createWindow(
    entryUrl: string,
    icon: Electron.NativeImage,
    developmentBuild: boolean,
): BrowserWindow {
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
        webPreferences: webPreferences(join(__dirname, "../preload/index.js"), developmentBuild),
    });
    enableKeyboardZoom(window);
    window.once("ready-to-show", () => window.show());
    void window.loadURL(entryUrl);
    return window;
}

/** How far the interface can be enlarged, one key press at a time. */
export const ZOOM_STEPS = [1, 1.1, 1.25, 1.5, 1.75, 2];

/**
 * Ctrl or Cmd with plus, minus and zero enlarge, shrink and reset the
 * interface, as they do in a browser. The window grows with its contents, as
 * far as the screen allows; past that, the screen scrolls.
 */
function enableKeyboardZoom(window: BrowserWindow): void {
    let step = 0;
    window.webContents.on("before-input-event", (event, input) => {
        if (input.type !== "keyDown" || !(input.control || input.meta) || input.alt) {
            return;
        }
        let next: number;
        if (input.key === "0") {
            next = 0;
        } else if (input.key === "=" || input.key === "+") {
            next = Math.min(step + 1, ZOOM_STEPS.length - 1);
        } else if (input.key === "-" || input.key === "_") {
            next = Math.max(step - 1, 0);
        } else {
            return;
        }
        event.preventDefault();
        step = next;
        const factor = ZOOM_STEPS[step] ?? 1;
        const room = screen.getDisplayMatching(window.getBounds()).workAreaSize;
        // A fixed-size window refuses a new size unless it is resizable for the moment.
        window.setResizable(true);
        window.setContentSize(
            Math.min(Math.round(WIDTH * factor), room.width),
            Math.min(Math.round(HEIGHT * factor), room.height),
        );
        window.setResizable(false);
        window.webContents.setZoomFactor(factor);
    });
}

export function showWindow(window: BrowserWindow): void {
    if (window.isMinimized()) {
        window.restore();
    }
    window.show();
    window.focus();
}
