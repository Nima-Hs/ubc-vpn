// The tray icon and the taskbar badge, and when each is shown. They are drawn
// in code from the app's mark (`icon/designs.ts`), not shipped as image files,
// so every state and size comes from one description and nothing can go
// stale. This file has no Electron import, so it can be tested on its own.

import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";
import { type TrayKind, type TrayPalette, taskbarBadge, trayIcon } from "./icon/designs";
import { encodePng } from "./icon/formats";
import { draw } from "./icon/raster";

export {
    BUSY_FRAME_MS,
    BUSY_FRAMES,
    COLOUR_PALETTE,
    TEMPLATE_PALETTE,
    TRAY_KINDS,
    type TrayKind,
    type TrayPalette,
} from "./icon/designs";
export { encodePng } from "./icon/formats";

export function trayKind(state: LinkState): TrayKind {
    switch (describe(state).tone) {
        case "idle":
            return "off";
        case "on":
            return "on";
        case "busy":
            return "busy";
        case "attention":
            return "attention";
        case "problem":
            return "problem";
    }
}

/**
 * Whether closing the window should hide it and leave the app in the tray.
 * That is only safe where there is a way back to a hidden window.
 *
 * macOS always has the Dock. Windows always has a tray. On Linux, GNOME has
 * none unless an extension adds one (Ubuntu ships that extension; Debian and
 * Fedora do not), and Electron cannot tell: it creates the icon without
 * error either way. So GNOME without Ubuntu's extension is assumed to have
 * no tray, and there closing the window quits the app.
 */
export function closeHidesWindow(
    platform: NodeJS.Platform,
    env: Record<string, string | undefined>,
    trayCreated: boolean,
): boolean {
    if (platform === "darwin") {
        return true;
    }
    if (!trayCreated) {
        return false;
    }
    if (platform === "linux") {
        const desktop = (env.XDG_CURRENT_DESKTOP ?? "").toLowerCase();
        return !desktop.includes("gnome") || desktop.includes("ubuntu");
    }
    return true;
}

/**
 * Connect, chosen from the tray menu. The window is shown first: connecting
 * starts a login, and a login's question must never wait where nobody is
 * looking.
 */
export function connectFromTray(showWindow: () => void, connect: () => unknown): void {
    showWindow();
    void connect();
}

/** The tray icon as RGBA pixels, `size` wide and high. `frame` steps the working one along. */
export function drawTrayIcon(
    kind: TrayKind,
    palette: TrayPalette,
    size: number,
    frame = 0,
): Buffer {
    return draw(trayIcon(kind, palette, frame), size);
}

export function trayIconPng(kind: TrayKind, palette: TrayPalette, size: number, frame = 0): Buffer {
    return encodePng(drawTrayIcon(kind, palette, size, frame), size);
}

/** The taskbar badge for a state, as a PNG, or `null` for none. */
export function taskbarBadgePng(kind: TrayKind, size: number): Buffer | null {
    return kind === "off" ? null : encodePng(draw(taskbarBadge(kind), size), size);
}
