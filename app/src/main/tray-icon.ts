// The state icon: the tray icon, and on Windows the taskbar button, which
// shows the very same drawing. It is drawn in code from the app's mark
// (`icon/designs.ts`), not shipped as image files, so every state and size
// comes from one description and nothing can go stale. This file has no
// Electron import, so it can be tested on its own.

import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";
import {
    BUSY_FRAME_MS,
    BUSY_FRAMES,
    COLOUR_PALETTE,
    type TrayKind,
    type TrayPalette,
    trayIcon,
} from "./icon/designs";
import { encodePng } from "./icon/formats";
import { draw } from "./icon/raster";

export {
    BUSY_FRAME_MS,
    BUSY_FRAMES,
    COLOUR_PALETTE,
    STATE_PICTURES,
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

/**
 * The sizes, in pixels, of the window icon that follows the state on the
 * Windows taskbar. Windows asks a window for a small icon (title bar, Alt+Tab
 * list) and a large one (taskbar button) at the system's scale: 16 and 32 at
 * 100%, 20 and 40 at 125%, 24 and 48 at 150%, 32 and 64 at 200%. Each is drawn
 * at exactly that size, so none is a blurred resize; 256 is there for
 * anything that asks for more.
 */
export const WINDOW_ICON_SIZES = [16, 20, 24, 32, 40, 48, 64, 256] as const;

/** The window icon for a state: the tray's own drawing, in colour, at one size. */
export function drawWindowIcon(kind: TrayKind, size: number, frame = 0): Buffer {
    return drawTrayIcon(kind, COLOUR_PALETTE, size, frame);
}

/** The `.ico` file a state picture is kept in, in `build/state-icons`. */
export function stateIconFile(kind: TrayKind, frame: number): string {
    return kind === "busy" ? `busy-${frame % BUSY_FRAMES}.ico` : `${kind}.ico`;
}

/** Something that shows the state icon: the tray, the taskbar button. */
export type StateIconPainter = (kind: TrayKind, frame: number) => void;

export interface StateIcons {
    /** Shows a state. The working state steps through its frames until another state is shown. */
    show(kind: TrayKind): void;
    /** Adds a painter, paints it with what is shown now, and returns how to remove it. */
    add(paint: StateIconPainter): () => void;
    /** Paints every painter again with what is shown now. */
    repaint(paint?: StateIconPainter): void;
    /** Whether the working frames are being stepped. */
    readonly stepping: boolean;
    /** Stops for good. */
    dispose(): void;
}

/**
 * One state, one frame count and one timer for every place the state icon
 * appears, so the tray and the taskbar can never show different things. The
 * timer runs only while working and something is there to paint; it stops
 * as soon as the state settles, the last painter goes, or the app quits.
 */
export function createStateIcons(
    timers: { set: (step: () => void, ms: number) => unknown; clear: (timer: unknown) => void } = {
        set: (step, ms) => setInterval(step, ms),
        clear: (timer) => clearInterval(timer as ReturnType<typeof setInterval>),
    },
): StateIcons {
    const painters = new Set<StateIconPainter>();
    let kind: TrayKind | null = null;
    let frame = 0;
    let timer: unknown;
    let disposed = false;

    const paintAll = () => {
        if (kind === null) {
            return;
        }
        for (const paint of painters) {
            paint(kind, frame);
        }
    };
    const stop = () => {
        if (timer !== undefined) {
            timers.clear(timer);
            timer = undefined;
        }
    };
    const startIfWorking = () => {
        if (timer === undefined && !disposed && kind === "busy" && painters.size > 0) {
            timer = timers.set(() => {
                frame = (frame + 1) % BUSY_FRAMES;
                paintAll();
            }, BUSY_FRAME_MS);
        }
    };

    return {
        show(next) {
            if (disposed || next === kind) {
                return;
            }
            stop();
            kind = next;
            frame = 0;
            paintAll();
            startIfWorking();
        },
        add(paint) {
            if (disposed) {
                return () => {};
            }
            painters.add(paint);
            if (kind !== null) {
                paint(kind, frame);
            }
            startIfWorking();
            return () => {
                painters.delete(paint);
                if (painters.size === 0) {
                    stop();
                }
            };
        },
        repaint(paint) {
            if (kind === null) {
                return;
            }
            if (paint === undefined) {
                paintAll();
            } else {
                paint(kind, frame);
            }
        },
        get stepping() {
            return timer !== undefined;
        },
        dispose() {
            disposed = true;
            stop();
            painters.clear();
        },
    };
}
