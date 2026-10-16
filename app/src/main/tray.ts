import { join } from "node:path";
import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import { app, type BrowserWindow, Menu, type NativeImage, nativeImage, Tray } from "electron";
import { appIcon } from "./icon/designs";
import { encodePng } from "./icon/formats";
import { draw } from "./icon/raster";
import {
    COLOUR_PALETTE,
    type StateIconPainter,
    type StateIcons,
    stateIconFile,
    TEMPLATE_PALETTE,
    type TrayKind,
    trayIconPng,
    trayKind,
} from "./tray-icon";
import { type TrayActions, trayMenu } from "./tray-menu";

export type { TrayActions } from "./tray-menu";

const mac = process.platform === "darwin";

export function trayImage(kind: TrayKind, frame = 0, size = 16): NativeImage {
    const image = nativeImage.createEmpty();
    for (const scaleFactor of [1, 2, 3]) {
        image.addRepresentation({
            scaleFactor,
            width: size,
            height: size,
            buffer: trayIconPng(
                kind,
                mac ? TEMPLATE_PALETTE : COLOUR_PALETTE,
                size * scaleFactor,
                frame,
            ),
        });
    }
    image.setTemplateImage(mac);
    return image;
}

/** The app icon, for the window: the same drawing as the installed program's. */
export function appImage(): NativeImage {
    const image = nativeImage.createEmpty();
    for (const scaleFactor of [1, 2, 4]) {
        const size = 64 * scaleFactor;
        image.addRepresentation({
            scaleFactor,
            width: 64,
            height: 64,
            buffer: encodePng(draw(appIcon(size), size), size),
        });
    }
    return image;
}

/** Where the state icon files are: beside the app once installed, in build/ before. */
function stateIconFolder(): string {
    return app.isPackaged
        ? join(process.resourcesPath, "state-icons")
        : join(__dirname, "../../build/state-icons");
}

const windowImages = new Map<string, NativeImage>();

/**
 * The state icon for a window: the tray's drawing, read from its `.ico`.
 * From a file, Windows is handed each size it asks for exactly as drawn; an
 * image made in memory gives it one size, which it would resize itself.
 */
export function windowStateImage(kind: TrayKind, frame: number): NativeImage {
    const name = stateIconFile(kind, frame);
    let image = windowImages.get(name);
    if (image === undefined) {
        image = nativeImage.createFromPath(join(stateIconFolder(), name));
        windowImages.set(name, image);
    }
    return image;
}

/**
 * Makes the window's taskbar button show the state icon, the same picture as
 * the tray, stepping with it while working. Windows only. It follows while the
 * window is shown; hidden or closed, it lets go, so nothing is stepped for a
 * button that is not there. The program's own icon, on the Start menu and in
 * the install folder, stays the app icon.
 */
export function followStateOnTaskbar(window: BrowserWindow, icons: StateIcons): void {
    if (process.platform !== "win32") {
        return;
    }
    let stop: (() => void) | null = null;
    const paint: StateIconPainter = (kind, frame) => {
        if (!window.isDestroyed()) {
            window.setIcon(windowStateImage(kind, frame));
        }
    };
    const follow = () => {
        stop ??= icons.add(paint);
    };
    const letGo = () => {
        stop?.();
        stop = null;
    };
    window.on("show", follow);
    window.on("hide", letGo);
    window.on("closed", letGo);
    if (window.isVisible()) {
        follow();
    }
}

/**
 * Puts the app in the tray and keeps the icon, tooltip and menu in step with
 * the state. Returns `null` if the icon could not be created. A desktop with
 * no tray does not always say so; see `closeHidesWindow`.
 *
 * The icon is painted by `icons`, which the taskbar button shares, so both
 * show the same state and the same working frame. The pictures are drawn
 * once and kept.
 */
export function createTray(
    actions: TrayActions,
    initial: LinkState,
    icons: StateIcons,
): {
    update(state: LinkState): void;
    /** The profiles as they now are, for the menu's list of them. */
    setProfiles(view: ProfilesView): void;
    destroy(): void;
} | null {
    let tray: Tray;
    try {
        tray = new Tray(trayImage(trayKind(initial)));
    } catch {
        return null;
    }

    const images = new Map<string, NativeImage>();
    const imageFor = (kind: TrayKind, frame: number) => {
        const key = `${kind}-${frame}`;
        let image = images.get(key);
        if (image === undefined) {
            image = trayImage(kind, frame);
            images.set(key, image);
        }
        return image;
    };
    const stopPainting = icons.add((kind, frame) => tray.setImage(imageFor(kind, frame)));

    let state = initial;
    let profiles: ProfilesView | null = null;
    const rebuild = () => {
        tray.setToolTip(`UBC VPN: ${describe(state).title}`);
        tray.setContextMenu(Menu.buildFromTemplate(trayMenu(state, profiles, actions)));
    };
    const update = (next: LinkState) => {
        state = next;
        rebuild();
    };

    // On Windows and Linux a click brings the window forward; macOS opens the
    // menu. A click never hides the window: clicking the tray takes focus
    // from the window first, so "is it in front?" cannot be asked reliably.
    if (!mac) {
        tray.on("click", actions.showWindow);
    }

    update(initial);
    return {
        update,
        setProfiles: (view) => {
            profiles = view;
            rebuild();
        },
        destroy: () => {
            stopPainting();
            tray.destroy();
        },
    };
}
