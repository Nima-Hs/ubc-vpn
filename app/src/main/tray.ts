import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";
import { type BrowserWindow, Menu, type NativeImage, nativeImage, Tray } from "electron";
import { appIcon } from "./icon/designs";
import { encodePng } from "./icon/formats";
import { draw } from "./icon/raster";
import {
    BUSY_FRAME_MS,
    BUSY_FRAMES,
    COLOUR_PALETTE,
    TEMPLATE_PALETTE,
    type TrayKind,
    taskbarBadgePng,
    trayIconPng,
    trayKind,
} from "./tray-icon";

export interface TrayActions {
    showWindow(): void;
    connect(): void;
    disconnect(): void;
    retry(): void;
    quit(): void;
}

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

/**
 * Shows the state on the window's taskbar button, as a small badge, while the
 * window is open. Windows only; elsewhere the tray says it.
 */
export function showStateOnTaskbar(window: BrowserWindow, state: LinkState): void {
    if (process.platform !== "win32" || window.isDestroyed()) {
        return;
    }
    const kind = trayKind(state);
    const badge = taskbarBadgePng(kind, 32);
    window.setOverlayIcon(
        badge === null ? null : nativeImage.createFromBuffer(badge, { scaleFactor: 2 }),
        badge === null ? "" : describe(state).title,
    );
}

/**
 * Puts the app in the tray and keeps the icon, tooltip and menu in step with
 * the state. Returns `null` if the icon could not be created. A desktop with
 * no tray does not always say so; see `closeHidesWindow`.
 *
 * While something is working the icon steps through a few pictures; it stops
 * as soon as the state settles. The pictures are drawn once and kept.
 */
export function createTray(
    actions: TrayActions,
    initial: LinkState,
): { update(state: LinkState): void; destroy(): void } | null {
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
    let shown: TrayKind | null = null;
    let stepping: ReturnType<typeof setInterval> | undefined;
    const showKind = (kind: TrayKind) => {
        if (kind === shown) {
            return;
        }
        shown = kind;
        clearInterval(stepping);
        stepping = undefined;
        tray.setImage(imageFor(kind, 0));
        if (kind === "busy") {
            let frame = 0;
            stepping = setInterval(() => {
                frame = (frame + 1) % BUSY_FRAMES;
                tray.setImage(imageFor("busy", frame));
            }, BUSY_FRAME_MS);
        }
    };

    const update = (state: LinkState) => {
        const copy = describe(state);
        showKind(trayKind(state));
        tray.setToolTip(`UBC VPN: ${copy.title}`);
        const run = {
            connect: actions.connect,
            disconnect: actions.disconnect,
            retry: actions.retry,
        };
        tray.setContextMenu(
            Menu.buildFromTemplate([
                { label: copy.title, enabled: false },
                { type: "separator" },
                { label: "Show UBC VPN", click: actions.showWindow },
                ...(copy.action === null
                    ? []
                    : [
                          {
                              label: copy.action.label,
                              enabled: !copy.working,
                              click: run[copy.action.kind],
                          },
                      ]),
                { type: "separator" },
                { label: "Quit UBC VPN", click: actions.quit },
            ]),
        );
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
        destroy: () => {
            clearInterval(stepping);
            tray.destroy();
        },
    };
}
