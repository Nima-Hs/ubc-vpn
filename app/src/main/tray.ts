import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";
import { Menu, type NativeImage, nativeImage, Tray } from "electron";
import {
    COLOUR_PALETTE,
    TEMPLATE_PALETTE,
    type TrayKind,
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

export function trayImage(kind: TrayKind, size = 16): NativeImage {
    const image = nativeImage.createEmpty();
    for (const scaleFactor of [1, 2, 3]) {
        image.addRepresentation({
            scaleFactor,
            width: size,
            height: size,
            buffer: trayIconPng(kind, mac ? TEMPLATE_PALETTE : COLOUR_PALETTE, size * scaleFactor),
        });
    }
    image.setTemplateImage(mac);
    return image;
}

/**
 * Puts the app in the tray and keeps the icon, tooltip and menu in step with
 * the state. Returns `null` if the icon could not be created. A desktop with
 * no tray does not always say so; see `closeHidesWindow`.
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

    const update = (state: LinkState) => {
        const copy = describe(state);
        tray.setImage(trayImage(trayKind(state)));
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
    return { update, destroy: () => tray.destroy() };
}
