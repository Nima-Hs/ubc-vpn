import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";
import { Menu, type NativeImage, nativeImage, nativeTheme, Tray } from "electron";
import { colourPalette, TEMPLATE_PALETTE, type TrayKind, trayIconPng, trayKind } from "./tray-icon";

export interface TrayActions {
    showWindow(): void;
    toggleWindow(): void;
    connect(): void;
    disconnect(): void;
    retry(): void;
    quit(): void;
}

const mac = process.platform === "darwin";

export function trayImage(kind: TrayKind, size = 16): NativeImage {
    const palette = mac ? TEMPLATE_PALETTE : colourPalette(nativeTheme.shouldUseDarkColors);
    const image = nativeImage.createEmpty();
    for (const scaleFactor of [1, 2, 3]) {
        image.addRepresentation({
            scaleFactor,
            width: size,
            height: size,
            buffer: trayIconPng(kind, palette, size * scaleFactor),
        });
    }
    image.setTemplateImage(mac);
    return image;
}

/**
 * Puts the app in the tray and keeps the icon, tooltip and menu in step with
 * the state. Returns `null` where the desktop refuses a tray icon; the
 * caller then keeps the window reachable some other way.
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
    let current = initial;

    const update = (state: LinkState) => {
        current = state;
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

    // On Windows and Linux a click opens the window; macOS opens the menu.
    if (!mac) {
        tray.on("click", actions.toggleWindow);
    }
    // The outline is light on a dark tray and dark on a light one.
    const onThemeChange = () => update(current);
    nativeTheme.on("updated", onThemeChange);

    update(initial);
    return {
        update,
        destroy: () => {
            nativeTheme.off("updated", onThemeChange);
            tray.destroy();
        },
    };
}
