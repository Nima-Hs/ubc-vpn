import { IPC } from "@shared/api";
import { type BrowserWindow, type IpcMainInvokeEvent, ipcMain } from "electron";
import type { Controller } from "./controller";
import { isTrustedOrigin } from "./security";

/**
 * Registers a handler that runs only for the interface's own page in the
 * app's own window. Anything else gets an error and nothing happens.
 */
/**
 * Whether an IPC message came from the interface: from the top frame of the
 * app's own window, showing the app's own page. A frame inside that page, or
 * any other window, is refused whatever it is showing.
 */
export function isFromInterface(
    sender: { origin: string } | null,
    interfaceFrame: unknown,
    devServerUrl: string | undefined,
): boolean {
    return (
        sender !== null && sender === interfaceFrame && isTrustedOrigin(sender.origin, devServerUrl)
    );
}

export function handleFromInterface(
    window: BrowserWindow,
    devServerUrl: string | undefined,
    channel: string,
    handler: (...args: unknown[]) => unknown,
): void {
    ipcMain.handle(channel, (event: IpcMainInvokeEvent, ...args: unknown[]) => {
        if (!isFromInterface(event.senderFrame, window.webContents.mainFrame, devServerUrl)) {
            throw new Error("refused");
        }
        return handler(...args);
    });
}

/** The fixed set of things the interface can ask for. None takes an argument. */
export function registerIpc(
    window: BrowserWindow,
    controller: Controller,
    devServerUrl: string | undefined,
): void {
    const handle = (channel: string, handler: () => unknown) =>
        handleFromInterface(window, devServerUrl, channel, handler);

    handle(IPC.getSnapshot, () => controller.getSnapshot());
    handle(IPC.connect, () => controller.connect());
    handle(IPC.disconnect, () => controller.disconnect());
    handle(IPC.retry, () => controller.retry());
    handle(IPC.minimizeWindow, () => window.minimize());
    handle(IPC.closeWindow, () => window.close());

    controller.subscribe((snapshot) => {
        if (!window.isDestroyed()) {
            window.webContents.send(IPC.snapshot, snapshot);
        }
    });
}
