import { IPC } from "@shared/api";
import { type BrowserWindow, type IpcMainInvokeEvent, ipcMain } from "electron";
import type { Controller } from "./controller";
import { isTrustedOrigin } from "./security";

/**
 * Registers a handler that runs only for the interface's own page in the
 * app's own window. Anything else gets an error and nothing happens.
 */
export function handleFromInterface(
    window: BrowserWindow,
    devServerUrl: string | undefined,
    channel: string,
    handler: (...args: unknown[]) => unknown,
): void {
    ipcMain.handle(channel, (event: IpcMainInvokeEvent, ...args: unknown[]) => {
        const frame = event.senderFrame;
        if (
            frame === null ||
            frame !== window.webContents.mainFrame ||
            !isTrustedOrigin(frame.origin, devServerUrl)
        ) {
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
    handle(IPC.hideWindow, () => window.close());

    controller.subscribe((snapshot) => {
        if (!window.isDestroyed()) {
            window.webContents.send(IPC.snapshot, snapshot);
        }
    });
}
