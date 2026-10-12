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

/** The longest answer a login prompt may be given, in characters. */
export const MAX_ANSWER_LENGTH = 1024;

/**
 * Whether the arguments of an "answer the prompt" message are what they must
 * be: a prompt id and the text the user typed. The interface is not trusted
 * to send only that, so anything else is refused before it goes further.
 */
export function isPromptAnswer(args: readonly unknown[]): args is [number, string] {
    const [id, value] = args;
    return (
        args.length === 2 &&
        typeof id === "number" &&
        Number.isInteger(id) &&
        id >= 0 &&
        id <= 0xffffffff &&
        typeof value === "string" &&
        value.length <= MAX_ANSWER_LENGTH
    );
}

/**
 * The fixed set of things the interface can ask for. Only one takes
 * arguments, and it checks them.
 */
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
    handle(IPC.cancelLogin, () => controller.cancelLogin());
    handleFromInterface(window, devServerUrl, IPC.answerPrompt, (...args) => {
        // Handed straight on. An answer may be a password: nothing here
        // keeps it, and a refusal says nothing about what was sent.
        if (!isPromptAnswer(args)) {
            throw new Error("refused");
        }
        controller.answerPrompt(args[0], args[1]);
    });
    handle(IPC.minimizeWindow, () => window.minimize());
    handle(IPC.closeWindow, () => window.close());

    controller.subscribe((snapshot) => {
        if (!window.isDestroyed()) {
            window.webContents.send(IPC.snapshot, snapshot);
        }
    });
}
