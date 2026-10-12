import { IPC } from "@shared/api";
import type { RouteInput } from "@shared/protocol/RouteInput";
import { type BrowserWindow, type IpcMainInvokeEvent, ipcMain } from "electron";
import type { SettingsService } from "./channel/settings";
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
 * Takes an answer to a login prompt from the interface and hands it straight
 * on. An answer may be a password, so nothing here keeps it, and a refusal
 * says only "refused": Electron prints a handler's error to the main
 * process's standard error, and nothing that was sent may end up there.
 */
export function takePromptAnswer(
    controller: Pick<Controller, "answerPrompt">,
    args: readonly unknown[],
): void {
    if (!isPromptAnswer(args)) {
        throw new Error("refused");
    }
    controller.answerPrompt(args[0], args[1]);
}

/**
 * The most entries, and the longest entry, the interface may send to be
 * checked. Both are above the client's own limits (256 entries of at most
 * 253 bytes), so that an honest "too many" or "too long" still reaches the
 * client and comes back as a problem the user can read. Past these, nothing
 * is started at all.
 */
export const MAX_ROUTE_ENTRIES = 1024;
export const MAX_ROUTE_ENTRY_LENGTH = 512;

function isEntryList(value: unknown): value is string[] {
    if (!Array.isArray(value) || value.length > MAX_ROUTE_ENTRIES) {
        return false;
    }
    // By position, not with `every`: that skips a gap in a list, and a gap
    // would go on to the client as `null`.
    for (let at = 0; at < value.length; at++) {
        const entry: unknown = value[at];
        if (typeof entry !== "string" || entry.length > MAX_ROUTE_ENTRY_LENGTH) {
            return false;
        }
    }
    return true;
}

/**
 * Takes routes from the interface: one argument, an object with exactly the
 * two lists, each a bounded list of bounded strings. Returns a fresh object
 * holding only those lists, or refuses.
 */
export function takeRouteInput(args: readonly unknown[]): RouteInput {
    const [input] = args;
    if (
        args.length !== 1 ||
        typeof input !== "object" ||
        input === null ||
        Array.isArray(input) ||
        Object.keys(input).sort().join() !== "dns_domains,subnets"
    ) {
        throw new Error("refused");
    }
    const { subnets, dns_domains } = input as Record<string, unknown>;
    if (!isEntryList(subnets) || !isEntryList(dns_domains)) {
        throw new Error("refused");
    }
    return { subnets: [...subnets], dns_domains: [...dns_domains] };
}

/**
 * The fixed set of things the interface can ask for. Three take arguments,
 * and each checks them before anything else happens.
 */
export function registerIpc(
    window: BrowserWindow,
    controller: Controller,
    settings: SettingsService,
    devServerUrl: string | undefined,
): void {
    const handle = (channel: string, handler: () => unknown) =>
        handleFromInterface(window, devServerUrl, channel, handler);

    handle(IPC.getSnapshot, () => controller.getSnapshot());
    handle(IPC.connect, () => controller.connect());
    handle(IPC.disconnect, () => controller.disconnect());
    handle(IPC.retry, () => controller.retry());
    handle(IPC.cancelLogin, () => controller.cancelLogin());
    handleFromInterface(window, devServerUrl, IPC.answerPrompt, (...args) =>
        takePromptAnswer(controller, args),
    );
    handle(IPC.getSettings, () => settings.getSettings());
    handleFromInterface(window, devServerUrl, IPC.checkRoutes, (...args) =>
        settings.checkRoutes(takeRouteInput(args)),
    );
    handleFromInterface(window, devServerUrl, IPC.saveRoutes, (...args) =>
        settings.saveRoutes(takeRouteInput(args)),
    );
    handle(IPC.minimizeWindow, () => window.minimize());
    handle(IPC.closeWindow, () => window.close());

    controller.subscribe((snapshot) => {
        if (!window.isDestroyed()) {
            window.webContents.send(IPC.snapshot, snapshot);
        }
    });
}
