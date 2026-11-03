// The update handlers, registered against a stand-in for Electron's `ipcMain`,
// to show that each one refuses what it should not be sent.

import { UPDATES_IPC } from "@shared/updates";
import { describe, expect, it, vi } from "vitest";

const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
vi.mock("electron", () => ({
    ipcMain: {
        handle: (channel: string, handler: (event: unknown, ...args: unknown[]) => unknown) =>
            handlers.set(channel, handler),
    },
}));

const { registerUpdates } = await import("../src/main/update/ipc");
const { APP_ORIGIN } = await import("../src/main/security");

describe("what the interface may ask of the updater", () => {
    it("installs only when asked with no arguments, from the interface", () => {
        const frame = { origin: APP_ORIGIN };
        const window = {
            webContents: { mainFrame: frame, send: () => {} },
            isDestroyed: () => false,
        };
        const updater = { view: () => null, check: vi.fn(), subscribe: () => () => {} };
        const install = vi.fn(async () => {});
        registerUpdates(window as never, undefined, updater as never, install);
        const handler = handlers.get(UPDATES_IPC.install);
        expect(handler).toBeDefined();
        const event = { senderFrame: frame };
        expect(() => handler?.(event, "C:\\made-up\\setup.exe")).toThrow("refused");
        expect(() => handler?.({ senderFrame: {} })).toThrow("refused");
        expect(install).not.toHaveBeenCalled();
        handler?.(event);
        expect(install).toHaveBeenCalledTimes(1);
    });
});
