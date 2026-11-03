// The Settings screen's IPC handlers, registered against a stand-in for
// Electron's `ipcMain`, to show that each one checks what it is sent.

import { PROFILES_IPC } from "@shared/profiles";
import { describe, expect, it, vi } from "vitest";

const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
vi.mock("electron", () => ({
    ipcMain: {
        handle: (channel: string, handler: (event: unknown, ...args: unknown[]) => unknown) =>
            handlers.set(channel, handler),
    },
}));

const { registerProfiles } = await import("../src/main/profiles/ipc");
const { APP_ORIGIN } = await import("../src/main/security");

describe("the Settings screen's requests", () => {
    it("saves Automatic updates only as on or off", async () => {
        const frame = { origin: APP_ORIGIN };
        const window = { webContents: { mainFrame: frame } };
        const setUpdates = vi.fn(async () => ({ ok: false, error: "unavailable" }) as const);
        const profiles = { setUpdates } as never;
        registerProfiles(window as never, undefined, profiles, { apply: () => {} }, "win32");
        const handler = handlers.get(PROFILES_IPC.setUpdates);
        expect(handler).toBeDefined();
        const event = { senderFrame: frame };
        await handler?.(event, false);
        expect(setUpdates).toHaveBeenCalledWith(false);
        for (const args of [["no"], [1], [], [true, true]]) {
            expect(() => handler?.(event, ...args), JSON.stringify(args)).toThrow("refused");
        }
        expect(setUpdates).toHaveBeenCalledTimes(1);
    });
});
