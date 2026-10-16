import { HIDDEN_ARG } from "@shared/profiles";
import type { GlobalSettings } from "@shared/protocol/GlobalSettings";
import { describe, expect, it } from "vitest";
import {
    connectsAtStart,
    loginItemFor,
    showsAfterSettings,
    startsInTray,
    startupSupported,
} from "../src/main/startup";

const GLOBAL: GlobalSettings = {
    start: "off",
    auto_connect: false,
    active_profile: "0123456789abcdef0123456789abcdef",
};

describe("starting when the user signs in", () => {
    it("registers nothing when off, and the plain program to open the window", () => {
        for (const platform of ["win32", "darwin"] as const) {
            expect(loginItemFor("off", platform)).toEqual({ openAtLogin: false, args: [] });
            expect(loginItemFor("window", platform)).toEqual({ openAtLogin: true, args: [] });
        }
    });

    it("starts in the tray with --hidden on Windows; macOS takes no arguments", () => {
        expect(loginItemFor("tray", "win32")).toEqual({ openAtLogin: true, args: [HIDDEN_ARG] });
        expect(loginItemFor("tray", "darwin")).toEqual({ openAtLogin: true, args: [] });
    });

    it("is offered where Electron can register it", () => {
        expect(startupSupported("win32")).toBe(true);
        expect(startupSupported("darwin")).toBe(true);
        expect(startupSupported("linux")).toBe(false);
    });
});

describe("starting in the tray", () => {
    const installed = {
        packaged: true,
        argv: ["C:\\Program Files\\UBC VPN\\UBC VPN.exe", HIDDEN_ARG],
        openedAtLogin: false,
        platform: "win32" as const,
        trayCreated: true,
    };

    it("happens for an installed app started with --hidden, at sign-in or by hand", () => {
        expect(startsInTray(installed)).toBe(true);
    });

    it("does not happen without --hidden", () => {
        expect(startsInTray({ ...installed, argv: [installed.argv[0] as string] })).toBe(false);
    });

    it("is ignored by an app that is not installed, as a test or development run", () => {
        expect(startsInTray({ ...installed, packaged: false })).toBe(false);
    });

    it("never leaves the window unreachable: without a tray it is shown", () => {
        expect(startsInTray({ ...installed, trayCreated: false })).toBe(false);
    });

    it("on macOS, holds the window back for a start at sign-in, not for the argument", () => {
        const mac = { ...installed, platform: "darwin" as const };
        expect(startsInTray(mac)).toBe(false);
        expect(startsInTray({ ...mac, openedAtLogin: true })).toBe(true);
    });

    it("on macOS, shows it once the settings say it does not belong in the tray", () => {
        expect(showsAfterSettings("darwin", "tray")).toBe(false);
        expect(showsAfterSettings("darwin", "window")).toBe(true);
        // Settings that cannot be read never leave the window held back.
        expect(showsAfterSettings("darwin", null)).toBe(true);
        // Elsewhere `--hidden` has said already.
        expect(showsAfterSettings("win32", "window")).toBe(false);
    });
});

describe("connecting when it starts", () => {
    it("is off unless asked for", () => {
        expect(connectsAtStart(GLOBAL, { state: "disconnected" })).toBe(false);
    });

    it("happens only from a settled 'not connected'", () => {
        const on = { ...GLOBAL, auto_connect: true };
        expect(connectsAtStart(on, { state: "disconnected" })).toBe(true);
        expect(connectsAtStart(on, { state: "connecting" })).toBe(false);
        expect(connectsAtStart(on, { state: "login_needed" })).toBe(false);
        expect(connectsAtStart(on, null)).toBe(false);
    });
});
