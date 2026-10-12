import { describe, expect, it } from "vitest";
import { serviceChannelPath } from "../src/main/channel/endpoint";

// The names the service listens on are owned by `crates/platform`
// (`Paths::channel_name`). When its transports land, replace the three
// values below with the crate's, and change `endpoint.ts` to match.
const PLATFORM_CRATE_CHANNEL = {
    win32: String.raw`\\.\pipe\ubc-vpn`,
    darwin: "/var/run/ubc-vpn/service.sock",
    linux: "/run/ubc-vpn/service.sock",
} as const;

describe("where the app looks for the service", () => {
    it.each(Object.entries(PLATFORM_CRATE_CHANNEL))(
        "on %s it is the platform crate's name",
        (os, path) => {
            expect(serviceChannelPath(os as NodeJS.Platform)).toBe(path);
        },
    );

    it("is a named pipe on Windows and an absolute socket path elsewhere", () => {
        expect(serviceChannelPath("win32")).toMatch(/^\\\\\.\\pipe\\[\w-]+$/);
        expect(serviceChannelPath("darwin")).toMatch(/^\/.+\.sock$/);
        expect(serviceChannelPath("linux")).toMatch(/^\/.+\.sock$/);
    });
});
