/**
 * Where the service listens.
 *
 * PLACEHOLDER. The app does not choose this name: `crates/platform` owns it
 * (`Paths::channel_name`), and these values must equal what that crate uses
 * on each OS. Its transports are still being written, so the names below are
 * stand-ins and are expected to change. This is the only place the app holds
 * them; `tests/endpoint.test.ts` pins them and is where to update them.
 */
export function serviceChannelPath(platform: NodeJS.Platform = process.platform): string {
    switch (platform) {
        case "win32":
            return String.raw`\\.\pipe\ubc-vpn`;
        case "darwin":
            return "/var/run/ubc-vpn/service.sock";
        default:
            return "/run/ubc-vpn/service.sock";
    }
}
