/**
 * Where the service listens. The service's transport is not written yet, so
 * these names are the app's proposal and must be agreed with it.
 */
export function defaultChannelPath(platform: NodeJS.Platform = process.platform): string {
    switch (platform) {
        case "win32":
            return String.raw`\\.\pipe\ubc-vpn`;
        case "darwin":
            return "/var/run/ubc-vpn/service.sock";
        default:
            return "/run/ubc-vpn/service.sock";
    }
}
