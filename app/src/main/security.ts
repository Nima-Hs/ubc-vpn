// Everything that confines the interface: it is served from local files under
// a strict Content-Security-Policy, cannot navigate or open windows, is
// granted no permissions, and cannot make a request to anywhere else.

import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { app, protocol, session } from "electron";

/** The interface's only origin. */
export const APP_ORIGIN = "app://ui";

const CONTENT_TYPES: Record<string, string> = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
};

/**
 * Scripts, styles and fonts come from the app's own files and nowhere else.
 * There is no inline script or style, no `eval`, and no network access.
 */
export const CONTENT_SECURITY_POLICY = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "font-src 'self'",
    "img-src 'self'",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
].join("; ");

/**
 * The dev server (`electron-vite dev`) injects an inline script and talks to
 * the window over a WebSocket to reload it, so development needs a looser
 * policy. It is never used by a built app.
 */
function devContentSecurityPolicy(devOrigin: string): string {
    const ws = devOrigin.replace(/^http/, "ws");
    return [
        "default-src 'none'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data:",
        `connect-src 'self' ${ws}`,
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ].join("; ");
}

/** Must run before the app is ready. */
export function registerAppScheme(): void {
    protocol.registerSchemesAsPrivileged([
        { scheme: "app", privileges: { standard: true, secure: true } },
    ]);
}

/** Serves the built interface from `root` at {@link APP_ORIGIN}. */
function serveInterface(root: string): void {
    const notFound = () => new Response(null, { status: 404 });
    protocol.handle("app", async (request) => {
        const url = new URL(request.url);
        // Node reports no origin for a custom scheme, so compare its parts.
        if (url.protocol !== "app:" || url.host !== "ui") {
            return notFound();
        }
        const file = normalize(join(root, decodeURIComponent(url.pathname)));
        const contentType = CONTENT_TYPES[extname(file)];
        // Only files inside the interface's folder, and only the kinds it uses.
        if (!file.startsWith(root + sep) || contentType === undefined) {
            return notFound();
        }
        try {
            return new Response(new Uint8Array(await readFile(file)), {
                headers: {
                    "Content-Type": contentType,
                    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
                    "X-Content-Type-Options": "nosniff",
                },
            });
        } catch {
            return notFound();
        }
    });
}

/**
 * Locks the session down and returns the URL the window should load.
 * `devServerUrl` is set only by `electron-vite dev`.
 */
export function secureSession(rendererRoot: string, devServerUrl: string | undefined): string {
    const allowed = [`${APP_ORIGIN}/`];
    let entry = `${APP_ORIGIN}/index.html`;

    if (devServerUrl !== undefined) {
        const devOrigin = new URL(devServerUrl).origin;
        allowed.push(`${devOrigin}/`, `${devOrigin.replace(/^http/, "ws")}/`, "devtools://");
        entry = devServerUrl;
        session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
            callback({
                responseHeaders: {
                    ...details.responseHeaders,
                    "Content-Security-Policy": [devContentSecurityPolicy(devOrigin)],
                },
            });
        });
    } else {
        serveInterface(rendererRoot);
    }

    // No request leaves the app: anything not addressed to the interface's
    // own origin is cancelled before it is sent.
    session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
        callback({ cancel: !allowed.some((prefix) => details.url.startsWith(prefix)) });
    });

    // The interface needs no camera, location, notification or other permission.
    session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => {
        callback(false);
    });
    session.defaultSession.setPermissionCheckHandler(() => false);

    app.on("web-contents-created", (_event, contents) => {
        // The one page may reload itself; it may not go anywhere else.
        const stay = (event: Electron.Event, url: string) => {
            if (url !== entry) {
                event.preventDefault();
            }
        };
        contents.on("will-navigate", stay);
        contents.on("will-redirect", stay);
        contents.on("will-attach-webview", (event) => event.preventDefault());
        contents.setWindowOpenHandler(() => ({ action: "deny" }));
    });

    return entry;
}

/** Whether a message came from the interface's own page. */
export function isTrustedOrigin(
    origin: string | undefined,
    devServerUrl: string | undefined,
): boolean {
    if (origin === undefined) {
        return false;
    }
    return (
        origin === APP_ORIGIN ||
        (devServerUrl !== undefined && origin === new URL(devServerUrl).origin)
    );
}
