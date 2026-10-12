// Everything that confines the interface: it is served from local files under
// a strict Content-Security-Policy, cannot navigate or open windows, is
// granted no permissions, and cannot make a request to anywhere else.
//
// Electron is passed in, never imported, so every rule here can be tested on
// its own: `tests/security.test.ts` removes nothing, but fails if one is.

import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import type {
    App,
    BrowserWindowConstructorOptions,
    Protocol,
    Session,
    WebContents,
} from "electron";

/** The interface's only origin. */
export const APP_ORIGIN = "app://ui";
const ENTRY = `${APP_ORIGIN}/index.html`;

/**
 * What the `app:` scheme may do: behave like `https:` and nothing more. It
 * may not bypass the Content-Security-Policy, be fetched, or be read from
 * another origin.
 */
export const APP_SCHEME = { scheme: "app", privileges: { standard: true, secure: true } } as const;

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

/**
 * The dev server's address, which only a development build may use. A built
 * app ignores the variable, so nothing that can set the app's environment
 * can point its window at another page.
 */
export function devServerUrlFor(
    developmentBuild: boolean,
    env: Record<string, string | undefined>,
): string | undefined {
    return developmentBuild ? env.ELECTRON_RENDERER_URL : undefined;
}

/**
 * The file an `app:` request names, or `null` if it may not be served. Only
 * the interface's host, only files inside its folder, and only the kinds of
 * file it is made of.
 */
export function resolveInterfaceFile(
    root: string,
    requestUrl: string,
): { file: string; contentType: string } | null {
    let url: URL;
    let path: string;
    try {
        url = new URL(requestUrl);
        path = decodeURIComponent(url.pathname);
    } catch {
        return null;
    }
    // Node reports no origin for a custom scheme, so compare its parts.
    if (url.protocol !== "app:" || url.host !== "ui") {
        return null;
    }
    const file = normalize(join(root, path));
    if (!file.startsWith(normalize(root) + sep)) {
        return null;
    }
    const contentType = CONTENT_TYPES[extname(file)];
    return contentType === undefined ? null : { file, contentType };
}

/** The headers every file of the interface is served with. */
export function interfaceHeaders(contentType: string): Record<string, string> {
    return {
        "Content-Type": contentType,
        "Content-Security-Policy": CONTENT_SECURITY_POLICY,
        // The browser must not guess a different type from the contents.
        "X-Content-Type-Options": "nosniff",
    };
}

/** Answers an `app:` request with one of the interface's files, or 404. */
export async function serveInterfaceFile(root: string, requestUrl: string): Promise<Response> {
    const found = resolveInterfaceFile(root, requestUrl);
    if (found !== null) {
        try {
            return new Response(new Uint8Array(await readFile(found.file)), {
                headers: interfaceHeaders(found.contentType),
            });
        } catch {
            // Fall through: a missing file is answered like a refused one.
        }
    }
    return new Response(null, { status: 404 });
}

/** The address prefixes a request may go to. Everything else is cancelled. */
export function allowedRequestPrefixes(devServerUrl: string | undefined): string[] {
    if (devServerUrl === undefined) {
        return [`${APP_ORIGIN}/`];
    }
    const devOrigin = new URL(devServerUrl).origin;
    return [
        `${APP_ORIGIN}/`,
        `${devOrigin}/`,
        `${devOrigin.replace(/^http/, "ws")}/`,
        "devtools://",
    ];
}

export function isAllowedRequest(url: string, prefixes: readonly string[]): boolean {
    return prefixes.some((prefix) => url.startsWith(prefix));
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

/**
 * How the interface's process is confined. Isolated from the preload's
 * world, sandboxed by the OS, with no Node, no `<webview>`, and developer
 * tools only in a development build.
 */
export function webPreferences(
    preload: string,
    developmentBuild: boolean,
): NonNullable<BrowserWindowConstructorOptions["webPreferences"]> {
    return {
        preload,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        webviewTag: false,
        spellcheck: false,
        devTools: developmentBuild,
    };
}

/**
 * The application menu. Electron's default one offers reload, zoom and
 * developer tools; a built app has no use for them. `null` means no menu;
 * macOS keeps the entries every Mac app has. `undefined` leaves the default
 * in place, for development.
 */
export function applicationMenu(
    platform: NodeJS.Platform,
    developmentBuild: boolean,
): { role: "appMenu" | "editMenu" | "windowMenu" }[] | null | undefined {
    if (developmentBuild) {
        return undefined;
    }
    return platform === "darwin"
        ? [{ role: "appMenu" }, { role: "editMenu" }, { role: "windowMenu" }]
        : null;
}

/** Keeps a page where it is: no navigation, no new windows, no `<webview>`. */
export function confineContents(
    contents: Pick<WebContents, "on" | "setWindowOpenHandler">,
    entry: string,
): void {
    // The one page may reload itself; it may not go anywhere else.
    const stay = (event: { preventDefault(): void }, url: string) => {
        if (url !== entry) {
            event.preventDefault();
        }
    };
    contents.on("will-navigate", stay);
    contents.on("will-redirect", stay);
    contents.on("will-attach-webview", (event) => event.preventDefault());
    contents.setWindowOpenHandler(() => ({ action: "deny" }));
}

/**
 * The switches that make Chromium open a debugging port or pipe. Whoever can
 * reach it controls the interface, and through the interface everything the
 * interface may ask the main process to do. No Electron fuse turns them off.
 */
export const REMOTE_DEBUGGING_SWITCHES = [
    "remote-debugging-port",
    "remote-debugging-pipe",
    "remote-debugging-address",
] as const;

/**
 * Whether this run may be debugged from outside. Only a run that has not
 * been packaged and is a demo build, a development build, or in dev mode
 * (talking to a pretend service, and saying so on every screen): those are
 * what the end-to-end tests drive, and their driver attaches through
 * `--remote-debugging-port`. A production build pointed at the real service
 * never may, packaged or not, and nothing packaged ever may.
 */
export function allowsRemoteDebugging(build: {
    isPackaged: boolean;
    demo: boolean;
    development: boolean;
    /** Whether the client is run in dev mode; see `bridgeCommand`. */
    devMode: boolean;
}): boolean {
    return !build.isPackaged && (build.demo || build.development || build.devMode);
}

/**
 * Takes the remote debugging switches off the command line unless this run
 * may be debugged. Must run before anything else reads the command line.
 */
export function refuseRemoteDebugging(
    commandLine: { removeSwitch(name: string): void },
    allowed: boolean,
): void {
    if (allowed) {
        return;
    }
    for (const name of REMOTE_DEBUGGING_SWITCHES) {
        commandLine.removeSwitch(name);
    }
}

/** Must run before the app is ready. */
export function registerAppScheme(protocol: Pick<Protocol, "registerSchemesAsPrivileged">): void {
    protocol.registerSchemesAsPrivileged([APP_SCHEME]);
}

export interface SessionParts {
    app: Pick<App, "on">;
    protocol: Pick<Protocol, "handle">;
    session: Pick<
        Session,
        "webRequest" | "setPermissionRequestHandler" | "setPermissionCheckHandler"
    >;
}

/**
 * Locks the session down and returns the URL the window should load.
 * `devServerUrl` comes from {@link devServerUrlFor}.
 */
export function secureSession(
    { app, protocol, session }: SessionParts,
    rendererRoot: string,
    devServerUrl: string | undefined,
): string {
    let entry = ENTRY;
    if (devServerUrl !== undefined) {
        const devOrigin = new URL(devServerUrl).origin;
        entry = devServerUrl;
        session.webRequest.onHeadersReceived((details, callback) => {
            callback({
                responseHeaders: {
                    ...details.responseHeaders,
                    "Content-Security-Policy": [devContentSecurityPolicy(devOrigin)],
                },
            });
        });
    } else {
        protocol.handle("app", (request) => serveInterfaceFile(rendererRoot, request.url));
    }

    // No request leaves the app: anything not addressed to the interface's
    // own origin is cancelled before it is sent.
    const allowed = allowedRequestPrefixes(devServerUrl);
    session.webRequest.onBeforeRequest((details, callback) => {
        callback({ cancel: !isAllowedRequest(details.url, allowed) });
    });

    // The interface needs no camera, location, notification or other permission.
    session.setPermissionRequestHandler((_contents, _permission, callback) => {
        callback(false);
    });
    session.setPermissionCheckHandler(() => false);

    app.on("web-contents-created", (_event, contents) => confineContents(contents, entry));

    return entry;
}
