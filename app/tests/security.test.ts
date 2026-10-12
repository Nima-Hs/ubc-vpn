// One test per protection around the interface. Each is written so that
// removing or loosening that one protection fails it, whatever else is still
// in place. The end-to-end test checks the same things in the running app.

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { isFromInterface } from "../src/main/ipc";
import {
    APP_SCHEME,
    allowedRequestPrefixes,
    applicationMenu,
    CONTENT_SECURITY_POLICY,
    confineContents,
    devServerUrlFor,
    interfaceHeaders,
    isAllowedRequest,
    isTrustedOrigin,
    registerAppScheme,
    resolveInterfaceFile,
    type SessionParts,
    secureSession,
    serveInterfaceFile,
    webPreferences,
} from "../src/main/security";

/** A folder laid out like the built interface, with a secret beside it. */
function interfaceFolder(): string {
    const parent = mkdtempSync(join(tmpdir(), "ubc-vpn-ui-"));
    const root = join(parent, "renderer");
    mkdirSync(join(root, "assets"), { recursive: true });
    writeFileSync(join(root, "index.html"), "<!doctype html>");
    writeFileSync(join(root, "assets", "app.js"), "export {};");
    writeFileSync(join(root, "assets", "notes.txt"), "not part of the interface");
    writeFileSync(join(parent, "secret.js"), "outside the interface");
    return root;
}

describe("the interface's process", () => {
    const production = webPreferences("/app/preload.js", false);

    it("is isolated, sandboxed and has no Node", () => {
        expect(production.contextIsolation).toBe(true);
        expect(production.sandbox).toBe(true);
        expect(production.nodeIntegration).toBe(false);
        expect(production.webSecurity).toBe(true);
    });

    it("cannot embed a webview", () => {
        expect(production.webviewTag).toBe(false);
    });

    it("has developer tools only in a development build", () => {
        expect(production.devTools).toBe(false);
        expect(webPreferences("/app/preload.js", true).devTools).toBe(true);
    });

    it("loads the preload it is given and nothing else", () => {
        expect(production.preload).toBe("/app/preload.js");
        expect(Object.keys(production).sort()).toEqual([
            "contextIsolation",
            "devTools",
            "nodeIntegration",
            "preload",
            "sandbox",
            "spellcheck",
            "webSecurity",
            "webviewTag",
        ]);
    });
});

describe("the Content-Security-Policy", () => {
    const directives = Object.fromEntries(
        CONTENT_SECURITY_POLICY.split("; ").map((directive) => {
            const [name, ...values] = directive.split(" ");
            return [name, values.join(" ")];
        }),
    );

    it("allows nothing by default", () => {
        expect(directives["default-src"]).toBe("'none'");
    });

    it("runs only the app's own scripts and styles: nothing inline, no eval", () => {
        expect(directives["script-src"]).toBe("'self'");
        expect(directives["style-src"]).toBe("'self'");
    });

    it("lets the interface connect to nothing", () => {
        expect(directives["connect-src"]).toBe("'none'");
    });

    it("loads fonts and images only from the app, and locks the rest", () => {
        expect(directives).toEqual({
            "default-src": "'none'",
            "script-src": "'self'",
            "style-src": "'self'",
            "font-src": "'self'",
            "img-src": "'self'",
            "connect-src": "'none'",
            "base-uri": "'none'",
            "form-action": "'none'",
            "frame-ancestors": "'none'",
        });
    });

    it("is sent with every file, along with a fixed content type", () => {
        expect(interfaceHeaders("text/html; charset=utf-8")).toEqual({
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "X-Content-Type-Options": "nosniff",
        });
    });
});

describe("serving the interface's files", () => {
    const root = interfaceFolder();

    it("serves the interface's own files", () => {
        expect(resolveInterfaceFile(root, "app://ui/index.html")).toEqual({
            file: join(root, "index.html"),
            contentType: "text/html; charset=utf-8",
        });
        expect(resolveInterfaceFile(root, "app://ui/assets/app.js")?.contentType).toBe(
            "text/javascript; charset=utf-8",
        );
    });

    it.each([
        "app://ui/../secret.js",
        "app://ui/assets/../../secret.js",
        "app://ui/%2e%2e/secret.js",
        "app://ui/%2e%2e%2fsecret.js",
        "app://ui/..%5csecret.js",
        "app://ui/assets/..%2f..%2fsecret.js",
        "app://ui//../secret.js",
    ])("never resolves outside the interface's folder: %s", (url) => {
        // Some of these the URL parser folds back inside the folder, where
        // they name a file that does not exist. None may land outside it.
        const found = resolveInterfaceFile(root, url);
        expect(found === null || found.file.startsWith(root + sep)).toBe(true);
    });

    it.each([
        // An encoded slash survives URL parsing and only becomes "../" once decoded.
        "app://ui/..%2fsecret.js",
        "app://ui/%2e%2e%2fsecret.js",
        "app://ui/assets/..%2f..%2fsecret.js",
        // A folder beside the interface's whose name merely starts the same.
        "app://ui/..%2frenderer-other%2fx.js",
    ])("refuses a path that climbs out of the folder: %s", (url) => {
        expect(resolveInterfaceFile(root, url)).toBeNull();
    });

    it("serves only the kinds of file the interface is made of", () => {
        expect(resolveInterfaceFile(root, "app://ui/assets/notes.txt")).toBeNull();
        expect(resolveInterfaceFile(root, "app://ui/assets/app.js.map")).toBeNull();
        expect(resolveInterfaceFile(root, "app://ui/assets/")).toBeNull();
    });

    it("answers only for its own host", () => {
        expect(resolveInterfaceFile(root, "app://other/index.html")).toBeNull();
        expect(resolveInterfaceFile(root, "app://ui.example/index.html")).toBeNull();
        expect(resolveInterfaceFile(root, "file://ui/index.html")).toBeNull();
    });

    it("refuses an address it cannot read", () => {
        expect(resolveInterfaceFile(root, "app://ui/%E0%A4%A")).toBeNull();
        expect(resolveInterfaceFile(root, "not a url")).toBeNull();
    });

    it("answers 404 for anything refused or missing, and 200 with the headers otherwise", async () => {
        expect((await serveInterfaceFile(root, "app://ui/../secret.js")).status).toBe(404);
        expect((await serveInterfaceFile(root, "app://other/index.html")).status).toBe(404);
        expect((await serveInterfaceFile(root, "app://ui/assets/notes.txt")).status).toBe(404);
        expect((await serveInterfaceFile(root, "app://ui/missing.js")).status).toBe(404);

        const served = await serveInterfaceFile(root, "app://ui/index.html");
        expect(served.status).toBe(200);
        expect(await served.text()).toBe("<!doctype html>");
        expect(served.headers.get("Content-Security-Policy")).toBe(CONTENT_SECURITY_POLICY);
        expect(served.headers.get("X-Content-Type-Options")).toBe("nosniff");
    });
});

describe("requests", () => {
    it("go only to the interface's own origin in a built app", () => {
        const allowed = allowedRequestPrefixes(undefined);
        expect(allowed).toEqual(["app://ui/"]);
        expect(isAllowedRequest("app://ui/assets/app.js", allowed)).toBe(true);
        for (const url of [
            "https://example.com/",
            "http://localhost:5173/",
            "ws://localhost:5173/",
            "file:///etc/passwd",
            "app://other/index.html",
            "app://ui.example/index.html",
            "devtools://devtools/bundled/inspector.html",
            "data:text/html,hello",
        ]) {
            expect(isAllowedRequest(url, allowed), url).toBe(false);
        }
    });

    it("also reach the dev server, and only it, in development", () => {
        const allowed = allowedRequestPrefixes("http://localhost:5173/");
        expect(isAllowedRequest("http://localhost:5173/src/main.tsx", allowed)).toBe(true);
        expect(isAllowedRequest("ws://localhost:5173/", allowed)).toBe(true);
        expect(isAllowedRequest("http://localhost:5173.example.com/", allowed)).toBe(false);
        expect(isAllowedRequest("https://example.com/", allowed)).toBe(false);
    });
});

describe("the dev server's address", () => {
    const env = { ELECTRON_RENDERER_URL: "https://example.com/" };

    it("is ignored by a built app, whatever the environment says", () => {
        expect(devServerUrlFor(false, env)).toBeUndefined();
    });

    it("is used by a development build", () => {
        expect(devServerUrlFor(true, env)).toBe("https://example.com/");
        expect(devServerUrlFor(true, {})).toBeUndefined();
    });
});

describe("who may call the main process", () => {
    it("trusts only the interface's own origin", () => {
        expect(isTrustedOrigin("app://ui", undefined)).toBe(true);
        for (const origin of [
            undefined,
            "null",
            "",
            "app://other",
            "app://ui.example",
            "https://example.com",
            "file://",
            "http://localhost:5173",
        ]) {
            expect(isTrustedOrigin(origin, undefined), String(origin)).toBe(false);
        }
    });

    it("trusts the dev server's origin only when there is a dev server", () => {
        expect(isTrustedOrigin("http://localhost:5173", "http://localhost:5173/")).toBe(true);
        expect(isTrustedOrigin("http://localhost:9999", "http://localhost:5173/")).toBe(false);
    });

    it("accepts a message only from the window's own top frame, on that origin", () => {
        const frame = { origin: "app://ui" };
        expect(isFromInterface(frame, frame, undefined)).toBe(true);
        // Another window or an inner frame, even one showing the app's page.
        expect(isFromInterface({ origin: "app://ui" }, frame, undefined)).toBe(false);
        // The right frame, showing something else.
        const elsewhere = { origin: "https://example.com" };
        expect(isFromInterface(elsewhere, elsewhere, undefined)).toBe(false);
        // A frame that has gone away.
        expect(isFromInterface(null, frame, undefined)).toBe(false);
    });
});

describe("the application menu", () => {
    it("is removed from a built app, so reload and developer tools are not offered", () => {
        expect(applicationMenu("win32", false)).toBeNull();
        expect(applicationMenu("linux", false)).toBeNull();
    });

    it("keeps only the standard entries on macOS", () => {
        expect(applicationMenu("darwin", false)).toEqual([
            { role: "appMenu" },
            { role: "editMenu" },
            { role: "windowMenu" },
        ]);
    });

    it("is left alone in development", () => {
        expect(applicationMenu("win32", true)).toBeUndefined();
    });
});

describe("the app: scheme", () => {
    it("is registered as a standard, secure scheme with no other privilege", () => {
        const registered: unknown[] = [];
        registerAppScheme({ registerSchemesAsPrivileged: (schemes) => registered.push(schemes) });
        expect(registered).toEqual([
            [{ scheme: "app", privileges: { standard: true, secure: true } }],
        ]);
        expect(APP_SCHEME.privileges).not.toHaveProperty("bypassCSP");
    });
});

/** Stand-ins for the parts of Electron `secureSession` configures, recording what it does. */
function fakeElectron() {
    type Listener = (...args: never[]) => unknown;
    const recorded = {
        handlers: new Map<string, (request: { url: string }) => Promise<Response>>(),
        beforeRequest: [] as Listener[],
        headersReceived: [] as Listener[],
        permissionRequest: [] as (Listener | null)[],
        permissionCheck: [] as (Listener | null)[],
        appListeners: new Map<string, Listener>(),
    };
    const parts = {
        app: {
            on: (event: string, listener: Listener) => recorded.appListeners.set(event, listener),
        },
        protocol: {
            handle: (scheme: string, handler: (request: { url: string }) => Promise<Response>) =>
                recorded.handlers.set(scheme, handler),
        },
        session: {
            webRequest: {
                onBeforeRequest: (listener: Listener) => recorded.beforeRequest.push(listener),
                onHeadersReceived: (listener: Listener) => recorded.headersReceived.push(listener),
            },
            setPermissionRequestHandler: (handler: Listener | null) =>
                recorded.permissionRequest.push(handler),
            setPermissionCheckHandler: (handler: Listener | null) =>
                recorded.permissionCheck.push(handler),
        },
    } as unknown as SessionParts;
    return { parts, recorded };
}

/** A stand-in for a page, recording what is done to it. */
function fakeContents() {
    const listeners = new Map<string, (event: { preventDefault(): void }, url: string) => void>();
    let openHandler: (() => { action: string }) | undefined;
    const contents = {
        on: (event: string, listener: (event: { preventDefault(): void }, url: string) => void) =>
            listeners.set(event, listener),
        setWindowOpenHandler: (handler: () => { action: string }) => {
            openHandler = handler;
        },
    } as unknown as Parameters<typeof confineContents>[0];
    /** Fires an event and reports whether it was prevented. */
    const prevented = (event: string, url = "") => {
        let stopped = false;
        listeners.get(event)?.({ preventDefault: () => (stopped = true) }, url);
        return stopped;
    };
    return { contents, prevented, open: () => openHandler?.() };
}

describe("the session, as a built app sets it up", () => {
    const root = interfaceFolder();
    const { parts, recorded } = fakeElectron();
    const entry = secureSession(parts, root, undefined);

    it("loads the interface from the app's own files", () => {
        expect(entry).toBe("app://ui/index.html");
        expect(recorded.headersReceived).toEqual([]);
    });

    it("serves app: requests through the checks above", async () => {
        const handler = recorded.handlers.get("app");
        expect(handler).toBeDefined();
        expect((await handler?.({ url: "app://ui/index.html" }))?.status).toBe(200);
        expect((await handler?.({ url: "app://ui/../secret.js" }))?.status).toBe(404);
    });

    it("cancels every request that is not to the interface's origin", () => {
        expect(recorded.beforeRequest).toHaveLength(1);
        const decide = (url: string) => {
            let cancel: boolean | undefined;
            (
                recorded.beforeRequest[0] as unknown as (
                    d: unknown,
                    cb: (r: { cancel: boolean }) => void,
                ) => void
            )({ url }, (response) => {
                cancel = response.cancel;
            });
            return cancel;
        };
        expect(decide("https://example.com/")).toBe(true);
        expect(decide("app://ui/assets/app.js")).toBe(false);
    });

    it("refuses every permission request", () => {
        expect(recorded.permissionRequest).toHaveLength(1);
        let granted: boolean | undefined;
        (
            recorded.permissionRequest[0] as unknown as (
                c: unknown,
                p: string,
                cb: (g: boolean) => void,
            ) => void
        )(null, "notifications", (answer) => {
            granted = answer;
        });
        expect(granted).toBe(false);
    });

    it("answers every permission check with no", () => {
        expect(recorded.permissionCheck).toHaveLength(1);
        expect((recorded.permissionCheck[0] as unknown as () => boolean)()).toBe(false);
    });

    it("confines every page the app creates", () => {
        const created = recorded.appListeners.get("web-contents-created") as unknown as (
            event: unknown,
            contents: unknown,
        ) => void;
        expect(created).toBeDefined();
        const page = fakeContents();
        created(null, page.contents);
        expect(page.prevented("will-navigate", "https://example.com/")).toBe(true);
    });
});

describe("a page", () => {
    const page = fakeContents();
    confineContents(page.contents, "app://ui/index.html");

    it("cannot navigate or be redirected away, but may reload itself", () => {
        expect(page.prevented("will-navigate", "https://example.com/")).toBe(true);
        expect(page.prevented("will-redirect", "https://example.com/")).toBe(true);
        expect(page.prevented("will-navigate", "app://ui/other.html")).toBe(true);
        expect(page.prevented("will-navigate", "app://ui/index.html")).toBe(false);
    });

    it("cannot attach a webview", () => {
        expect(page.prevented("will-attach-webview")).toBe(true);
    });

    it("cannot open a window", () => {
        expect(page.open()).toEqual({ action: "deny" });
    });
});
