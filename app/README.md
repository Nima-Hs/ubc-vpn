# UBC VPN app

The desktop app: a tray icon and one small window. It shows the state of the VPN and sends commands to the service. It makes no security decisions. The design is in [`docs/architecture.md`](../docs/architecture.md).

## Set up

You need Node (the version in [`.node-version`](.node-version)) and pnpm (the version in `packageManager` in [`package.json`](package.json); `corepack enable` installs it).

```sh
cd app
pnpm install
```

pnpm runs no dependency's install script unless [`pnpm-workspace.yaml`](pnpm-workspace.yaml) allows it. Only esbuild's is allowed. Electron downloads its binary the first time it runs.

## Run it

```sh
pnpm demo   # the interface with a fake service; no backend needed
pnpm dev    # the interface against the real service
```

Demo mode replaces the service and the login with in-memory fakes, so you can see every state. The fake login accepts anything you type. The fake settings check routes with a rough copy of the real rules. It adds a **Parts** screen that shows each shared component and has a button for every state. Demo code is left out of production builds, and `pnpm check:build` fails if any is found.

`pnpm dev` reaches the service through the command-line client, which it starts as `ubc-vpn bridge`. Set `UBC_VPN_CLI` to the client you built, for example `UBC_VPN_CLI=../target/debug/ubc-vpn pnpm dev`. Without it, or without a running service, the app shows "Service not running". An installed app ignores `UBC_VPN_CLI`.

To use a dev-mode service (one run as yourself with `ubc-vpn-service --dev`, with pretend routing and a pretend gateway), also set `UBC_VPN_DEV=1`. The app then starts the client with `--dev` first every time, passes on the two variables that say where a dev-mode service listens (`XDG_RUNTIME_DIR` on Linux, `TMPDIR` on macOS), and shows "Development mode. This is not the real VPN." on every screen. Only exactly `1` turns it on, and an installed app ignores it ([`src/main/channel/cli.ts`](src/main/channel/cli.ts)).

The app never uses the place Electron would choose for its own profile (Chromium's caches and preferences): on Windows and macOS that is the very folder the client keeps your `settings.json` in. That file is the client's, and the app never creates, reads or writes it. An installed app keeps its profile in a sub-folder named `app` of the client's settings folder, which on Linux it finds by the client's own rule (`XDG_CONFIG_HOME` only if it is an absolute path, otherwise `~/.config`). An app that is not installed keeps out of the installed product's folders altogether: it uses a folder named `UBC VPN App Dev` beside them, or the one `UBC_VPN_PROFILE` names. An installed app ignores that variable too ([`src/main/profile.ts`](src/main/profile.ts)).

## Check it

```sh
pnpm lint            # Biome: lint and format
pnpm format          # the same, fixing what it can
pnpm typecheck
pnpm test            # unit tests (Vitest)
pnpm test:e2e        # builds both builds and drives the real app (Playwright)
pnpm test:system     # the real app against the real client and a dev-mode service
pnpm build           # production build, into out/
pnpm check:build     # the production build contains no demo code
pnpm check:licenses  # everything shipped has an allowed licence
pnpm icons           # draws the app icon files in build/ again, after the mark changes
```

The end-to-end tests keep the app's window off the screen when run on your own computer, so they do not open windows over your work: they set `UBC_VPN_TEST_HIDDEN=1`, which an app that is not installed honours by never showing its window and making no tray icon, and an installed app ignores. In CI the window and the tray icon are shown, so the few tests about showing, hiding and closing to the tray run there and are skipped locally.

On your own computer they also never reach a real client, the installed service, your settings or your saved password: the apps they launch do not inherit `UBC_VPN_CLI`, `UBC_VPN_DEV` or any `UBC_VPN_SYSTEM_*` variable from your shell ([`tests/e2e/safe-env.ts`](tests/e2e/safe-env.ts)). A test that needs one sets it itself. On CI nothing is removed.

The end-to-end test saves a screenshot of every state to `test-results/screens`, or to `SCREENSHOT_DIR` if that is set. On Linux without a display, run it under `xvfb-run`.

`pnpm test:system` is the one test with no stand-in in it ([`tests/system/real.spec.ts`](tests/system/real.spec.ts)). It starts `ubc-vpn-service --dev`, starts the production build of the app with `UBC_VPN_DEV=1`, and drives the window: the service is found and claimed, routes are checked and saved, a login is answered, the connection comes up and goes down, a login is cancelled, a wrong password is refused. On CI the workflow builds the two programs and names them, as here:

```sh
cargo build --locked -p ubc-vpn-service --features dev-mode
cargo build --locked -p ubc-vpn-cli --features dev-mode
UBC_VPN_SYSTEM_SERVICE=../target/debug/ubc-vpn-service UBC_VPN_SYSTEM_CLI=../target/debug/ubc-vpn pnpm test:system
```

It runs on CI only: where `CI` is not set it is skipped and says why, because it starts real programs and a real channel, and someone's own computer may have a UBC VPN installed and in use. The app system workflow (`.github/workflows/app-system.yml`) runs it. Without the two variables it is skipped too, and says so. Everything it starts gets a home of its own in one temporary folder, which it removes; it never touches an installed UBC VPN. On Windows it stops at once if a dev-mode service of yours is already running, because the dev channel there is named after the user. Its screenshots go to `test-results/system-screens`, or to `SCREENSHOT_DIR`.

## How it is built

| Folder | What it is |
| --- | --- |
| `src/main` | The main process: window, tray, and the way to the service |
| `src/main/channel` | The bridge client: starts `ubc-vpn bridge` and exchanges JSON lines with it |
| `src/main/demo` | The fake service. Demo builds only |
| `src/preload` | The only bridge to the interface: a short, fixed list of functions |
| `src/renderer` | The interface: React, Tailwind, and the design system |
| `src/shared` | Types and wording both sides use |
| `src/shared/protocol` | Generated from the Rust types. Never edit these |
| `tests` | Unit tests, a mock bridge that follows the contract, and `e2e` |

The interface runs sandboxed with no Node access, loads only the app's own files under a strict Content-Security-Policy, and cannot navigate, open windows, or make a network request. The bridge client never logs a line it sends or receives.

The app never opens the service's pipe or socket itself. It starts the command-line client as `ubc-vpn bridge` and talks to it over standard input and output; the client is what checks that the other end really is the service. The contract is [`crates/core/src/bridge.rs`](../crates/core/src/bridge.rs), and `tests/mock-bridge.mjs` follows it. The app never sends `connect` through the bridge, so it never holds a session cookie. The bridge is started with no shell, its own short list of environment variables (`BRIDGE_ENV`), and its standard error discarded; it is ended when the app lets go of it.

Logging in works the same way. The app starts the client as `ubc-vpn connect --json`, shows the user each question the client asks, and writes each answer to the client's standard input ([`src/main/channel/connect.ts`](src/main/channel/connect.ts); the contract is [`crates/core/src/login.rs`](../crates/core/src/login.rs), and `tests/mock-cli.mjs` follows it). The client talks to the gateway and gives the session cookie to the service, so the app never sees it. An answer may be a password: it goes from the field to the client once and is kept nowhere, not in the state the interface is sent, not in an error and not in a log. The app passes the client no routes; the client reads the user's settings itself. The questions are shown by [`src/renderer/src/views/login-view.tsx`](src/renderer/src/views/login-view.tsx): what is typed stays in the field until Continue is pressed, is handed over once, and the field is wiped. Escape, Cancel, or putting the window away gives a login up. The client's last line, not the cancel, says what happened: if the service had already been asked to connect, or the client gives no last line in time, the app asks the service to disconnect, and shows the login as given up only then. Until then the screen says "Cancelling". If the service cannot be reached at that moment, the disconnect is sent once more when the bridge is next ready, and the screen meanwhile shows what has happened to the service. That second try has thirty seconds from the cancel; after that it is dropped, because by then it could take down a connection made some other way. If the user quits while a cancelled login is still being wound up, the quit waits for it, for at most three seconds; a quit in the middle of a login nobody cancelled sends nothing ([`src/main/login.ts`](src/main/login.ts), [`src/main/quit.ts`](src/main/quit.ts)). Text from the gateway is made one plain line in the main process before it is shown: control characters, newlines and the characters that reverse text direction are removed. The client is started at most once every three seconds, so no number of presses can send MFA requests in a stream, and Connect from the tray shows the window first.

The user's settings go the same way. The app never opens `settings.json` or the policy file: it runs `ubc-vpn settings get`, `check-routes` and `set-routes` ([`src/main/channel/settings.ts`](src/main/channel/settings.ts); the contract is [`crates/core/src/settings_cli.rs`](../crates/core/src/settings_cli.rs), and `tests/mock-settings.mjs` follows it). The rules for routes therefore exist once, in the client, and are the ones the service applies when it connects. Routes the user typed go to the client on standard input, never on its command line. Text read from the settings file is made safe to show before the interface gets it; in a route or a domain, anything removed leaves a mark (U+FFFD) in its place, so a stored entry that is not what it seems is refused by the check and does not pass for a good one. The Routes screen ([`src/renderer/src/views/routes-view.tsx`](src/renderer/src/views/routes-view.tsx)) checks the stored routes when it opens and what is typed a moment after the typing stops, marks each problem on its own row, and saves only what has just been checked. A screen with unsaved changes is not left until the user says what to do with them ([`src/renderer/src/lib/navigation.ts`](src/renderer/src/lib/navigation.ts)).

The real `ubc-vpn connect` is not built yet, so a login has only been run against the demo's fake and the mock client in the tests. The first run against UBC is Milestone 1.

Where the client sits in an installed app is in [`src/main/channel/cli.ts`](src/main/channel/cli.ts) and nowhere else. That place is provisional until the installers exist.

Ctrl or Cmd with plus, minus and zero enlarge, shrink and reset the interface. The window grows with it.

Each of these protections has a test in `tests/security.test.ts` that fails when it is removed, and the end-to-end test checks them again in the running app. When you add a protection, add its test, then remove the protection and watch the test fail.

### Remote debugging

The service's log reaches the interface through one place in the main process ([`src/main/logs/book.ts`](src/main/logs/book.ts)). Every line is checked there against the contract, refused if it carries anything the contract does not name, and its text made one plain line of bounded length, whatever the service did to it; the service redacts, and this is the app's own second look. The app follows the contract's order (watch first, then read), takes each line once by its number, reads a gap again once and then accepts it, starts afresh when the service has, and keeps at most a thousand lines. The log is closed again when the window is put away or its page reloads. A diagnostics report is put together in the main process and goes to the clipboard, only when asked for, and never to disk. The main process cannot see a key press, so it holds a request to copy to what a user's own press looks like: the log is open, the window is the one in use, and the last copy was a few seconds ago at least ([`src/main/logs/report.ts`](src/main/logs/report.ts)). None of this is in a production build yet: `__LOGS__` in `electron.vite.config.ts` leaves it out until the app can ask the real service, and `pnpm check:build` fails if any of it is found. Today only the demo build has it, against a pretend service.

Chromium's `--remote-debugging-port`, `--remote-debugging-pipe` and `--remote-debugging-address` let anything on the computer take over the interface, and no Electron fuse turns them off. The app removes them from its own command line before anything reads it. A production build always does, packaged or not, and so does anything packaged. Only a run that is not packaged and is a demo build, a development build, or in dev mode (`UBC_VPN_DEV=1`) keeps them, because Playwright drives the app through that port. Whether a run is in dev mode is decided once, so a run that keeps the port is never one whose client talks to the real service. `tests/e2e/remote-debugging.spec.ts` starts the production build with the switch and checks that nothing answers, whatever else the dev switch is set to, and that in dev mode something does.

### The tray

Closing the window hides it and leaves the app in the tray, but only where there is a way back to a hidden window. macOS always has the Dock, and Windows always has a tray. GNOME has no tray unless an extension adds one, and Electron cannot tell, so on GNOME without Ubuntu's extension closing the window quits the app. Starting the app a second time always brings the window back.

The tray icon is the app's mark, drawn for each state in a shape of its own: off, both lines thin; working, the upper line wide and in moving dashes (three pictures, stepped only while working); on, the upper line wide and whole; needs attention, a triangle over the lower line's end; a problem, a diamond there. On Windows and Linux each state also has its colour from the tokens (neutral, accent, green, amber, red), with a dark rim so it shows on a dark taskbar and a light one. macOS tints it itself, so there the shapes alone tell the states apart. A click on it shows the window. On Windows the window's taskbar button shows the very same picture while the window is open, working frames included: one timer and one state drive both (`createStateIcons` in [`src/main/tray-icon.ts`](src/main/tray-icon.ts)), stepping only while working and something is on screen to paint. The button reads each picture from an `.ico` in `build/state-icons` (shipped as `resources/state-icons`), because Windows is then handed every size it asks for exactly as drawn. The program's own icon, in the Start menu and the install folder, stays the app icon.

The app icon (the program, the Start menu, the setup program) is the mark on the app's dark surface. It is drawn in code from the same description as the tray icon and the title bar's mark ([`src/shared/mark.ts`](src/shared/mark.ts), [`src/main/icon`](src/main/icon)), and written to `build/` by `pnpm icons`; `tests/icons.test.ts` fails if the files there are out of date. No image tool is used.

Not yet checked on a real desktop, and to be checked before the first release: the tray on macOS and on Linux (GNOME with and without the extension, KDE), the rimmed icon on a light Windows taskbar, and the click on Windows.

Every word the app shows about the connection is in [`src/shared/copy.ts`](src/shared/copy.ts). The window and the tray both read from it.

## The design system

One rule: **a screen never styles anything by hand.** Colours, sizes, radii, shadows and motion come from tokens. Controls come from the shared components. `tests/design-rules.test.ts` enforces this.

- **Tokens** are in [`src/renderer/src/styles/tokens.css`](src/renderer/src/styles/tokens.css). Primitives (`--ink-900`) name a value and are used only in that file. Roles (`--c-surface`) name a job and are what components use.
- **Tailwind** is wired to the tokens in [`styles/app.css`](src/renderer/src/styles/app.css). Its default palette, type scale, radii and shadows are switched off, so `bg-blue-500` and `rounded-2xl` do not exist; `bg-surface` and `rounded-lg` do.
- **Components** are in [`src/renderer/src/components/ui`](src/renderer/src/components/ui): `Button`, `IconButton`, `StatusIndicator`, `Panel`, `List` and `ListRow`, `TextField`, `Tooltip`, and `Heading`, `Subheading` and `Text`.
- **Screens** are in `src/renderer/src/views`. A screen arranges components with layout classes (`flex`, `gap-4`, `px-5`) and nothing else. To add a screen, add it to the list in `App.tsx`; the switcher, a row under the title bar that names every screen, appears when there is more than one and has room for four.

If a screen needs something the components cannot do, change the component or add a token. Do not reach past them.

### Adding to it

- A new colour is a new role in `tokens.css` that points at a primitive, plus a line in `app.css`. Add its text and background pairs to `tests/tokens.test.ts`, which measures contrast and fails below WCAG AA.
- A light theme is a second set of roles under `[data-theme="light"]` in `tokens.css`. No component changes.
- A shadcn/ui component is copied into `components/ui` and restyled with tokens before use. Add only what a screen needs.

### Why it looks like this

- **Dark, and not tied to the OS theme.** The app looks the same on Windows, macOS and Linux. Fonts are bundled; the window draws its own title bar.
- **The accent is a clear blue ("tide").** It marks the one main action and the keyboard focus ring. Green, amber and red are kept for state: connected, needs attention, failed. So the accent never has to mean "good" or "bad".
- **Filled buttons are light with dark text.** That clears WCAG AA with room to spare, which white text on a mid blue struggles to do.
- **Instrument Sans** for the interface: narrow enough for a small window, plain enough to disappear. **Geist Mono** for addresses and subnets, which are read one character at a time.
- **The diagram is the app's one picture.** One line leaves this computer and splits: a wide lane to UBC that fills when the VPN is on, and a thin lane for everything else that is always there. That is split tunnelling.
- **Motion is short and has a reason.** New text settles in over 240 ms, the tunnel fills over 420 ms, a pressed button shrinks to 96%. With reduced motion on, things fade and nothing moves.
- **What loops never jumps.** The "working" pulse, the breathing status mark and the spinner all run on the page's clock ([`lib/steady-loop.ts`](src/renderer/src/lib/steady-loop.ts)), so a change of state or screen picks each one up where it was instead of starting it again, and each fades out still moving when the work ends.

## Dependencies

Every version is exact, and `pnpm-lock.yaml` is committed. Packages under `dependencies` are shipped in the app; their licences must be on the list in [`allowed-licenses.json`](allowed-licenses.json). The fonts' licence, OFL-1.1, is approved for the two font packages named there and for nothing else. It requires its text to travel with the fonts: the check confirms each font package has a `LICENSE` file, and packaging, when it is added, must copy those files into the installed app alongside the other licence notices. The build does not do that yet. Build tools are under `devDependencies`. Electron is there too, as packaging requires, but it is shipped and so is checked as well.
