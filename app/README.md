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

Demo mode replaces the service with an in-memory fake, so you can see every state. It adds a **Components** screen that shows each shared component and has a button for every state. Demo code is left out of production builds, and `pnpm check:build` fails if any is found.

`pnpm dev` reaches the service through the command-line client, which it starts as `ubc-vpn bridge`. Set `UBC_VPN_CLI` to the client you built, for example `UBC_VPN_CLI=../target/debug/ubc-vpn pnpm dev`. Without it, or without a running service, the app shows "Service not running". An installed app ignores `UBC_VPN_CLI`. Connecting needs login, which is a later feature.

## Check it

```sh
pnpm lint            # Biome: lint and format
pnpm format          # the same, fixing what it can
pnpm typecheck
pnpm test            # unit tests (Vitest)
pnpm test:e2e        # builds demo mode and drives the real app (Playwright)
pnpm build           # production build, into out/
pnpm check:build     # the production build contains no demo code
pnpm check:licenses  # everything shipped has an allowed licence
```

The end-to-end test saves a screenshot of every state to `test-results/screens`, or to `SCREENSHOT_DIR` if that is set. On Linux without a display, run it under `xvfb-run`.

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

Where the client sits in an installed app is in [`src/main/channel/cli.ts`](src/main/channel/cli.ts) and nowhere else. That place is provisional until the installers exist.

Ctrl or Cmd with plus, minus and zero enlarge, shrink and reset the interface. The window grows with it.

Each of these protections has a test in `tests/security.test.ts` that fails when it is removed, and the end-to-end test checks them again in the running app. When you add a protection, add its test, then remove the protection and watch the test fail.

### The tray

Closing the window hides it and leaves the app in the tray, but only where there is a way back to a hidden window. macOS always has the Dock, and Windows always has a tray. GNOME has no tray unless an extension adds one, and Electron cannot tell, so on GNOME without Ubuntu's extension closing the window quits the app. Starting the app a second time always brings the window back.

The tray icon is light with a dark rim, so it shows on a dark taskbar and a light one; macOS tints it itself. A click on it shows the window.

Not yet checked on a real desktop, and to be checked before the first release: the tray on macOS and on Linux (GNOME with and without the extension, KDE), the rimmed icon on a light Windows taskbar, and the click on Windows.

Every word the app shows about the connection is in [`src/shared/copy.ts`](src/shared/copy.ts). The window and the tray both read from it.

## The design system

One rule: **a screen never styles anything by hand.** Colours, sizes, radii, shadows and motion come from tokens. Controls come from the shared components. `tests/design-rules.test.ts` enforces this.

- **Tokens** are in [`src/renderer/src/styles/tokens.css`](src/renderer/src/styles/tokens.css). Primitives (`--ink-900`) name a value and are used only in that file. Roles (`--c-surface`) name a job and are what components use.
- **Tailwind** is wired to the tokens in [`styles/app.css`](src/renderer/src/styles/app.css). Its default palette, type scale, radii and shadows are switched off, so `bg-blue-500` and `rounded-2xl` do not exist; `bg-surface` and `rounded-lg` do.
- **Components** are in [`src/renderer/src/components/ui`](src/renderer/src/components/ui): `Button`, `IconButton`, `StatusIndicator`, `Panel`, `List` and `ListRow`, `TextField`, `Tooltip`, and `Heading`, `Subheading` and `Text`.
- **Screens** are in `src/renderer/src/views`. A screen arranges components with layout classes (`flex`, `gap-4`, `px-5`) and nothing else. To add a screen, add it to the list in `App.tsx`; the switcher in the title bar appears when there is more than one.

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

## Dependencies

Every version is exact, and `pnpm-lock.yaml` is committed. Packages under `dependencies` are shipped in the app; their licences must be on the list in [`allowed-licenses.json`](allowed-licenses.json). The fonts' licence, OFL-1.1, is approved for the two font packages named there and for nothing else. It requires its text to travel with the fonts: the check confirms each font package has a `LICENSE` file, and packaging, when it is added, must copy those files into the installed app alongside the other licence notices. The build does not do that yet. Build tools are under `devDependencies`. Electron is there too, as packaging requires, but it is shipped and so is checked as well.
