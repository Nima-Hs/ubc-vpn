# Consistency across Windows, macOS and Linux

UBC VPN is one product on three systems. The app's screens, its settings, the command-line client, updates, and how the VPN behaves must be the same on each.

## The same everywhere

- **The app.** Every screen, its layout, colours, type, words, and states (connecting, connected, errors, empty) are the same. The screens are one React app; do not add a screen, a setting, or a control on one system only.
- **The command-line client.** The same commands, options, output, JSON, exit codes, and help text. A message may name a system's own tool, such as the command that starts the service, but its wording and shape stay the same.
- **Settings and profiles.** One file format and the same options with the same defaults. An option that cannot work on a system is shown and explained there, not hidden.
- **Updates.** One flow and one "Automatic updates" setting on all three, as `docs/architecture.md` describes. Until automatic updates are built, a new installer is the update on every system.
- **Behaviour.** The same rules for routes, DNS, full tunnel, saved passwords, reconnecting, and failing closed, with the same results the user can see. Where a system cannot enforce a protection at all, `docs/architecture.md` records the gap and what covers it instead.

## Different on purpose

These follow each system's own conventions and are the only allowed differences:

- The tray or menu bar icon, or none on a desktop without a tray; the macOS app menu; whether closing the window keeps the app running; the window's title bar buttons; and keyboard shortcuts (⌘ on macOS, Ctrl elsewhere).
- The administrator prompt (UAC, the macOS password or Touch ID prompt, the Linux password prompt), and the system's own notices, such as Gatekeeper's check of an unsigned package and the macOS background item notice.
- Where passwords are saved (Credential Manager, Keychain, the desktop's Secret Service).
- How the service is registered, started and stopped (a Windows service, a launchd daemon, a systemd unit).
- The installer format (`.exe`, `.pkg`, `.deb` and `.rpm`), where files are installed, and where the policy, state and settings are kept.
- How "start at sign-in" is registered.

Anything else that differs is a bug. A feature is done only when it works on all three systems, or the pull request says which system follows and why, and an issue tracks it.

## Checked by tests

These checks are added with the macOS and Linux port:

- The command-line client's help text is the same on all three systems, apart from lines the help text marks as specific to one system.
- The app's main screens are captured as screenshots on all three systems in CI and compared.
