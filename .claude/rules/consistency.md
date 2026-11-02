# Consistency across Windows, macOS and Linux

UBC VPN is one product on three systems. The app's screens, its settings, the command-line client, updates, and how the VPN behaves must be the same on each.

## The same everywhere

- **The app.** Every screen, its layout, colours, type, words, and states (connecting, connected, errors, empty) are the same. The screens are one React app; do not add a screen, a setting, or a control on one system only.
- **The command-line client.** The same commands, options, output, JSON, exit codes, and help text. A message may name a system's own tool, such as the command that starts the service, but its wording and shape stay the same.
- **Settings and profiles.** One file format and the same options with the same defaults. An option that cannot work on a system is shown and explained there, not hidden.
- **Updates.** The same flow on all three: check and download in the background, verify with the release key, a "Restart to update" button, one administrator prompt, relaunch, and the same "Automatic updates" setting.
- **Behaviour.** The same rules for routes, DNS, full tunnel, saved passwords, reconnecting, and failing closed. A rule enforced on one system is enforced on all.

## Different on purpose

These follow each system's own conventions and are the only allowed differences:

- Where the tray or menu bar icon lives, and the window's title bar buttons.
- The administrator prompt (UAC, the macOS password or Touch ID prompt, the Linux password prompt).
- Where passwords are saved (Credential Manager, Keychain, the desktop's Secret Service).
- The installer format (`.exe`, `.pkg`, `.deb` and `.rpm`) and where files are installed.
- How "start at sign-in" is registered.

Anything else that differs is a bug. A feature is done only when it works on all three systems, or the pull request says which system follows and why, and an issue tracks it.

## Checked by tests

- The command-line client's help text is the same on all three systems, apart from lines marked as specific to one.
- The app's main screens are photographed on all three systems in CI and compared.
