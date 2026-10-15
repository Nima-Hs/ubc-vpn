# Contributing

## Setup

Install Rust with [rustup](https://rustup.rs/). It picks up the version pinned in `rust-toolchain.toml`.

Install [prek](https://prek.j178.dev/) and enable the git hooks once per clone:

```sh
cargo install --locked prek   # or: winget install j178.Prek
prek install
```

The hooks are defined in `.pre-commit-config.yaml`, so [pre-commit](https://pre-commit.com/) works too.

To work on the app in `app/`, install the [Node.js](https://nodejs.org/) version named in `app/.node-version`, then let it provide the pinned [pnpm](https://pnpm.io/):

```sh
corepack enable
cd app
pnpm install --frozen-lockfile
```

The pnpm version is the `packageManager` field of `app/package.json`. `app/README.md` has the commands for running and testing the app.

Ordinary builds and tests need no native library. Only the engine's `libopenconnect` feature does, and it takes our own build of it, never one installed on the system. Download the artifact of the newest `Native library` run on `main` for your OS, unpack it into an empty folder, and name that folder:

```sh
gh run list --workflow native-windows.yml --branch main --event push --status success --limit 1
gh run download <run-id> --name libopenconnect-windows-x64 --dir <folder>
UBC_VPN_NATIVE_DIR=<folder> cargo test -p ubc-vpn-engine --features libopenconnect,fake
```

The command-line client and the service connect for real only when built with their `real-engine` feature, which takes the same folder. They load the library from the folder the program is in, and from nowhere else, so on Windows put the libraries beside the programs after building:

```sh
UBC_VPN_NATIVE_DIR=<folder> cargo build -p ubc-vpn-cli --features real-engine
UBC_VPN_NATIVE_DIR=<folder> cargo build -p ubc-vpn-service --features real-engine
native/windows/stage.sh <folder> target/debug
```

`stage.sh` also downloads the Wintun pinned in `native/windows/wintun.pin` and checks its checksum. That copy is for your own machine only: Wintun's licence lets us pass it on only inside our installer. Build each program with `-p`, not `--workspace`, so no other crate's features are switched on for it. A build with `real-engine` and `dev-mode` together refuses to run as the installed service. `ubc-vpn connect` then logs in to the gateway named in the installed policy. The service, in installed mode, needs administrator rights and the installed policy and state folders, so until the installer exists run it only on a machine you can reset.

The macOS and Linux artifacts hold a tarball to unpack, and the tests there build a small stand-in library with the system's C compiler (`cc`). `.github/workflows/engine.yml` has the exact steps.

The engine's login tests talk to a stand-in gateway in `crates/engine/tests/gateway/`, written for the Python version pinned in that workflow, with nothing beyond its standard library. Without it those tests are skipped and say so. To run them, make a throwaway key in a folder outside the repository and name the Python and the folder:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=vpn.example.test" -keyout <folder>/key.pem -out <folder>/cert.pem
UBC_VPN_TEST_PYTHON=<python> UBC_VPN_TEST_GATEWAY_DIR=<folder> cargo test -p ubc-vpn-engine --test fake_gateway
```

The tunnel tests that create a real tunnel device run only with `UBC_VPN_TEST_DEVICE` set, which only the engine workflow sets: on a Windows runner, as administrator, with the Wintun pinned in `native/windows/wintun.pin` beside the test programs. Do not set it on your own machine; without it those tests are skipped and say so.

## Development mode

Development mode runs the real service, the real command-line client and the app together as yourself, with no admin rights. Routing, DNS and the gateway are pretend: nothing on your network changes and nothing is sent to UBC. It is the only way to run the three together today, because the real VPN engine is not connected yet.

The commands below are for a POSIX shell, run from the repository root. On Windows use Git Bash.

### Build

```sh
cargo build --locked -p ubc-vpn-service --features dev-mode
cargo build --locked -p ubc-vpn-cli --features dev-mode
```

Build each program by itself with `-p`, as shown. The programs are `target/debug/ubc-vpn-service` and `target/debug/ubc-vpn`. Without the feature neither knows `--dev`, and the service stops at once, saying it has no VPN engine yet.

### Where it keeps its files

Dev mode has a folder and a channel of its own, so it never reads or changes an installed UBC VPN.

| | Dev folder | Channel |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\UBC VPN Dev\` | the pipe `ubc-vpn-dev-<your SID>` |
| macOS | `~/Library/Application Support/UBC VPN Dev/` | `$TMPDIR/ubc-vpn-dev-<your user ID>/service.sock` |
| Linux | `$XDG_CONFIG_HOME/ubc-vpn-dev/`, or `~/.config/ubc-vpn-dev/` | `$XDG_RUNTIME_DIR/ubc-vpn-dev-<your user ID>/service.sock` |

The dev folder holds `policy/policy.json`, `state/state.json` and `settings/settings.json`. On macOS and Linux the socket goes under `/tmp` when the variable is unset or not an absolute path. To start afresh, stop the service and delete the dev folder.

### Write the policy

The service reads its policy from the dev folder and does not create it. Make the `policy` folder inside the dev folder and save this as `policy.json` in it:

```json
{"gateway":"vpn.example.test","pins":["pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}
```

Both values are made up. The pretend gateway presents the first pin in this file, so any well-formed pin is accepted. Without the file the service stops with "The policy file cannot be read".

### Start the service

```sh
target/debug/ubc-vpn-service --dev
```

It says it is running and stays in the foreground. One user can run one dev-mode service: a second one stops with "The channel could not be opened: already exists".

### Use the command-line client

`--dev` goes first, before the command. In another terminal:

```sh
target/debug/ubc-vpn --dev status
echo '{"subnets":["10.255.0.0/24"],"dns_domains":["ece.example.test"]}' | target/debug/ubc-vpn --dev settings set-routes --json
target/debug/ubc-vpn --dev settings get --json
target/debug/ubc-vpn --dev connect
target/debug/ubc-vpn --dev status
target/debug/ubc-vpn --dev disconnect
```

- The first `status`, `connect` or `disconnect` that reaches the service makes you its owner.
- `connect` uses the saved routes. With none saved it ends with `route_refused`, so save some first, as above or in the app.
- `connect` needs a terminal. It asks three questions, and the pretend gateway accepts exactly one answer to each: username `alice`, password `correct-horse-battery`, one-time code `123456`. These are made up and are compiled only into a dev-mode build. Any other answer is refused as a wrong password.
- The username is saved after a connect that worked and is not asked for again. A refused login forgets it.
- While connected, `status` shows the pretend tunnel `fake0` with the address `10.255.0.2`.

`target/debug/ubc-vpn help` lists every command and exit status.

### Start the app against it

With the service running, and the app's packages installed as in Setup:

```sh
cd app
UBC_VPN_CLI=../target/debug/ubc-vpn UBC_VPN_DEV=1 pnpm dev
```

- `UBC_VPN_CLI` names the client you built. The app starts it for everything it does.
- `UBC_VPN_DEV=1` has the app start that client with `--dev`. Only exactly `1` turns it on. The app then shows "Development mode. This is not the real VPN." on every screen.
- `UBC_VPN_PROFILE` is optional. It names the folder for the app's own profile, which is Chromium's caches and preferences. Without it an app that is not installed uses a folder named `UBC VPN App Dev`, beside the installed product's folders and never inside them.

An installed app ignores all three variables. Log in with the same made-up answers as above.

`pnpm demo` is something else: the interface alone, with no client and no service. `app/README.md` describes it.

### The tests that run it

Two tests run the real programs together in dev mode. Each makes a temporary home of its own and removes it, so neither touches your dev folder. On Windows the pipe is named after the user and not the home, so both stop at once if a dev-mode service of yours is running.

```sh
UBC_VPN_SYSTEM_SERVICE=<absolute path of ubc-vpn-service> cargo test --locked -p ubc-vpn-cli --features dev-mode --test system -- --nocapture
```

The other drives the app's window as well; `app/README.md` has its command (`pnpm test:system`). Both are skipped, and say so, when the variables that name the programs are not set. `.github/workflows/system.yml` and `.github/workflows/app-system.yml` run them on all three OSes.

### Never ship it

A program built with `dev-mode` must never be released or installed: it can be told to trust a pretend gateway and to apply no routes. A release builds each program by itself with `-p` and without the feature, and CI fails if the service or the client would be built with any feature that has `dev`, `fake` or `debug` in its name (`.github/workflows/ci.yml`).

## Workflow

Branch from `main`, commit using Conventional Commits, and open a pull request whose title follows the same format. The full conventions are in [workflow](.claude/rules/workflow.md), [dependencies](.claude/rules/dependencies.md) and [security](.claude/rules/security.md).

CI runs `cargo fmt`, `cargo clippy` and `cargo test`. For the app it runs the lint, type check, unit tests and end-to-end tests. See `.github/workflows/ci.yml` and `.github/workflows/app.yml` for the exact commands.

The TypeScript types in `app/src/shared/protocol/` are generated from `crates/core` by `cargo test`. Never edit them by hand; change the Rust type, run the tests, and commit the result.

## Security

Never commit VPN profiles, credentials, keys, or logs. Report vulnerabilities privately with the "Report a vulnerability" button under the repository's Security tab, not in a public issue.
