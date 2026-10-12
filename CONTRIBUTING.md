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

The macOS and Linux artifacts hold a tarball to unpack, and the tests there build a small stand-in library with the system's C compiler (`cc`). `.github/workflows/engine.yml` has the exact steps.

The engine's login tests talk to a stand-in gateway in `crates/engine/tests/gateway/`, written for the Python version pinned in that workflow, with nothing beyond its standard library. Without it those tests are skipped and say so. To run them, make a throwaway key in a folder outside the repository and name the Python and the folder:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=vpn.example.test" -keyout <folder>/key.pem -out <folder>/cert.pem
UBC_VPN_TEST_PYTHON=<python> UBC_VPN_TEST_GATEWAY_DIR=<folder> cargo test -p ubc-vpn-engine --test fake_gateway
```

## Workflow

Branch from `main`, commit using Conventional Commits, and open a pull request whose title follows the same format. The full conventions are in [workflow](.claude/rules/workflow.md), [dependencies](.claude/rules/dependencies.md) and [security](.claude/rules/security.md).

CI runs `cargo fmt`, `cargo clippy` and `cargo test`. For the app it runs the lint, type check, unit tests and end-to-end tests. See `.github/workflows/ci.yml` and `.github/workflows/app.yml` for the exact commands.

The TypeScript types in `app/src/shared/protocol/` are generated from `crates/core` by `cargo test`. Never edit them by hand; change the Rust type, run the tests, and commit the result.

## Security

Never commit VPN profiles, credentials, keys, or logs. Report vulnerabilities privately with the "Report a vulnerability" button under the repository's Security tab, not in a public issue.
