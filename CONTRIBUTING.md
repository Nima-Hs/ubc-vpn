# Contributing

## Setup

Install Rust with [rustup](https://rustup.rs/). It picks up the version pinned in `rust-toolchain.toml`.

Install [prek](https://prek.j178.dev/) and enable the git hooks once per clone:

```sh
cargo install --locked prek   # or: winget install j178.Prek
prek install
```

The hooks are defined in `.pre-commit-config.yaml`, so [pre-commit](https://pre-commit.com/) works too.

## Workflow

Branch from `main`, commit using Conventional Commits, and open a pull request whose title follows the same format. The full conventions are in [workflow](.claude/rules/workflow.md), [dependencies](.claude/rules/dependencies.md) and [security](.claude/rules/security.md).

CI runs `cargo fmt`, `cargo clippy` and `cargo test`; see `.github/workflows/ci.yml` for the exact commands.

## Security

Never commit VPN profiles, credentials, keys, or logs. Report vulnerabilities privately with the "Report a vulnerability" button under the repository's Security tab, not in a public issue.
