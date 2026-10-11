# Dependencies

Everything the app is built from or ships with must be declared in the repo and pinned to an exact version. A build must never depend on whatever happens to be installed on the machine.

## Rust crates

Managed by Cargo. `Cargo.toml` declares them, `Cargo.lock` pins exact versions.

- Add, remove, and upgrade with `cargo add`, `cargo remove`, and `cargo update`. Do not edit `Cargo.lock` by hand.
- Commit `Cargo.lock`. Use `--locked` in CI and scripts so builds fail instead of silently re-resolving.
- The Rust version is pinned in `rust-toolchain.toml`. Change it there, not per machine.

## Everything else

Cargo does not manage native libraries, build and packaging tools, GitHub Actions, git hooks, or non-Rust packages.

- Pin each one to an exact version in a file in the repo, using the ecosystem's lockfile where one exists. Pin GitHub Actions and git hooks to a full commit SHA with the version in a comment.
- Document how to obtain it in `CONTRIBUTING.md`, and install it the same way in CI.

## Licenses

Our own code is `MIT OR Apache-2.0`. The app is redistributed to users, so every dependency's license must allow that. Do not add a dependency with a copyleft or unknown license without asking first.

- Rust crates are checked by `cargo deny check` against the allow-list in `deny.toml`. Do not widen the list without approval.
- Approved exception: `libopenconnect` and its native dependencies (LGPL) are bundled. Each LGPL library must stay a separate, replaceable library file that is loaded at run time. Never link an LGPL library statically, into our own programs or into another library.
- Code under a licence in the `deny.toml` allow-list may be built into `libopenconnect` itself, either because openconnect's own source includes it or because the system library's version differs between distributions. `libopenconnect` stays replaceable, and that code's licence text and exact source still ship.
- The compiler's own runtime may be linked into a library. Ship its licence text and record where its source comes from.
- For every bundled LGPL library, each release must ship its license text and the exact source it was built from, including our patches.

## Updates

- Routine updates come from Dependabot (`.github/dependabot.yml`). Do not batch unrelated upgrades into feature PRs.
- Dependency changes use the `build` type, e.g. `build(deps): bump tokio from 1.40 to 1.41`.
