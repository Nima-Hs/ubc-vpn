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
- Approved exception: Process Monitor, Microsoft's tracing tool, is not pinned. Only the Windows native workflow uses it, in `native/windows/tests/trace.sh`, to record what the probe touches. It is never shipped.
  - It is downloaded on each run from `https://live.sysinternals.com/Procmon64.exe`. Microsoft publishes only the current version there, with no versioned address, so a pinned checksum would stop matching whenever the file is replaced and the old version could not be fetched again.
  - Before it runs, the script requires a valid Authenticode signature whose publisher is Microsoft Corporation, and prints the version in the log.
  - It runs as administrator, in a job of its own, on a machine that uploads nothing. That job works on a copy of the output and gives the rest of the workflow only its result, pass or fail.
  - The output that ships is uploaded by another job, on a machine that never ran Process Monitor. That job checks every file against SHA-256 checksums recorded by the build job, and checks the list of them against a checksum the build job gave out as a job output.
  - So a tampered Process Monitor could report a clean trace, but could not change what ships. The signature check is what we rely on for the trace's verdict.
  - Each machine is GitHub's and is discarded after the run, and the workflow uses no secrets and has read-only access to the repository.
- Approved exception: the MSYS2 base that the Windows native build runs in is not pinned. The build uses the MSYS2 already installed on GitHub's `windows-latest` runner, which changes when GitHub updates the image.
  - Pinned, by file name and SHA-256: the build tools in `native/windows/tools.lock` and the compiler and libraries in `native/windows/packages.lock`. `build.sh` stops if the installed ones differ.
  - Not pinned: everything those run on, such as the shell, coreutils, tar, curl, gpg and pacman.
  - It could be pinned by starting from a dated `msys2-base` archive with a known checksum instead of the runner's copy. That is not done yet.
  - Nothing from the base ships: every DLL in the output comes from our own build or from a package in `packages.lock`, and the build stops on any other. The output's `build-packages.txt` records every installed package and its version, and the workflow's tests run on the output itself.

## Licenses

Our own code is `MIT OR Apache-2.0`. The app is redistributed to users, so every dependency's license must allow that. Do not add a dependency with a copyleft or unknown license without asking first.

- Rust crates are checked by `cargo deny check` against the allow-list in `deny.toml`. Do not widen the list without approval.
- Approved exception: `libopenconnect` and its native dependencies (LGPL) are bundled. Each LGPL library must stay a separate, replaceable library file that is loaded at run time. Never link an LGPL library statically, into our own programs or into another library.
- Code under a licence in the `deny.toml` allow-list may be built into `libopenconnect` itself, either because openconnect's own source includes it or because the system library's version differs between distributions. `libopenconnect` stays replaceable, and that code's licence text and exact source still ship.
- The compiler's own runtime may be linked into a library. Ship its licence text and record where its source comes from.
- Approved exception: fonts under the SIL Open Font License 1.1 may be bundled with the app. This covers font files only, not code. The fonts stay under that licence, not ours. Ship each font's copyright notice and licence text. Do not bundle a font that declares a Reserved Font Name: the packaged files are converted and subsetted, which counts as a modified version.
- Approved exception: Wintun, the Windows tunnel driver, is bundled as the prebuilt signed `wintun.dll` downloaded from wintun.net/builds, under its licence for prebuilt binaries. That licence is not open source and allows redistribution only on these terms:
  - It is used only through the API in `wintun.h`.
  - It is distributed only inside our installer, next to the programs that use it, never as a file or release asset by itself.
  - It is not modified in any way: not patched, not re-signed, and nothing is extracted from it. Never build it ourselves.
  - Its version and checksum are pinned, and its licence text ships with it.
- For every bundled LGPL library, each release must ship its license text and the exact source it was built from, including our patches.

## Updates

- Routine updates come from Dependabot (`.github/dependabot.yml`). Do not batch unrelated upgrades into feature PRs.
- Dependency changes use the `build` type, e.g. `build(deps): bump tokio from 1.40 to 1.41`.
