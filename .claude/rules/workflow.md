# Workflow

Trunk-based development with Conventional Commits. `main` is the only long-lived branch and is always releasable.

## Branches

- Never commit directly to `main`. Start every piece of work on a new branch from an up-to-date `main`.
- Name branches `<type>/<short-description>` or `<type>/<issue-number>-<short-description>`: lowercase kebab-case, 50 characters or fewer. Examples: `feat/split-tunnel`, `fix/12-dns-leak-on-reconnect`.
- Keep branches short-lived and focused on one change. Rebase on `main`; do not merge `main` into the branch.
- Integrate through a squash-merged pull request, then delete the branch. No `develop` or release branches.
- Branches created by bots (for example `dependabot/*`) are exempt from the naming format.

## Commits and PR titles

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/): `<type>[(scope)][!]: <description>`.

- Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- Description: imperative mood, lowercase, no trailing period, 72 characters or fewer.
- The body explains what and why, not how. Reference issues in footers: `Closes: #12`.
- Breaking changes: add `!` before the colon and a `BREAKING CHANGE: <description>` footer.
- One logical change per commit.
- A PR title uses the same format. It becomes the commit on `main` and a changelog line, so describe the effect for users, not the implementation.

## Versions and changelog

Versions follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). `CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/). Both are generated from the commits on `main` at release time.

- Never hand-edit the version number or `CHANGELOG.md`, and never create tags by hand.
- The commit type decides the version bump and the changelog section, so choose it accurately:

  | Commit                  | Bump before 1.0.0 | Bump from 1.0.0 | Changelog section |
  | ----------------------- | ----------------- | --------------- | ----------------- |
  | Breaking change (`!`)   | minor             | major           | marked breaking   |
  | `feat`                  | patch             | minor           | `Added`           |
  | `fix`                   | patch             | patch           | `Fixed`           |
  | `perf`, `refactor`      | patch             | patch           | `Changed`         |
  | All other types         | patch             | patch           | omitted           |

- Releases are tags on `main` named `vX.Y.Z`.
- Release automation is not set up yet. It is added before the first release.
