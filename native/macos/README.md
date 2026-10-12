# libopenconnect for macOS

Builds `libopenconnect` for macOS 13 or later on Apple silicon, from source, as a folder of libraries that can be dropped into the app and run on a Mac with nothing else installed.

## What gets built

| Component | Version | Licence | Libraries |
| --- | --- | --- | --- |
| openconnect | 9.21 | LGPL-2.1-only | `libopenconnect.5.dylib` |
| GnuTLS | 3.8.13 | LGPL-2.1-or-later | `libgnutls.30.dylib` |
| Nettle | 4.0 | LGPL-3.0-or-later or GPL-2.0-or-later | `libnettle.9.dylib`, `libhogweed.7.dylib` |
| GMP | 6.3.0 | LGPL-3.0-or-later or GPL-2.0-or-later | `libgmp.10.dylib` |

Download addresses and SHA-256 checksums are in `versions.env`. Every archive is checked before it is unpacked. There is one patch, in `patches/openconnect/`: it stops the library closing file descriptor 0 when a handle is freed that never made a command pipe. The Windows and Linux builds apply the same one.

The openconnect source is the upstream release archive, `openconnect-9.21.tar.gz`, not a git checkout: the archive comes with its build files already generated, so autoconf, automake and libtool are not needed. The commit that tag `v9.21` points at is recorded in `versions.env` for reference. The archive's PGP signature was checked by hand when the checksum was pinned; the build checks the checksum only. Built with the patch below, the library reports `v9.21-unknown`, as the Windows and Linux builds do; the workflow expects exactly that.

Everything else comes from macOS itself: `libxml2`, `zlib`, `libiconv`, and the Security and CoreFoundation frameworks.

Homebrew's copies of these libraries are not used, because they are built for the macOS version of the machine that made them, not for macOS 13.

## Building

On an Apple-silicon Mac with the Xcode version named in `versions.env`:

```sh
native/macos/build.sh build
SOURCE_COMMIT=$(git rev-parse HEAD) native/macos/bundle.sh build libopenconnect-macos-arm64
```

`build.sh` compiles everything into `build/prefix`. Nothing from Homebrew takes part: the scripts run with only the system folders on `PATH`, select the pinned Xcode themselves, and build their own `pkgconf` from a checksummed archive. `make` and `m4` are Xcode's.

`bundle.sh` writes the output folder. It refuses to finish unless every library:

- is arm64 and declares macOS 13.0 as its minimum;
- has no weak imports, which is how a function missing from macOS 13 would show up;
- loads only the other libraries in the folder and the system libraries listed above;
- contains no path from the build machine, and is signed.

The compiler also treats any use of a function newer than macOS 13 as an error.

## The output folder

| Path | Holds |
| --- | --- |
| `lib/` | The libraries, plus a pkg-config file that works wherever the folder is |
| `include/openconnect.h` | The header |
| `licenses/` | Licence texts for each component |
| `sources/` | The source archives the libraries were built from, and this recipe |
| `manifest.json` | The commit of this repository the output was built from (`recipe.commit`, as in the Windows manifest), each component's version, licence, minimum macOS and source checksum, and the tools used |

Each library finds the others next to itself (`@loader_path`), and `libopenconnect` is named `@rpath/libopenconnect.5.dylib`. A program that links it needs one search path pointing at the folder, for example `-Wl,-rpath,@executable_path/../Frameworks`.

The libraries are signed ad hoc. The app's release build must sign them again with the real identity.

## For the service that loads these

The service runs as root, so:

- **Clear three environment variables at start.** GnuTLS honours `SSLKEYLOGFILE` (writes session keys to that file), `GNUTLS_SYSTEM_PRIORITY_FILE` (replaces its settings file) and `GNUTLS_DEBUG_LEVEL`.
- **GnuTLS reads `/etc/gnutls/config`** if it exists. This is its usual system-wide settings file; only an administrator can create it.
- **The folder holding these libraries must be owned by root** and writable by nobody else. Whoever can replace a library there runs code as root.
- **Nettle and GMP are LGPLv3.** Users must be able to replace them with their own builds. If the app is ever signed with the hardened runtime, library validation blocks that unless it is allowed for.

## Choices worth knowing

- **GnuTLS, as on Windows.** It is built with no optional dependency: no p11-kit (smart cards), TPM, IDN host names or compression.
- **Trusted certificates** come from the macOS Keychain.
- **openconnect** is built without stoken, libpskc, libproxy, PC/SC, LZ4, Kerberos and translations. Its command-line client is built along the way but not shipped.
- **Possible later hardening:** switching off SRP, GOST, heartbeat and DTLS-SRTP in GnuTLS, and building releases without the CI cache.

## Not covered

- **Nothing has been run on macOS 13 itself.** The workflow builds on macOS 15 and runs the probe on macOS 14, the oldest Apple-silicon machine GitHub offers. That the libraries work on macOS 13 rests on the static checks above.
- Intel Macs.
- Signing or notarizing with a real identity.
- The probe accepts any certificate, so certificate checking against the Keychain is not exercised.
