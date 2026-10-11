# libopenconnect for macOS

Builds `libopenconnect` for macOS 13 or later on Apple silicon, from source, as a folder of libraries that can be dropped into the app and run on a Mac with nothing else installed.

## What gets built

| Component | Version | Licence | Libraries |
| --- | --- | --- | --- |
| openconnect | 9.21 | LGPL-2.1-only | `libopenconnect.5.dylib` |
| GnuTLS | 3.8.13 | LGPL-2.1-or-later | `libgnutls.30.dylib` |
| Nettle | 4.0 | LGPL-3.0-or-later or GPL-2.0-or-later | `libnettle.9.dylib`, `libhogweed.7.dylib` |
| GMP | 6.3.0 | LGPL-3.0-or-later or GPL-2.0-or-later | `libgmp.10.dylib` |

Exact versions, download addresses and SHA-256 checksums are in `versions.env`. openconnect is fetched with git and checked against a pinned commit. There are no patches.

Everything else comes from macOS itself: `libxml2`, `zlib`, `libiconv` and the Security framework.

Homebrew's copies of these libraries are not used, because they are built for the macOS version of the machine that made them, not for macOS 13.

## Building

On an Apple-silicon Mac with the Xcode command-line tools:

```sh
brew install autoconf automake libtool pkgconf
native/macos/build.sh build
native/macos/bundle.sh build libopenconnect-macos-arm64
```

`build.sh` compiles everything into `build/prefix`. `bundle.sh` writes the output folder and refuses to finish unless every library is arm64, declares macOS 13.0 as its minimum, is signed, and loads nothing outside the folder except system libraries.

The four Homebrew tools only generate openconnect's build files. Homebrew cannot pin them, so the versions used are recorded in `manifest.json`.

## The output folder

| Path | Holds |
| --- | --- |
| `lib/` | The libraries, plus a pkg-config file that works wherever the folder is |
| `include/openconnect.h` | The header |
| `licenses/` | Licence texts for each component |
| `sources/` | The source archives the libraries were built from, and this recipe |
| `manifest.json` | Each component's version, licence, minimum macOS and source checksum |

Each library finds the others next to itself (`@loader_path`), and `libopenconnect` is named `@rpath/libopenconnect.5.dylib`. A program that links it needs one search path pointing at the folder, for example `-Wl,-rpath,@executable_path/../Frameworks`.

The libraries are signed ad hoc. The app's release build must sign them again with the real identity.

## Choices worth knowing

- **GnuTLS, as on Windows.** It is built with no optional dependency: no p11-kit (smart cards), TPM, IDN host names or compression.
- **Trusted certificates** come from the macOS Keychain.
- **`/etc/gnutls/config`** is read by GnuTLS if an administrator creates it. This is GnuTLS's usual system-wide settings file.
- **openconnect** is built without stoken, libpskc, libproxy, PC/SC, LZ4, Kerberos and translations. Only the library is built, not the command-line client.

## Not covered

Intel Macs, and signing or notarizing with a real identity.
