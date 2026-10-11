# libopenconnect for Windows

Builds `libopenconnect` v9.21 (GnuTLS backend) for Windows x64 from the upstream source, and collects it with the DLLs it needs, their licences and their source.

MSYS2 has no OpenConnect package, so the library is compiled here with MinGW (UCRT64). The libraries it depends on, GnuTLS and the rest, are taken from MSYS2 as prebuilt packages.

## Running it

In an [MSYS2](https://www.msys2.org/) UCRT64 shell, from this folder:

```sh
./setup.sh
./build.sh
```

`setup.sh` installs the build tools and the pinned compiler and libraries, replacing other versions of those packages if you have them. `build.sh` deletes and recreates `work/` (scratch) and `out/` (the result).

The `Native library (Windows)` workflow runs the same two scripts on GitHub's Windows runner, then tests the result with [`../probe`](../README.md) and uploads `out/` as the `libopenconnect-windows-x64` artifact.

## What is pinned

- **The OpenConnect source.** `build.sh` names the commit that tag `v9.21` points to and stops if the tag has moved. The build is made from the archive of that commit, not from the clone.
- **The patch.** `patches/` holds the one change we make, so the code compiles against current MinGW headers.
- **The compiler and the libraries.** `packages.lock` lists every MinGW package file with its SHA-256. `setup.sh` downloads exactly those files from `repo.msys2.org`, which keeps old versions, checks them and installs them. `build.sh` stops if an installed package is not the locked version.
- **The licences.** `licences.txt` names the licence we use each package under. `build.sh` stops if a package that would ship is not listed.

The build tools in `build-tools.txt` (autoconf, make, git and so on) are not pinned. They do not end up in the output.

To update a library, change its line in `packages.lock` to the new file name and SHA-256. To accept a new dependency, add it to `packages.lock` and `licences.txt`.

## The output

| Path | Holds |
| --- | --- |
| `bin/` | `libopenconnect-5.dll` and every DLL it needs that is not part of Windows |
| `licenses/` | The licence text of OpenConnect, of each MSYS2 package a DLL came from, and of the MinGW runtime linked into our DLL |
| `source/` | The OpenConnect archive and patch, and the MSYS2 source package of each bundled DLL |
| `manifest.json` | Each component with its version, licence, package, source and checksums |
| `build-packages.txt` | Every MSYS2 package installed during the build, build tools included |

The DLL list is not written down anywhere. `build.sh` reads the import table of `libopenconnect-5.dll`, then of each DLL that leads to, and stops if one is found neither in MSYS2's `/ucrt64/bin` nor in Windows.

For each MSYS2 package that contributes a DLL, `build.sh` downloads the source package of the exact installed version in the same run, checks its signature against MSYS2's keyring, and stops if it cannot. A source package holds the upstream source, MSYS2's patches and its build recipe. Licence texts are the files the package installs or, when it installs none, the ones at the top of that upstream source.

The MinGW runtime (`crt`, `headers`) and `libgcc` are linked statically into `libopenconnect-5.dll`. Their licence texts are included; their source is not.

## Known issue: do not ship this output in the service yet

MSYS2's GnuTLS reads configuration from paths that an ordinary user may be able to create. Tracing the probe on the build runner showed it opening, on every run:

- `D:\M\msys64\ucrt64\etc\gnutls\config`, the path of MSYS2's own build machine. A file planted there changed the TLS settings and made the probe's handshake fail.
- `\etc\gnutls\pkcs11.conf` on the current drive, a file that can name PKCS#11 modules to load.
- `..\etc\pkcs11\` beside the program's folder, and `.config\pkcs11\` in the user's profile, through p11-kit.

A service running with admin rights must not read any of these. The fix, a GnuTLS built here without PKCS#11 and with a safe configuration path, is not part of this recipe yet.

Wintun, the tunnel driver the library loads at run time, is deliberately not in the output. The workflow downloads it for the connection test only.
