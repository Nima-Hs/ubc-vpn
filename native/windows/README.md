# libopenconnect for Windows

Builds `libopenconnect` v9.21 and GnuTLS 3.8.13 for Windows x64 from source, and collects them with the other DLLs they need, the licences and the source.

MSYS2 has no OpenConnect package, so it is compiled here with MinGW (UCRT64). GnuTLS is compiled here too, because MSYS2's build of it is not safe to load into a service that runs with admin rights (see [Why GnuTLS is built here](#why-gnutls-is-built-here)). The remaining libraries are MSYS2's prebuilt packages.

## Running it

In an [MSYS2](https://www.msys2.org/) UCRT64 shell, from this folder:

```sh
./setup.sh
./build.sh
```

`setup.sh` installs the pinned build tools, compiler and libraries, replacing other versions of those packages if you have them. `build.sh` deletes and recreates `work/` (scratch) and `out/` (the result). It keeps the GnuTLS build in `cache/gnutls` and reuses it until `common.sh`, `gnutls.sh` or a lock file changes; a first build takes several minutes longer.

The `Native library (Windows)` workflow runs the same two scripts on GitHub's Windows runner, then the tests below. Only if all of them pass does it mark the output shippable and upload it as the `libopenconnect-windows-x64` artifact.

## The DLLs

| DLL | Why it is there | From |
| --- | --- | --- |
| `libopenconnect-5.dll` | The VPN engine | Built here |
| `libgnutls-30.dll` | TLS and DTLS for the engine | Built here |
| `libnettle-9.dll` | Ciphers and hashes for GnuTLS | MSYS2 |
| `libhogweed-7.dll` | Public-key cryptography for GnuTLS, part of Nettle | MSYS2 |
| `libgmp-10.dll` | Big-number arithmetic for libhogweed | MSYS2 |
| `libxml2-16.dll` | Parses the gateway's XML replies | MSYS2 |
| `libiconv-2.dll` | Character-set conversion for libxml2 | MSYS2 |
| `zlib1.dll` | Compression for the tunnel and for libxml2 | MSYS2 |
| `libwinpthread-1.dll` | Threading layer the MinGW compiler's code relies on | MSYS2 |

`build.sh` does not copy this list. It reads the import table of `libopenconnect-5.dll`, then of each DLL that leads to, and takes each one from the GnuTLS build or from MSYS2's `/ucrt64/bin`. It stops if a DLL is found in neither place nor in Windows, or if the result differs from `dlls.txt`.

## What is pinned

- **OpenConnect.** `build.sh` names the commit that tag `v9.21` points to and stops if the tag has moved. The build is made from the archive of that commit, with the one patch in `patches/`.
- **GnuTLS.** `common.sh` names the release and `sources.lock` its SHA-256. It is the release the macOS build uses.
- **The compiler and the libraries.** `packages.lock` lists every MinGW package file with its SHA-256. `setup.sh` downloads exactly those files from `repo.msys2.org`, which keeps old versions, checks them and installs them. `build.sh` stops if the installed MinGW packages are not exactly the locked ones.
- **The build tools.** `tools.lock` does the same for autoconf, automake, libtool, make, patch, perl, git and what they need. `build.sh` stops if one is missing or at another version.
- **The MSYS2 source packages.** `sources.lock` lists each one with its SHA-256.
- **The licences.** `licences.txt` names the licence we use each component under. `build.sh` stops if something that would ship is not listed.

Not pinned: the MSYS2 base that the tools run on (the shell, coreutils, tar, curl, gpg, pacman). It cannot be replaced from inside a running MSYS2, so it is whatever the machine has. On the runner that is GitHub's image. `out/build-packages.txt` records the versions used.

To update a library, change its lines in `packages.lock` and `sources.lock` to the new file names and SHA-256s. To accept a new DLL, add it to those, to `licences.txt` and to `dlls.txt`.

## Why GnuTLS is built here

MSYS2's GnuTLS was traced reading `D:\M\msys64\ucrt64\etc\gnutls\config`, a path left over from MSYS2's own build machine, and `\etc\gnutls\pkcs11.conf` on the current drive. An ordinary user can usually create folders in the root of a drive. A file planted at the first path changed the library's TLS settings; the second can name code to load ([issue #13](https://github.com/Nima-Hs/ubc-vpn/issues/13)).

`gnutls.sh` removes both, and what led to them:

- **The configuration file is compiled out.** GnuTLS takes its path from `--with-system-priority-file`, which defaults to `<prefix>/etc/gnutls/config`. Given an empty value, as here, GnuTLS is built without the feature. No path is chosen, so there is none to protect.
- **PKCS#11 is compiled out** with `--without-p11-kit`. The `pkcs11.conf` path is fixed in GnuTLS's PKCS#11 code, and p11-kit has its own module folders; with the option none of that code is built and `libp11-kit` is not needed. We give up smart-card and token support, which the app does not use.
- **Message translation is off** (`--disable-nls`), so the library does not look for a `locale` folder.
- **Nothing optional is linked**: no IDN, compression, TPM or DANE, and GnuTLS's own copies of libtasn1 and libunistring are used. That leaves Nettle and GMP as its only dependencies.

Nettle and GMP stay as MSYS2 packages. They are arithmetic libraries: the string scan finds no path in them and the trace shows them opening no file.

## The tests

The workflow runs these on every build output, reused GnuTLS or not. The scripts are in `tests/`.

- **Probe and connect.** [`../probe`](../README.md) must pass in both modes, loading DLLs only from the output and Windows.
- **Planted files** (`planted-files.sh`). Creates every location the old build read, and a few more, with a GnuTLS configuration that turns all TLS versions off and PKCS#11 module lists that name a marker DLL. The probe must still pass in both modes and the marker must not be loaded. The same files are then tried on MSYS2's stock GnuTLS (`control.sh` unpacks it from the packages in `control.lock`; it is never installed or shipped), and that run must fail. Without it the test would prove nothing.
- **File trace** (`trace.sh`). Runs the probe under Process Monitor and lists every path it touches outside its own folder and `C:\Windows`. Each must match a rule in `trace-allow.txt`.
- **String scan** (`scan-strings.sh`). Searches every DLL for absolute paths and for `ucrt64`, `msys64`, `/etc/`, `\etc\` and `pkcs11`. Each hit must match a rule in `strings-allow.txt`, with the reason it is harmless.

`manifest.json` is written with `"shippable": false`. The workflow's last step before the upload (`approve.sh`) sets it to `true`, and only runs if every test passed on that same output. Anything that consumes the output must refuse it unless the flag is `true`.

## The output

| Path | Holds |
| --- | --- |
| `bin/` | The DLLs above |
| `licenses/` | The licence text of OpenConnect, GnuTLS, each MSYS2 package a DLL came from, and the MinGW runtime linked into the DLLs built here |
| `source/` | The OpenConnect archive and patch, the GnuTLS release, and the MSYS2 source package of each MSYS2 DLL |
| `manifest.json` | Whether the output is shippable, and each component with its origin, version, licence, source and checksums |
| `build-packages.txt` | Every MSYS2 package installed during the build |

For each MSYS2 package that contributes a DLL, `build.sh` downloads the source package of the exact installed version in the same run, checks it against `sources.lock` and against the signature of an MSYS2 packager, and stops if either fails. Licence texts are the files the package installs or, when it installs none, the ones at the top of its upstream source.

The MinGW runtime (`crt`, `headers`) and `libgcc` are linked statically into the two DLLs built here. Their licence texts are included. Their source is not, but the manifest records where it is and its SHA-256.

Wintun, the tunnel driver the library loads at run time, is deliberately not in the output. The workflow downloads it for the tests only.

## What the service must still do

The build removes the paths; these remain the job of the program that loads the DLLs:

- Install the DLLs in a folder only administrators can write, and its parent likewise. libxml2 looks for a catalogue at `..\etc\xml\catalog` relative to its own DLL if a document ever asks for one.
- Load them from that folder only: a full path or `SetDefaultDllDirectories`, never the current directory or `PATH`.
- Start with a clean environment. GnuTLS still obeys `GNUTLS_SYSTEM_PRIORITY_FILE` (a configuration file), `SSLKEYLOGFILE` (writes session keys to a file) and `GNUTLS_DEBUG_LEVEL`; remove all three before loading it.
- Set `TEMP` and `TMP` to a folder only administrators can write before calling `openconnect_setup_cmd_pipe()`. OpenConnect makes a short-lived socket file there, and falls back to `C:\Windows\Temp`, `C:\Temp` and the current folder.
- Load Wintun from a full path as well.
