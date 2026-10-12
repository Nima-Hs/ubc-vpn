# libopenconnect for Windows

Builds `libopenconnect` v9.21 and GnuTLS 3.8.13 for Windows x64 from source, and collects them with the other DLLs they need, the licences and the source.

MSYS2 has no OpenConnect package, so it is compiled here with MinGW (UCRT64). GnuTLS is compiled here too, because MSYS2's build of it is not safe to load into a service that runs with admin rights (see [Why GnuTLS is built here](#why-gnutls-is-built-here)). The remaining libraries are MSYS2's prebuilt packages.

## Running it

In an [MSYS2](https://www.msys2.org/) UCRT64 shell, from this folder:

```sh
./setup.sh
./build.sh
```

`setup.sh` installs the pinned build tools, compiler and libraries, replacing other versions of those packages if you have them. `build.sh` deletes and recreates `work/` (scratch) and `out/` (the result). It keeps the GnuTLS build in `cache/gnutls` and reuses it until `common.sh`, `gnutls.sh`, a GnuTLS patch or a lock file changes; a first build takes about ten minutes longer.

The `Native library (Windows)` workflow runs the same two scripts on GitHub's Windows runner, then the tests below. Only if all of them pass, and GnuTLS was built in that same run, does it mark the output shippable and upload it as the `libopenconnect-windows-x64` artifact. Builds of `main` always build GnuTLS. A pull request may reuse an earlier build of it to save time; its output is then uploaded as `libopenconnect-windows-x64-reused-gnutls` and stays unshippable.

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

- **OpenConnect.** `build.sh` names the commit that tag `v9.21` points to and stops if the tag has moved. The build is made from the archive of that commit, with the one patch in `patches/openconnect/`.
- **GnuTLS.** `common.sh` names the release and `sources.lock` its SHA-256. It is the release the macOS build uses, with the one patch in `patches/gnutls/`. `gnutls.sh` also requires a signature by the maintainer whose key is in `keys/` and whose full fingerprint it names. That key is one of the four in the keyring gnutls.org publishes for its releases. It expires on 2027-01-01. After that a GnuTLS build stops at the signature check until `keys/gnutls-release.asc` is replaced with the renewed key, or with another maintainer's key and its fingerprint in `gnutls.sh`.
- **The compiler and the libraries.** `packages.lock` lists every MinGW package file with its SHA-256. `setup.sh` downloads exactly those files from `repo.msys2.org`, which keeps old versions, checks them and installs them. `build.sh` stops if the installed MinGW packages are not exactly the locked ones.
- **The build tools.** `tools.lock` does the same for autoconf, automake, libtool, make, patch, perl, git and what they need. `build.sh` stops if one is missing or at another version.
- **The MSYS2 source packages.** `sources.lock` lists each one with its SHA-256.
- **The licences.** `licences.txt` names the licence we use each component under. `build.sh` stops if something that would ship is not listed.

Not pinned: the MSYS2 base that the tools run on (the shell, coreutils, tar, curl, gpg, pacman). It is whatever the machine has; on the runner that is GitHub's image. It could be pinned by starting from a dated `msys2-base` archive with a known hash instead of the installed MSYS2, which is not done yet. `out/build-packages.txt` records the versions used.

To update a library, change its lines in `packages.lock` and `sources.lock` to the new file names and SHA-256s. To accept a new DLL, add it to those, to `licences.txt` and to `dlls.txt`.

## Why GnuTLS is built here

MSYS2's GnuTLS was traced reading `D:\M\msys64\ucrt64\etc\gnutls\config`, a path left over from MSYS2's own build machine, and `\etc\gnutls\pkcs11.conf` on the current drive. An ordinary user can usually create folders in the root of a drive. A file planted at the first path changed the library's TLS settings; the second can name code to load ([issue #13](https://github.com/Nima-Hs/ubc-vpn/issues/13)).

`gnutls.sh` removes both, and what led to them:

- **No configuration file is read.** GnuTLS takes the file's path from `--with-system-priority-file`, which defaults to `<prefix>/etc/gnutls/config`. An empty value, as here, removes the built-in path. Upstream GnuTLS would then still read a file named by the `GNUTLS_SYSTEM_PRIORITY_FILE` environment variable and apply its cipher, key exchange and default priority settings. `patches/gnutls/` removes that too: the variable is not consulted and no file is looked up. The string scan checks that the variable's name is gone from the DLL. The macOS build keeps the file, at `/etc/gnutls/config`, which only root can write there.
- **PKCS#11 is compiled out** with `--without-p11-kit`. The `pkcs11.conf` path is fixed in GnuTLS's PKCS#11 code, and p11-kit has its own module folders; with the option none of that code is built and `libp11-kit` is not needed. We give up smart-card and token support, which the app does not use.
- **Message translation is off** (`--disable-nls`), so the library does not look for a `locale` folder.
- **Nothing optional is linked**: no IDN, compression, TPM or DANE, and GnuTLS's own copies of libtasn1 and libunistring are used. That leaves Nettle and GMP as its only dependencies.

Nettle and GMP stay as MSYS2 packages. They are arithmetic libraries: the string scan finds no path in them and the trace shows them opening no file.

## The tests

The workflow runs these on every build output, reused GnuTLS or not. The scripts are in `tests/`.

- **Probe and connect.** [`../probe`](../README.md) must pass in both modes, loading DLLs only from the output and Windows.
- **Planted files** (`planted-files.sh`). Writes GnuTLS configurations that turn off every cipher, key exchange and TLS version. They are named in `GNUTLS_SYSTEM_PRIORITY_FILE`, then planted at the path the old build read and its neighbours. The probe must pass in both modes every time. Each case is also tried on MSYS2's stock GnuTLS (`control.sh` unpacks it from the packages in `control.lock`; it is never installed or shipped), and there it must fail. Without that the test would prove nothing.
- **No PKCS#11** (`no-pkcs11.sh`, and checks in `build.sh`). GnuTLS and OpenConnect must both have been configured without it, no DLL may import or mention p11-kit, and `libgnutls-30.dll` may hold no library name to load at run time other than Windows' `crypt32.dll` and `ncrypt.dll`.
- **Trace** (`trace.sh`). Runs the probe under Process Monitor and follows it and every process it starts. Files must be in the probe's own folder, or under `C:\Windows` where ordinary users cannot write; `user-writable.ps1` decides that by reading the permissions, which is how it knows `C:\Windows\Temp` is not such a place. Every registry key must match a rule in `trace-allow.txt`, and none may name a bundled library. Today the only file rule is for NTFS's own bookkeeping, and the registry keys are all Windows' own.
- **String scan** (`scan-strings.sh`). Searches every DLL for absolute paths, for `ucrt64`, `msys64`, `/etc/`, `\etc\`, `pkcs11` and `.gnutls`, and for names that look like environment variables. Each hit must match a rule in `strings-allow.txt`, with the reason it is harmless or what the service must do about it.

`manifest.json` is written with `"shippable": false`. The workflow's last step before the upload (`approve.sh`) sets it to `true`. It only runs if every test passed on that same output, and it leaves the flag alone if GnuTLS was not built in that run. It fails if the manifest does not name the commit of this repository the output was built from. Anything that consumes the output must refuse it unless the flag is `true`.

The flag alone is not enough. Any run that builds GnuTLS and passes the tests marks its output shippable, and that includes a run started by hand on a branch. A consumer must take the artifact only from a run of `main`, and check that `recipe.commit` in the manifest is a commit on `main`. On a pull-request run that commit is GitHub's temporary merge commit, which is never on `main`, so those artifacts fail the check by design.

## The output

| Path | Holds |
| --- | --- |
| `bin/` | The DLLs above |
| `licenses/` | The licence text of OpenConnect, GnuTLS, each MSYS2 package a DLL came from, and the MinGW runtime linked into the DLLs built here |
| `source/` | The OpenConnect archive, the GnuTLS release, and the MSYS2 source package of each MSYS2 DLL |
| `source/recipe/` | A copy of the files in this folder that are in the repository, as they were built: the scripts with their configure options, our patches to OpenConnect and GnuTLS, the lock files, lists and key. The workflow checks it matches the repository |
| `manifest.json` | Whether the output is shippable, the commit of this repository it was built from, and each component with its origin, version, licence, source and checksums |
| `build-packages.txt` | Every MSYS2 package installed during the build |

For each MSYS2 package that contributes a DLL, `build.sh` downloads the source package of the exact installed version in the same run, checks it against `sources.lock` and against the signature of an MSYS2 packager, and stops if either fails. Licence texts are the files the package installs or, when it installs none, the ones at the top of its upstream source.

The MinGW runtime (`crt`, `headers`) and `libgcc` are linked statically into the two DLLs built here. Their licence texts are included. Their source is not, but the manifest records where it is and its SHA-256.

Wintun, the tunnel driver the library loads at run time, is deliberately not in the output. The workflow downloads it for the tests only.

## What the service must still do

The build removes the paths; these remain the job of the program that loads the DLLs:

- Install the DLLs in a folder only administrators can write, and its parent likewise. libxml2 looks for a catalogue at `..\etc\xml\catalog` relative to its own DLL if a document ever asks for one.
- Load them from that folder only: a full path or `SetDefaultDllDirectories`, never the current directory or `PATH`.
- Remove these environment variables before loading the DLLs. They are the ones the string scan and a reading of the source find the libraries reading:
  - `SSLKEYLOGFILE`: GnuTLS writes session keys to the file it names.
  - `GNUTLS_DEBUG_LEVEL`, `GNUTLS_CPUID_OVERRIDE`, `GNUTLS_BUFFER_RECLAIM`, `GNUTLS_NO_EXPLICIT_INIT`, `GNUTLS_NO_IMPLICIT_INIT`: change how GnuTLS logs, picks processor-specific code and starts up.
  - `NETTLE_FAT_VERBOSE`: makes Nettle print to standard error.
  - `XML_CATALOG_FILES`, `XML_DEBUG_CATALOG`: libxml2's catalogue files.
  - `NTLMUSER`, `USER`: OpenConnect takes a user name from them when a proxy asks for NTLM authentication.
  - `GNUTLS_SYSTEM_PRIORITY_FILE`: this build does not read it, but remove it anyway.
- Do not call GnuTLS's trust-on-first-use functions. They keep a file in `.gnutls` under the folder named by `HOME`, or `HOMEDRIVE` and `HOMEPATH`. OpenConnect does not call them.
- Set `TMP` and `TEMP` to a folder that already exists and that only administrators can write, before calling `openconnect_setup_cmd_pipe()`. OpenConnect makes a short-lived socket file there. If that folder is unusable it falls back to `C:\Windows\Temp`, then `C:\Temp`, which any user may be able to create, then the current folder. Tracked for the engine as [issue #18](https://github.com/Nima-Hs/ubc-vpn/issues/18).
- Load Wintun from a full path as well.
