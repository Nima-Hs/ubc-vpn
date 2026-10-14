# libopenconnect for Linux

Builds `libopenconnect` v9.21 (GnuTLS backend) for x64 from the pinned upstream commit. One build serves both the `.deb` and the `.rpm`.

| File | Does |
| --- | --- |
| `build.sh` | Builds the library and writes the output folder |
| `check-probe.sh` | Runs the probe and requires the expected version and `RESULT: PASS` |
| `load-test.sh` | Runs the probe in another distribution's container with only the declared packages installed |

There is one patch, in `patches/openconnect/`: it stops the library closing file descriptor 0 when a handle is freed that never made a command pipe, stops every handle offering single sign-on to the gateway, and stops a host-scan tag in the reply to an address with no path crashing the library. The Windows and macOS builds apply the same one.

## Building

The build runs as root in the `ubuntu:22.04` image pinned by digest in `.github/workflows/native-linux.yml`. That workflow is the reference build; its artifact is `libopenconnect-linux-x64`. To run it locally, from the repository root:

```sh
image=ubuntu@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
docker run --rm -v "$PWD:/src" -w /src \
  -e SOURCE_COMMIT="$(git rev-parse HEAD)" -e BUILD_IMAGE="$image" \
  "$image" bash native/linux/build.sh out
```

The compiler, the other build tools and the GnuTLS and zlib headers are installed with `apt-get` from a dated snapshot of the Ubuntu archive (`APT_SNAPSHOT` in `build.sh`), so every build gets the same versions; the script fails if apt would download a package from anywhere else. `ca-certificates`, with the `openssl` package it depends on, is the single thing taken from the live archive, because the snapshot service is https only and the base image cannot check its certificate otherwise. It only authenticates the connection to the snapshot service; the packages themselves are still verified by apt's signatures. The version of every package in the build container is recorded in `manifest.json`.

## Output

```
lib/libopenconnect.so.5      the library (plus the usual symlinks)
lib/pkgconfig/openconnect.pc relocatable; point PKG_CONFIG_PATH here
include/openconnect.h
licenses/                    licence text for each component
source/                      the exact source archives that were built, our patches, and build.sh
manifest.json                components, versions, licences, system libraries, build details
```

| Component | Version | Licence | How it ships |
| --- | --- | --- | --- |
| openconnect | 9.21, commit `8b702bf2dbaf11302ed98629214b1df5d50a12aa` | LGPL-2.1 | `libopenconnect.so.5` |
| json-parser | the copy inside openconnect | BSD-2-Clause | compiled into the library |
| libxml2 | 2.15.4, pinned by SHA-256 | MIT | linked statically into the library |

The openconnect archive is made with `git archive` from the verified commit, and the library is built from that archive with the patches applied, so what ships is what was built. The library takes its version string from `git describe`; built from an archive, with no git history beside it, it reports `v9.21-unknown`, as the Windows build does.

## Decisions

### Built on Ubuntu 22.04

It is the oldest supported system, so the result runs on the newer ones. The highest glibc symbol version the library needs is `GLIBC_2.34`; Ubuntu 22.04 has glibc 2.35 and Debian 12 has 2.36.

### Only libxml2 is bundled

Sonames found on each system (October 2026):

| | gnutls | zlib | libxml2 | lz4 | p11-kit | nettle / hogweed |
| --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 22.04 | 30 | 1 | 2 | 1 | 0 | 8 / 6 |
| Ubuntu 24.04 | 30 | 1 | 2 | 1 | 0 | 8 / 6 |
| Ubuntu 26.04 | 30 | 1 | **16** | 1 | 0 | 8 / 6 |
| Debian 12 and 13 | 30 | 1 | 2 | 1 | 0 | 8 / 6 |
| Fedora 44 | 30 | 1 | 2 | 1 | 0 | 8 / 6 |
| Fedora rawhide | 30 | 1 | 2 | 1 | 0 | **9 / 7** |

- **libxml2** changes soname on Ubuntu 26.04, so it is linked in statically. Its symbols are not exported, so it cannot clash with a system libxml2 loaded by the same program.
- **GnuTLS and zlib** have the same soname everywhere and come from the distribution. A TLS library should get the distribution's security updates.
- **Turned off**, because we do not use them and each would add a library: LZ4 compression, PKCS#11 smart cards (p11-kit), the external-browser login (which links nettle, whose soname is changing), libproxy, stoken, PSKC, PC/SC, GSSAPI and translations. Password login, DTLS and ESP are unaffected.

The library needs exactly `libgnutls.so.30`, `libz.so.1`, `libm.so.6` and `libc.so.6`. `build.sh` fails if anything else appears.

### Package dependencies

| | Declare |
| --- | --- |
| `.deb` | `libc6 (>= 2.34)`, `libgnutls30 (>= 3.7.3)`, `zlib1g` |
| `.rpm` | `glibc >= 2.34`, `gnutls >= 3.7.3`, `zlib` |

On Ubuntu 24.04 and later, and Debian 13, the package is `libgnutls30t64`, which provides `libgnutls30`. On Fedora `zlib` is provided by `zlib-ng-compat`.

### Where the library is found at run time

Install it in the app's private folder, never in a system library path, and link each program that uses it with an rpath relative to itself. With programs in `bin/` and the library in `lib/`:

```sh
RUSTFLAGS='-C link-arg=-Wl,-rpath,$ORIGIN/../lib'
```

The loader then finds our `libopenconnect.so.5` before it looks in the system paths, so a distribution `libopenconnect` is neither needed nor used. Do not set `LD_LIBRARY_PATH` for the service: it is searched before the rpath, and `sudo` drops it anyway.

The service must never be made setuid or given file capabilities. glibc ignores an `$ORIGIN` rpath for such programs, so the library would not be found, or a system one would be loaded instead. A service started as root by systemd is not affected.

The workflow proves this: the probe is laid out this way, runs under `sudo` on a system with no distribution `libopenconnect`, and must report `v9.21-unknown`.

## Updating

Change the version and commit (or SHA-256) at the top of `build.sh`, the expected version in the workflow, and the table above. To update the compiler and other build packages, move `APT_SNAPSHOT` to a later date. If the soname table changes, revisit what is bundled.

`build.sh` passes two `ac_cv_func_*` settings to openconnect's `configure`. They turn off PKCS#11 smart-card support and the external-browser login (which uses HPKE), because neither has a switch of its own. With them on, the library would link p11-kit, nettle, hogweed and gmp directly, and the nettle and hogweed sonames differ between distributions. Removing the two settings brings both features back, along with those links, which then have to be declared as package dependencies or bundled.

The library is linked with `-z relro -z now`, and `build.sh` checks the result.
