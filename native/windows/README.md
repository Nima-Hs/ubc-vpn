# libopenconnect for Windows

Builds `libopenconnect` v9.21 (GnuTLS backend) for Windows x64 from the upstream source, and collects it with every DLL, licence and source file that has to ship alongside it.

MSYS2 has no OpenConnect package, so the library is compiled here with MinGW (UCRT64). The libraries it depends on, GnuTLS and the rest, are taken from MSYS2 as prebuilt packages.

## Running it

In an [MSYS2](https://www.msys2.org/) UCRT64 shell, from this folder:

```sh
pacman -S --needed - < packages.txt
./build.sh
```

`build.sh` deletes and recreates `work/` (scratch) and `out/` (the result). The `Native library (Windows)` workflow runs the same two commands on GitHub's Windows runner, then tests the result with [`../probe`](../README.md) and uploads `out/` as the `libopenconnect-windows-x64` artifact.

## What is pinned

- **The source.** `build.sh` names the commit that tag `v9.21` points to and stops if the tag has moved. The build is made from the archive of that commit, not from the clone.
- **The patch.** `patches/` holds the one change we make, so the code compiles against current MinGW headers.
- **MSYS2 packages are not pinned.** MSYS2 is a rolling repository and keeps no old versions to pin to. Instead, each build records the exact version of every package it used.

## The output

| Path | Holds |
| --- | --- |
| `bin/` | `libopenconnect-5.dll` and every DLL it needs that is not part of Windows |
| `licenses/` | The licence text of OpenConnect and of each MSYS2 package a DLL came from |
| `source/` | The source archive that was built, and the patch. The LGPL requires us to offer these |
| `manifest.json` | Each component with its version, licence, files and checksums |
| `build-packages.txt` | Every MSYS2 package installed during the build, compiler included |

The DLL list is not written down anywhere. `build.sh` reads the import table of `libopenconnect-5.dll`, then of each DLL that leads to, and stops if one is found neither in MSYS2's `/ucrt64/bin` nor in Windows.

Wintun, the tunnel driver the library loads at run time, is deliberately not in the output. The workflow downloads it for the connection test only.
