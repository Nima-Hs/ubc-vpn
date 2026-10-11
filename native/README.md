# Native libraries

The app links `libopenconnect`, which we build ourselves from a pinned source tag on each OS. Distro and package-manager builds are not used: Windows has none, and some Linux releases ship a version with known bugs.

| Folder | Holds |
| --- | --- |
| `probe/` | A small Rust program that checks a built library actually works |
| `windows/`, `macos/`, `linux/` | The build recipe, patches and pinned versions for that OS. Added by the per-OS build work |

## The probe

`probe/` loads a `libopenconnect` build and exercises the calls the app depends on: the certificate, login-form and logging callbacks, a login, a connection, and creating a tunnel device with no script. Each OS build must pass it before its output is used.

It is a test tool for a fake gateway on your own machine. **Never point it at a real gateway:** it takes the password as a command-line argument and prints everything the library logs, session cookie included.

### Which library it tests

The probe uses whichever `libopenconnect` the build and the loader find, so point both at the build under test:

- **Linux and macOS:** set `PKG_CONFIG_PATH` to the build's `lib/pkgconfig` before `cargo build`, and `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) to its `lib` when running.
- **Windows:** put the folder holding `libopenconnect-5.dll` and its dependencies first on `PATH` when running. Nothing is needed at build time.

The first line the probe prints is the library's version; check it is the one you built.

### Running it

```sh
cd native/probe
cargo build --release --locked

# A throwaway certificate for the fake gateway.
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj "/CN=localhost"

# Callbacks only. No admin rights needed.
python3 fake_server.py cert.pem key.pem 4444 &
./target/release/oc-probe probe https://127.0.0.1:4444

# Login, connect and tunnel device. Needs admin rights.
sudo ./target/release/oc-probe connect https://127.0.0.1:4444 testuser testpass
```

It prints `RESULT: PASS` and exits 0 on success. On Windows, run the same commands from Git Bash in an administrator terminal, without `sudo`.

`fake_server.py` is a stand-in gateway. It listens on localhost only, accepts any credentials, and is not a VPN server. `ocserv.conf.in` is a template for a real `ocserv` test server on Linux; the Linux build workflow fills in its placeholders.

The probe is a standalone crate, outside the main workspace, and is never shipped. Its shortcuts (password on the command line, accepting any certificate, unredacted logs) must not be copied into the engine crate.
