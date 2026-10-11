# Native libraries

The app links `libopenconnect`, which we build ourselves from a pinned source tag on each OS. Distro and package-manager builds are not used: Windows has none, and some Linux releases ship a version with known bugs.

| Folder | Holds |
| --- | --- |
| `windows/`, `macos/`, `linux/` | The build recipe, patches and pinned versions for that OS |
| `probe/` | A small Rust program that checks a built library actually works |

## The probe

`probe/` loads a `libopenconnect` build and exercises the calls the app depends on: the certificate, login-form and logging callbacks, a login, a connection, and creating a tunnel device with no script. Each OS build must pass it before its artefact is used.

```sh
cd native/probe
cargo build --release

# Callbacks only, against the bundled fake gateway. No admin rights needed.
python3 fake_server.py cert.pem key.pem 4444 &
./target/release/oc-probe probe https://127.0.0.1:4444

# Login, connect and tunnel device. Needs admin rights.
sudo ./target/release/oc-probe connect https://127.0.0.1:4444 testuser testpass
```

`fake_server.py` is a stand-in gateway for tests. It accepts any credentials and is not a VPN server. `ocserv.conf.in` configures a real `ocserv` test server on Linux.

The probe is a standalone crate, outside the main workspace, and is never shipped.
