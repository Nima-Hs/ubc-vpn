# UBC VPN

<!-- A screenshot of the app is to be added at the first release. -->

A desktop VPN client for UBC's myVPN that does split tunnelling, for Windows, macOS and Linux. Only the UBC subnets you choose go through the VPN; everything else uses your normal connection. UBC's official client sends all traffic through the tunnel and cannot be set up otherwise.

This is an independent open-source project. It is not affiliated with or endorsed by the University of British Columbia.

## Status

In development. There is no release yet, and it cannot connect to UBC: the real VPN engine is not connected yet.

What works today is the app, the command-line client and the service talking to each other in development mode, against a pretend gateway with pretend routing. [CONTRIBUTING.md](CONTRIBUTING.md#development-mode) says how to run that.

## What it will install

- **The app.** A tray icon and a window. It shows the state of the VPN and sends commands.
- **A small service.** The only part with admin rights. It opens the tunnel, sets routes and DNS for the chosen subnets, checks they took effect, and cleans up.
- **A command-line client, `ubc-vpn`.** It logs in and talks to the service. The app uses it for both.

One installer per system installs all three and asks for admin rights once.

## How it stays safe

This is the design, from [docs/architecture.md](docs/architecture.md). Not all of it is built yet.

- The password goes from you to the command-line client, and from there only to the gateway. It never reaches the service, and it is never written to a file, a log or a command line. If you ask for it to be saved, it is kept in the system keyring.
- The app never handles the session cookie and never talks to the gateway.
- The gateway is pinned. Its name and certificate pins live in a file only an admin can write, and the session cookie is sent only to a gateway that matches a pin.
- The service takes commands from one user only: its owner, the first user to run the app or the client after install. Its channel is local and rejects remote clients.
- The VPN library prints the session cookie in its debug output, so the service removes it before storing any log.
- Checks fail closed. If the service cannot confirm the routes are right, it reports failure and removes everything it set up.

## Supported systems

Planned for the first release:

- Windows 10 and 11 on x64.
- macOS 13 or later on Apple silicon.
- Ubuntu 22.04 or later, Debian 12 or later, and current Fedora, on x64.

Only IPv4 subnets are routed. Your IPv6 setup is left untouched.

## More

- [docs/architecture.md](docs/architecture.md): the design and the reasons for it.
- [CONTRIBUTING.md](CONTRIBUTING.md): setup, running in development mode, and the workflow.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
