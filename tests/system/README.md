# System tests of the installed product

The tests here install UBC VPN's real package on a throwaway CI machine and use it as a user would: the installed service, the command-line client and the app, connecting to a test gateway on that machine with made-up names, addresses and accounts. They never use a real UBC host or account, and never run on a machine anyone keeps.

Each system has a folder of its own, and a test in one folder runs only on that system:

| Folder | System | Package it installs |
| --- | --- | --- |
| `macos/` | macOS | the `.pkg` installer |
| `linux/` | Linux | the `.deb` and `.rpm` packages, with an ocserv gateway in a network namespace reached over a veth pair |

Both folders are empty until their package is built. On Windows, the installed setup program is tested by `.github/workflows/installer-windows.yml`; a `windows/` folder is added here if a Windows test moves in.

What the tests check is the same on every system ([consistency](../../.claude/rules/consistency.md)): connecting, split and full tunnel, DNS, disconnecting, and that nothing is left behind afterwards. Only how the package is installed and how the service is started differ.

Other tests that run the real programs together, in dev mode and without installing anything, are elsewhere: `crates/cli/tests/system.rs` and `app/tests/system/` (see `CONTRIBUTING.md`, "The tests that run it").
