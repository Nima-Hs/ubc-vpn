# Security

This app handles a university password and a VPN session cookie, and installs an admin-level service.

- Never write a password, session cookie, or token to a log, error message, file, or command-line argument. Pass secrets through standard input or the OS keyring only.
- Redact secrets before storing or displaying output from third-party libraries. `libopenconnect` logs the session cookie at debug level.
- No real credentials, hostnames of private systems, or captured traffic in tests, fixtures, or documentation. Use obviously fake values.
- Never weaken a security check to make a test pass. A test of a security rule must fail when the rule is removed.
- Never commit to `main`, force-push, or bypass git hooks (`--no-verify`) to get around a failing check. Fix the cause.
