// The environment the end-to-end tests hand to every app they launch.
//
// On someone's own computer a test must never reach the real VPN service,
// the user's settings or their saved password: a test that did once changed
// the owner's live routes. The demo build has no client at all, but a
// production build that is not installed runs whichever client
// `UBC_VPN_CLI` names, and `UBC_VPN_DEV` and the `UBC_VPN_SYSTEM_*`
// variables point tests at real programs. A launched app inherits the
// environment of whoever ran the tests, so off CI these are taken out of it
// before anything starts. A test that needs one sets it itself, explicitly,
// after this. On CI, where the machine is thrown away, nothing is removed.

/**
 * Names that could lead a launched app to a real client or service. Windows
 * reads a variable's name in any case, so the name is compared in one.
 */
export function leadsToRealClient(name: string): boolean {
    const upper = name.toUpperCase();
    return (
        upper === "UBC_VPN_CLI" || upper === "UBC_VPN_DEV" || upper.startsWith("UBC_VPN_SYSTEM_")
    );
}

/**
 * `env` without anything that could lead a launched app to a real client or
 * service, unless it is CI's. Never changes `env` itself.
 */
export function launchEnvironment(
    env: Record<string, string | undefined>,
): Record<string, string | undefined> {
    if (env.CI) {
        return { ...env };
    }
    return Object.fromEntries(Object.entries(env).filter(([name]) => !leadsToRealClient(name)));
}
