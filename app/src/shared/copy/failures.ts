// The failures the service reports, in words. The connection's words, a
// login that fails the same way, and an action the service refused all use
// them. `copy.ts` does not re-export this file: it is how those words are
// made, not something a screen reads.

import type { ErrorCode } from "../protocol/ErrorCode";

export const UPDATE_BOTH = "Install the latest UBC VPN to update both.";

export interface Failure {
    title: string;
    body: string;
    /** Whether trying again could work without the user changing something else first. */
    retry: boolean;
}

export const FAILURES: Record<ErrorCode, Failure> = {
    not_owner: {
        title: "Managed by another user",
        body: "Another user of this computer controls the VPN. An administrator can reset the VPN service to hand it over.",
        retry: false,
    },
    not_claimed: {
        title: "Setup not finished",
        body: "The VPN service has not been set up for you yet. Quit UBC VPN and open it again to finish.",
        retry: false,
    },
    protocol_mismatch: {
        title: "Update needed",
        body: `The app and the VPN service are different versions. ${UPDATE_BOTH}`,
        retry: false,
    },
    bad_request: {
        title: "Couldn’t connect",
        body: `The VPN service did not understand the app’s request. ${UPDATE_BOTH}`,
        retry: false,
    },
    route_refused: {
        title: "Route refused",
        body: "The VPN service refused one of your subnets or domains, so nothing was changed. The message below says which one. Remove or fix it, then connect again.",
        retry: true,
    },
    pin_mismatch: {
        title: "Connection blocked",
        body: "The server that answered could not prove it is UBC’s VPN, so nothing was sent to it. Try again from another network, and do not connect from this one while this keeps happening.",
        retry: true,
    },
    login_needed: {
        title: "Log in again",
        body: "Your UBC session has ended, so the VPN is off. Log in to connect again.",
        retry: true,
    },
    gateway_unreachable: {
        title: "Can’t reach UBC",
        body: "UBC’s VPN did not answer. Check your internet connection, then try again.",
        retry: true,
    },
    engine_failed: {
        title: "Tunnel failed",
        body: "The tunnel could not be opened, or it was lost. Your traffic is using your normal connection. Try again.",
        retry: true,
    },
    verification_failed: {
        title: "Routes not confirmed",
        body: "The VPN could not confirm its routes were set correctly, so it turned itself off and removed them. Try again.",
        retry: true,
    },
    busy: {
        title: "Still working",
        body: "The VPN service is finishing the last thing you asked for. Wait a few seconds, then try again.",
        retry: true,
    },
    policy_invalid: {
        title: "Reinstall needed",
        body: "A file the VPN service needs is missing or damaged. Install UBC VPN again to restore it.",
        retry: false,
    },
    not_connected: {
        title: "Not connected",
        body: "The VPN is not connected, so no routes were changed. Your routes are saved and are used when you connect. Try connecting now.",
        retry: true,
    },
    internal: {
        title: "Service error",
        body: "Something went wrong inside the VPN service. Try again. If it keeps happening, restart your computer.",
        retry: true,
    },
};
