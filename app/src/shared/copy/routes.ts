// The Routes screen's words, and what is wrong with a route.

import type { SettingsError } from "../api";
import type { RouteProblemCode } from "../protocol/RouteProblemCode";
import type { SettingsView } from "../protocol/SettingsView";

/** The Routes screen's fixed words. */
export const ROUTES = {
    title: "Routes",
    body: "Only traffic to these subnets goes through the VPN. Everything else uses your normal connection.",
    loading: "Reading your settings…",
    subnets: "Subnets",
    noSubnets: "No subnets yet. Add the UBC networks you want to reach through the VPN.",
    domains: "Domains",
    domainsBody: "Names under these domains are looked up through the VPN.",
    noDomains: "No domains yet. Add one if UBC names should be looked up through the VPN.",
    whileConnected: "Changes apply the next time you connect.",
    saved: "Saved.",
    checking: "Checking…",
    unsaved: "You have changes that are not saved.",
} as const;

/** What the policy and the app allow, said before the user types anything. */
export function describeRouteLimits(
    view: Pick<
        SettingsView,
        "policy_readable" | "allowed_routes" | "min_prefix_len" | "max_routes"
    >,
): { limits: string; allowed?: string; noPolicy?: string } {
    const limits = `A subnet can be no larger than /${view.min_prefix_len}: the number after the slash must be ${view.min_prefix_len} or more. You can list up to ${view.max_routes} subnets and ${view.max_routes} domains.`;
    if (!view.policy_readable) {
        return {
            limits,
            noPolicy:
                "The VPN’s policy file is missing or damaged, so routes cannot be checked against it and the VPN will not connect. Install UBC VPN again to restore it.",
        };
    }
    return view.allowed_routes === null
        ? { limits }
        : {
              limits,
              allowed: "Subnets must be inside one of the networks this installation allows:",
          };
}

/** What is wrong with one entry, or with the whole list, and how to put it right. */
export function describeRouteProblem(
    code: RouteProblemCode,
    limits: Pick<SettingsView, "min_prefix_len" | "max_routes">,
): string {
    switch (code) {
        case "no_subnets":
            return "Add at least one subnet. Without one, nothing goes through the VPN.";
        case "too_many":
            return `There are more than ${limits.max_routes} subnets or more than ${limits.max_routes} domains. Remove some.`;
        case "bad_subnet":
            return "Write a network as address/length with no spaces, such as 203.0.113.0/24. The address must be the first one in the network.";
        case "too_wide":
            return `This subnet is too large. Use /${limits.min_prefix_len} or a larger number after the slash.`;
        case "reserved":
            return "This range is reserved for special uses, such as this computer itself or the local network, and cannot go through the VPN.";
        case "not_allowed":
            return "This subnet is outside the networks this installation allows.";
        case "bad_domain":
            return "Write a plain lower-case name, such as campus.example.";
    }
}

/**
 * Why settings could not be read, checked or saved, and what to do. Empty
 * for the one case that is not a failure the user should hear about.
 */
export function describeSettingsError(
    error: SettingsError,
    doing: "read" | "check" | "save",
): string {
    switch (error) {
        case "unreadable":
            return "Your settings file is damaged, so it has been left as it is and your routes cannot be shown. If you edited it by hand, undo the change.";
        case "unwritable":
            return "Your settings could not be saved, and the old ones are unchanged. Check that your disk is not full, then save again.";
        case "bad_input":
            return doing === "save"
                ? "These routes are too long to save. Remove some entries, then save again."
                : "These routes are too long to check. Remove some entries.";
        case "busy":
            return "A save is already under way. Wait for it to finish.";
        case "superseded":
            // A newer check took this one's place. There is nothing to tell.
            return "";
        case "unavailable":
            return doing === "read"
                ? "UBC VPN could not read your settings. Try again. If it keeps happening, install UBC VPN again."
                : doing === "save"
                  ? "UBC VPN could not save your routes, and nothing was changed. Try again."
                  : "UBC VPN could not check these routes. Try again.";
    }
}
