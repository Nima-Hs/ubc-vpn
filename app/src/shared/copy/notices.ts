// Notices shown on any screen: an action that did not start, and dev mode.

import type { ActionError } from "../api";
import { FAILURES } from "./failures";

export interface NoticeCopy {
    text: string;
    /** The service's own account of a refusal, shown beneath the text. */
    detail?: string;
}

/** The words for an action that did not start. */
export function describeActionError(error: ActionError): NoticeCopy {
    switch (error.kind) {
        case "login_unavailable":
            return {
                text: "This version of UBC VPN cannot log in to UBC yet, so it cannot connect.",
            };
        case "service_unavailable":
            return { text: "The VPN service did not answer. Wait a few seconds, then try again." };
        case "refused": {
            const detail = error.message.trim();
            return { text: FAILURES[error.code].body, ...(detail !== "" && { detail }) };
        }
    }
}

/** Shown on every screen while the app talks to a dev-mode service. */
export const DEVELOPMENT_MODE = "Development mode. This is not the real VPN.";
