// Checks that a parsed line has the shape the protocol promises before the
// rest of the app trusts it. The types are the generated ones; this file only
// confirms that a value really is one of them.

import type { BridgeLine } from "@shared/protocol/BridgeLine";
import type { CliMessage } from "@shared/protocol/CliMessage";
import type { ConnState } from "@shared/protocol/ConnState";
import type { ErrorCode } from "@shared/protocol/ErrorCode";
import type { ErrorInfo } from "@shared/protocol/ErrorInfo";
import type { LoginErrorCode } from "@shared/protocol/LoginErrorCode";
import type { Outcome } from "@shared/protocol/Outcome";
import type { PromptKind } from "@shared/protocol/PromptKind";
import type { ResponseBody } from "@shared/protocol/ResponseBody";
import type { ServerMessage } from "@shared/protocol/ServerMessage";
import type { TunnelInfo } from "@shared/protocol/TunnelInfo";

// Typed against `ErrorCode`, so a code added to the protocol fails the type
// check here until it is listed.
const ERROR_CODES: Record<ErrorCode, true> = {
    not_owner: true,
    not_claimed: true,
    protocol_mismatch: true,
    bad_request: true,
    route_refused: true,
    pin_mismatch: true,
    login_needed: true,
    gateway_unreachable: true,
    engine_failed: true,
    verification_failed: true,
    busy: true,
    policy_invalid: true,
    internal: true,
};

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isU32(value: unknown): value is number {
    return (
        typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffffffff
    );
}

function isErrorCode(value: unknown): value is ErrorCode {
    return typeof value === "string" && Object.hasOwn(ERROR_CODES, value);
}

function isTunnelInfo(value: unknown): value is TunnelInfo {
    return (
        isObject(value) &&
        typeof value.interface === "string" &&
        typeof value.address === "string" &&
        isStringArray(value.subnets) &&
        isStringArray(value.dns_domains)
    );
}

export function isConnState(value: unknown): value is ConnState {
    if (!isObject(value)) {
        return false;
    }
    switch (value.state) {
        case "disconnected":
        case "connecting":
        case "disconnecting":
        case "login_needed":
            return true;
        case "connected":
            return isTunnelInfo(value.tunnel);
        case "failed":
            return isErrorCode(value.code) && typeof value.message === "string";
        default:
            return false;
    }
}

function isErrorInfo(value: unknown): value is ErrorInfo {
    return isObject(value) && isErrorCode(value.code) && typeof value.message === "string";
}

function isResponseBody(value: unknown): value is ResponseBody {
    if (!isObject(value)) {
        return false;
    }
    switch (value.kind) {
        case "claimed":
        case "accepted":
            return true;
        case "status":
            return isConnState(value.value);
        default:
            return false;
    }
}

function isOutcome(value: unknown): value is Outcome {
    if (!isObject(value)) {
        return false;
    }
    switch (value.status) {
        case "ok":
            return isResponseBody(value.value);
        case "error":
            return isErrorInfo(value.value);
        default:
            return false;
    }
}

export function isServerMessage(value: unknown): value is ServerMessage {
    if (!isObject(value) || !isObject(value.data)) {
        return false;
    }
    switch (value.type) {
        case "response":
            return isU32(value.data.id) && isOutcome(value.data.outcome);
        case "event":
            return value.data.kind === "state_changed" && isConnState(value.data.value);
        default:
            return false;
    }
}

/** Whether a parsed line from the bridge is one the contract allows. */
export function isBridgeLine(value: unknown): value is BridgeLine {
    if (!isObject(value)) {
        return false;
    }
    switch (value.type) {
        case "ready":
            return (
                typeof value.service_version === "string" &&
                typeof value.owner_claimed === "boolean"
            );
        case "update_needed":
            return typeof value.service_version === "string";
        case "service_unavailable":
        case "untrusted_service":
        case "not_owner":
        case "bad_line":
            return true;
        case "server":
            return isServerMessage(value.message);
        default:
            return false;
    }
}

// Typed against the generated unions, so a kind or code added to the protocol
// fails the type check here until it is listed.
const PROMPT_KINDS: Record<PromptKind, true> = {
    username: true,
    password: true,
    code: true,
    text: true,
};

const LOGIN_ERROR_CODES: Record<LoginErrorCode, true> = {
    wrong_password: true,
    pin_mismatch: true,
    cancelled: true,
    gateway_unreachable: true,
    route_refused: true,
    service_unavailable: true,
    busy: true,
    not_owner: true,
    internal: true,
};

/** Whether a parsed line from `ubc-vpn connect --json` is one the contract allows. */
export function isCliMessage(value: unknown): value is CliMessage {
    if (!isObject(value)) {
        return false;
    }
    switch (value.type) {
        case "prompt":
            return (
                isU32(value.id) &&
                typeof value.kind === "string" &&
                Object.hasOwn(PROMPT_KINDS, value.kind) &&
                typeof value.label === "string" &&
                (value.message === undefined || typeof value.message === "string")
            );
        case "done":
            return true;
        case "error":
            return (
                typeof value.code === "string" &&
                Object.hasOwn(LOGIN_ERROR_CODES, value.code) &&
                typeof value.message === "string"
            );
        default:
            return false;
    }
}
