// The tray's menu, as Electron's menu template. No Electron import, so what
// it holds in each state can be tested on its own.

import type { LinkState } from "@shared/api";
import { describe, profileSwitchNote, TRAY_PROFILE, TRAY_PROFILE_DURING_LOGIN } from "@shared/copy";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import { describeProfilesError } from "@shared/settings-copy";
import {
    describeTunnelOutcome,
    switchesLive,
    TUNNEL,
    TUNNEL_MODES,
    type TunnelStatus,
    tunnelLocked,
    UNREAD_TUNNEL,
} from "@shared/tunnel";

export interface TrayActions {
    showWindow(): void;
    connect(): void;
    disconnect(): void;
    retry(): void;
    quit(): void;
    /** Makes a profile the one the next connect uses. */
    switchProfile(id: ProfileId): void;
    /** Switches between split and full tunnel, as the window does. */
    setTunnel(mode: TunnelMode): void;
}

/** One entry of the menu: a subset of Electron's `MenuItemConstructorOptions`. */
export interface TrayMenuItem {
    label?: string;
    type?: "separator" | "radio" | "submenu";
    enabled?: boolean;
    checked?: boolean;
    click?: () => void;
    submenu?: TrayMenuItem[];
}

/**
 * The tray's line for where things stand: the title, and the tunnel mode
 * while connected, so the tooltip and the menu say which.
 */
export function trayStatus(state: LinkState, tunnel: TunnelStatus = UNREAD_TUNNEL): string {
    const copy = describe(state, tunnel);
    if (switchesLive(state) && tunnel.switching !== null) {
        return `Switching to ${TUNNEL.names[tunnel.switching.to].toLowerCase()}`;
    }
    return switchesLive(state)
        ? `${copy.title}, ${TUNNEL.names[copy.mode].toLowerCase()}`
        : copy.title;
}

/**
 * The tunnel submenu: split and full, the one in use checked. Full is not
 * offered where the policy forbids it, and neither while the mode is fixed.
 * Atop them, why, or what switching does, or what came of the last switch.
 */
function tunnelMenu(
    state: LinkState,
    tunnel: TunnelStatus,
    actions: TrayActions,
    loggingIn: boolean,
): TrayMenuItem {
    const copy = describe(state, tunnel);
    const locked = tunnelLocked(state, tunnel, loggingIn);
    const outcome =
        tunnel.outcome === null
            ? null
            : describeTunnelOutcome(tunnel.outcome, (error) =>
                  describeProfilesError(error, "change"),
              );
    const notes = [
        ...(outcome === null ? [] : [outcome.title, outcome.body]),
        ...(locked !== null
            ? [locked]
            : !tunnel.fullAllowed
              ? [TUNNEL.forbidden]
              : switchesLive(state)
                ? [TUNNEL.live]
                : []),
    ];
    return {
        label: TUNNEL.legend,
        type: "submenu",
        submenu: [
            ...notes.map((label) => ({ label, enabled: false })),
            ...TUNNEL_MODES.map((mode) => ({
                label: TUNNEL.names[mode],
                type: "radio" as const,
                checked: copy.mode === mode,
                enabled:
                    locked === null &&
                    tunnel.switching === null &&
                    (mode !== "full" || tunnel.fullAllowed),
                click: () => actions.setTunnel(mode),
            })),
        ],
    };
}

/**
 * The menu: where things stand, the window, the one action, the tunnel, the profiles
 * when there is more than one to choose from, and Quit. A profile chosen
 * while connected or connecting is used by the next connect, and the
 * submenu says so. While a login is under way the profiles cannot be
 * changed: the login is for the profile it started with, and the submenu
 * says so.
 */
export function trayMenu(
    state: LinkState,
    profiles: ProfilesView | null,
    actions: TrayActions,
    loggingIn = false,
    tunnel: TunnelStatus = UNREAD_TUNNEL,
): TrayMenuItem[] {
    const copy = describe(state, tunnel);
    const run = {
        connect: actions.connect,
        disconnect: actions.disconnect,
        retry: actions.retry,
    };
    const note =
        profiles === null ? null : loggingIn ? TRAY_PROFILE_DURING_LOGIN : profileSwitchNote(state);
    return [
        { label: trayStatus(state, tunnel), enabled: false },
        { type: "separator" },
        { label: "Show UBC VPN", click: actions.showWindow },
        ...(copy.action === null
            ? []
            : [
                  {
                      label: copy.action.label,
                      enabled: !copy.working,
                      click: run[copy.action.kind],
                  },
              ]),
        { type: "separator" },
        tunnelMenu(state, tunnel, actions, loggingIn),
        ...(profiles === null || profiles.profiles.length < 2
            ? []
            : [
                  { type: "separator" as const },
                  {
                      label: TRAY_PROFILE,
                      type: "submenu" as const,
                      submenu: [
                          ...(note === null ? [] : [{ label: note, enabled: false }]),
                          ...profiles.profiles.map((profile) => ({
                              label: profile.name,
                              type: "radio" as const,
                              checked: profile.id === profiles.global.active_profile,
                              enabled: !loggingIn,
                              click: () => actions.switchProfile(profile.id),
                          })),
                      ],
                  },
              ]),
        { type: "separator" },
        { label: "Quit UBC VPN", click: actions.quit },
    ];
}
