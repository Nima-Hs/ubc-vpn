// The tray's menu, as Electron's menu template. No Electron import, so what
// it holds in each state can be tested on its own.

import type { LinkState } from "@shared/api";
import { describe, profileSwitchNote, TRAY_PROFILE, TRAY_PROFILE_DURING_LOGIN } from "@shared/copy";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { ProfilesView } from "@shared/protocol/ProfilesView";

export interface TrayActions {
    showWindow(): void;
    connect(): void;
    disconnect(): void;
    retry(): void;
    quit(): void;
    /** Makes a profile the one the next connect uses. */
    switchProfile(id: ProfileId): void;
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
 * The menu: where things stand, the window, the one action, the profiles
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
): TrayMenuItem[] {
    const copy = describe(state);
    const run = {
        connect: actions.connect,
        disconnect: actions.disconnect,
        retry: actions.retry,
    };
    const note =
        profiles === null ? null : loggingIn ? TRAY_PROFILE_DURING_LOGIN : profileSwitchNote(state);
    return [
        { label: copy.title, enabled: false },
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
