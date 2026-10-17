import type { Snapshot, VpnApi } from "@shared/api";
import { UNREAD_TUNNEL } from "@shared/tunnel";
import { create } from "zustand";

export const api: VpnApi = window.ubcVpn;

/** What the main process last sent. Until it answers, the app is "starting". */
export const useSnapshot = create<Snapshot>(() => ({
    state: { link: "starting" },
    notice: null,
    login: { phase: "idle" },
    loginProfile: null,
    tunnel: UNREAD_TUNNEL,
    closeHides: false,
    development: false,
}));

/** Starts following the main process. Call once, before the first render. */
export function followMainProcess(): void {
    api.onSnapshot((snapshot) => useSnapshot.setState(snapshot, true));
    void api.getSnapshot().then((snapshot) => useSnapshot.setState(snapshot, true));
}
