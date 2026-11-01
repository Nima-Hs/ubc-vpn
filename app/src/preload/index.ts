// The only bridge between the interface and the rest of the app. It exposes a
// fixed list of functions; the interface never gets `ipcRenderer` itself, and
// none of these functions takes a channel name or passes arguments through.

import { DEMO_IPC, IPC, type Snapshot, type VpnApi } from "@shared/api";
import { LOGS_IPC, type LogUpdate } from "@shared/logs";
import { DEMO_PROFILES_IPC, PROFILES_IPC } from "@shared/profiles";
import type { ProfileId } from "@shared/protocol/ProfileId";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { StartMode } from "@shared/protocol/StartMode";
import { contextBridge, ipcRenderer } from "electron";

declare const __DEMO__: boolean;
declare const __LOGS__: boolean;
declare const __SETTINGS__: boolean;

/**
 * Asks the main process, and always answers with a promise, as `VpnApi`
 * promises. A value Electron cannot send is refused as a rejected promise:
 * from Electron 45 `ipcRenderer.invoke` throws at once instead, which would
 * reach the page as an exception where it expects a rejection. Only used
 * here, with the fixed channels below.
 */
function invoke<T>(channel: string, ...args: unknown[]): Promise<T> {
    try {
        return ipcRenderer.invoke(channel, ...args);
    } catch (error) {
        return Promise.reject(error);
    }
}

const api: VpnApi = {
    platform: process.platform,
    getSnapshot: () => invoke(IPC.getSnapshot),
    onSnapshot: (listener) => {
        const handler = (_event: unknown, snapshot: Snapshot) => listener(snapshot);
        ipcRenderer.on(IPC.snapshot, handler);
        return () => {
            ipcRenderer.off(IPC.snapshot, handler);
        };
    },
    connect: () => invoke(IPC.connect),
    disconnect: () => invoke(IPC.disconnect),
    answerPrompt: (id, value) => invoke(IPC.answerPrompt, id, value),
    cancelLogin: () => invoke(IPC.cancelLogin),
    setTunnel: (mode) => invoke(IPC.setTunnel, mode),
    getSettings: () => invoke(IPC.getSettings),
    checkRoutes: (input) => invoke(IPC.checkRoutes, input),
    saveRoutes: (input) => invoke(IPC.saveRoutes, input),
    retry: () => invoke(IPC.retry),
    minimizeWindow: () => invoke(IPC.minimizeWindow),
    closeWindow: () => invoke(IPC.closeWindow),
    ...(__LOGS__ && {
        logs: {
            open: () => invoke(LOGS_IPC.open),
            close: () => invoke(LOGS_IPC.close),
            onUpdate: (listener: (update: LogUpdate) => void) => {
                const handler = (_event: unknown, update: LogUpdate) => listener(update);
                ipcRenderer.on(LOGS_IPC.update, handler);
                return () => {
                    ipcRenderer.off(LOGS_IPC.update, handler);
                };
            },
            copyReport: () => invoke(LOGS_IPC.copyReport),
        },
    }),
    ...(__SETTINGS__ && {
        profiles: {
            list: () => invoke(PROFILES_IPC.list),
            setStartup: (start: StartMode, autoConnect: boolean) =>
                invoke(PROFILES_IPC.setStartup, start, autoConnect),
            forgetPassword: (id: ProfileId | null) => invoke(PROFILES_IPC.forgetPassword, id),
            create: (name: string) => invoke(PROFILES_IPC.create, name),
            rename: (id: ProfileId, name: string) => invoke(PROFILES_IPC.rename, id, name),
            update: (
                id: ProfileId,
                change: { username?: string | null; save_password?: boolean },
            ) => invoke(PROFILES_IPC.update, id, change),
            remove: (id: ProfileId) => invoke(PROFILES_IPC.remove, id),
            switchTo: (id: ProfileId) => invoke(PROFILES_IPC.switchTo, id),
            onChange: (listener: (view: ProfilesView) => void) => {
                const handler = (_event: unknown, view: ProfilesView) => listener(view);
                ipcRenderer.on(PROFILES_IPC.changed, handler);
                return () => {
                    ipcRenderer.off(PROFILES_IPC.changed, handler);
                };
            },
        },
    }),
    ...(__DEMO__ && {
        demo: {
            listScenarios: () => invoke(DEMO_IPC.listScenarios),
            setScenario: (name: string) => invoke(DEMO_IPC.setScenario, name),
            loginItem: () => invoke(DEMO_PROFILES_IPC.loginItem),
        },
    }),
};

contextBridge.exposeInMainWorld("ubcVpn", api);
