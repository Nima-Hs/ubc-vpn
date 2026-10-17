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

const api: VpnApi = {
    platform: process.platform,
    getSnapshot: () => ipcRenderer.invoke(IPC.getSnapshot),
    onSnapshot: (listener) => {
        const handler = (_event: unknown, snapshot: Snapshot) => listener(snapshot);
        ipcRenderer.on(IPC.snapshot, handler);
        return () => {
            ipcRenderer.off(IPC.snapshot, handler);
        };
    },
    connect: () => ipcRenderer.invoke(IPC.connect),
    disconnect: () => ipcRenderer.invoke(IPC.disconnect),
    answerPrompt: (id, value) => ipcRenderer.invoke(IPC.answerPrompt, id, value),
    cancelLogin: () => ipcRenderer.invoke(IPC.cancelLogin),
    setTunnel: (mode) => ipcRenderer.invoke(IPC.setTunnel, mode),
    getSettings: () => ipcRenderer.invoke(IPC.getSettings),
    checkRoutes: (input) => ipcRenderer.invoke(IPC.checkRoutes, input),
    saveRoutes: (input) => ipcRenderer.invoke(IPC.saveRoutes, input),
    retry: () => ipcRenderer.invoke(IPC.retry),
    minimizeWindow: () => ipcRenderer.invoke(IPC.minimizeWindow),
    closeWindow: () => ipcRenderer.invoke(IPC.closeWindow),
    ...(__LOGS__ && {
        logs: {
            open: () => ipcRenderer.invoke(LOGS_IPC.open),
            close: () => ipcRenderer.invoke(LOGS_IPC.close),
            onUpdate: (listener: (update: LogUpdate) => void) => {
                const handler = (_event: unknown, update: LogUpdate) => listener(update);
                ipcRenderer.on(LOGS_IPC.update, handler);
                return () => {
                    ipcRenderer.off(LOGS_IPC.update, handler);
                };
            },
            copyReport: () => ipcRenderer.invoke(LOGS_IPC.copyReport),
        },
    }),
    ...(__SETTINGS__ && {
        profiles: {
            list: () => ipcRenderer.invoke(PROFILES_IPC.list),
            setStartup: (start: StartMode, autoConnect: boolean) =>
                ipcRenderer.invoke(PROFILES_IPC.setStartup, start, autoConnect),
            forgetPassword: (id: ProfileId | null) =>
                ipcRenderer.invoke(PROFILES_IPC.forgetPassword, id),
            create: (name: string) => ipcRenderer.invoke(PROFILES_IPC.create, name),
            rename: (id: ProfileId, name: string) =>
                ipcRenderer.invoke(PROFILES_IPC.rename, id, name),
            update: (
                id: ProfileId,
                change: { username?: string | null; save_password?: boolean },
            ) => ipcRenderer.invoke(PROFILES_IPC.update, id, change),
            remove: (id: ProfileId) => ipcRenderer.invoke(PROFILES_IPC.remove, id),
            switchTo: (id: ProfileId) => ipcRenderer.invoke(PROFILES_IPC.switchTo, id),
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
            listScenarios: () => ipcRenderer.invoke(DEMO_IPC.listScenarios),
            setScenario: (name: string) => ipcRenderer.invoke(DEMO_IPC.setScenario, name),
            loginItem: () => ipcRenderer.invoke(DEMO_PROFILES_IPC.loginItem),
        },
    }),
};

contextBridge.exposeInMainWorld("ubcVpn", api);
