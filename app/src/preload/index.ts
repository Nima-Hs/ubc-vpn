// The only bridge between the interface and the rest of the app. It exposes a
// fixed list of functions; the interface never gets `ipcRenderer` itself, and
// none of these functions takes a channel name or passes arguments through.

import { DEMO_IPC, IPC, type Snapshot, type VpnApi } from "@shared/api";
import { LOGS_IPC, type LogUpdate } from "@shared/logs";
import { contextBridge, ipcRenderer } from "electron";

declare const __DEMO__: boolean;
declare const __LOGS__: boolean;

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
    ...(__DEMO__ && {
        demo: {
            listScenarios: () => ipcRenderer.invoke(DEMO_IPC.listScenarios),
            setScenario: (name: string) => ipcRenderer.invoke(DEMO_IPC.setScenario, name),
        },
    }),
};

contextBridge.exposeInMainWorld("ubcVpn", api);
