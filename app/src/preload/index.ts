// The only bridge between the interface and the rest of the app. It exposes a
// fixed list of functions; the interface never gets `ipcRenderer` itself, and
// none of these functions takes a channel name or passes arguments through.

import { DEMO_IPC, IPC, type Snapshot, type VpnApi } from "@shared/api";
import { contextBridge, ipcRenderer } from "electron";

declare const __DEMO__: boolean;

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
    retry: () => ipcRenderer.invoke(IPC.retry),
    minimizeWindow: () => ipcRenderer.invoke(IPC.minimizeWindow),
    closeWindow: () => ipcRenderer.invoke(IPC.closeWindow),
    ...(__DEMO__ && {
        demo: {
            listScenarios: () => ipcRenderer.invoke(DEMO_IPC.listScenarios),
            setScenario: (name: string) => ipcRenderer.invoke(DEMO_IPC.setScenario, name),
        },
    }),
};

contextBridge.exposeInMainWorld("ubcVpn", api);
