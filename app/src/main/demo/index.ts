// Demo mode's wiring: the pretend service, login, settings, log and
// profiles, and the IPC the interface uses to pick a scenario. Reached only
// through a dynamic import behind `__DEMO__` in `../index.ts`, so no
// production build contains any of it (`pnpm check:build`).

import { DEMO_IPC } from "@shared/api";
import { DEMO_PROFILES_IPC } from "@shared/profiles";
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import type { BrowserWindow } from "electron";
import type { ProfilesService } from "../channel/profiles";
import type { SettingsService } from "../channel/settings";
import type { LoginFactory } from "../controller";
import { handleFromInterface } from "../ipc";
import type { ServiceLink } from "../link";
import type { LogFeed } from "../logs/book";
import type { LoginItem } from "../startup";
import type { TunnelSwitch } from "../tunnel-switch";
import { createDemoLink, DEMO_SCENARIOS } from "./demo-link";
import { createDemoLogin, DEMO_LOGIN_SCENARIOS } from "./demo-login";
import { createDemoLogs, DEMO_LOG_SCENARIOS } from "./demo-logs";
import { createDemoProfiles, DEMO_PROFILES_SCENARIOS } from "./demo-profiles";
import { createDemoSettings, DEMO_SETTINGS_SCENARIOS } from "./demo-settings";

/** What the demo needs from the app that is made after it. */
export interface DemoApp {
    devServerUrl: string | undefined;
    /** The watched profiles, once the app has made them. */
    profiles: () => ProfilesService | undefined;
    /** The split or full switch, once the app has made it. */
    tunnelSwitch: () => TunnelSwitch | undefined;
    /** The last request to start at sign-in, which a demo only records. */
    loginItem: () => LoginItem | null;
}

/** The fakes a demo build uses in place of the service and the client. */
export interface Demo {
    link: ServiceLink;
    login: LoginFactory;
    settings: SettingsService;
    profiles: ProfilesService;
    logs: LogFeed;
    /** The interface's way to pick a scenario, for the one window. */
    register: (window: BrowserWindow) => void;
}

export function createDemo(app: DemoApp): Demo {
    const { devServerUrl } = app;
    const fakeSettings = createDemoSettings();
    const stepMs = Number(process.env.UBC_VPN_DEMO_STEP_MS);
    const step = Number.isFinite(stepMs) && stepMs > 0 ? stepMs : undefined;
    // The pretend service connects with the mode the pretend settings
    // hold, and switches a live connection when they change.
    let savedMode: TunnelMode = "split";
    const demo = createDemoLink(step, () => savedMode);
    const fakeProfiles = createDemoProfiles((mode) => {
        savedMode = mode;
        return demo.switchTunnel(mode);
    });
    const fakeLogs = createDemoLogs(step);
    let demoLogin: ReturnType<typeof createDemoLogin> | undefined;
    const login: LoginFactory = (onState) => {
        demoLogin = createDemoLogin(onState, () => void demo.connect(), step);
        return demoLogin;
    };
    const register = (window: BrowserWindow) => {
        handleFromInterface(window, devServerUrl, DEMO_IPC.listScenarios, () => [
            ...DEMO_SCENARIOS,
            ...DEMO_LOGIN_SCENARIOS,
            ...DEMO_SETTINGS_SCENARIOS,
            ...DEMO_LOG_SCENARIOS,
            ...DEMO_PROFILES_SCENARIOS,
        ]);
        handleFromInterface(window, devServerUrl, DEMO_IPC.setScenario, (name) => {
            if (typeof name === "string") {
                // A login state, or a connection state with no login under way.
                demoLogin?.setScenario(name);
                demo.setScenario(name);
                fakeSettings.setScenario(name);
                fakeLogs.setScenario(name);
                fakeProfiles.setScenario(name);
                // Everyone hears of the scenario's profiles, the saved mode among them.
                void app
                    .profiles()
                    ?.list()
                    .then((result) => {
                        if (result.ok) {
                            savedMode = result.value.global.tunnel;
                        } else {
                            app.tunnelSwitch()?.readFailed();
                        }
                    });
            }
        });
        handleFromInterface(window, devServerUrl, DEMO_PROFILES_IPC.loginItem, () => {
            const asked = app.loginItem();
            return asked === null ? null : { openAtLogin: asked.openAtLogin, args: asked.args };
        });
    };
    return {
        link: demo,
        login,
        settings: fakeSettings,
        profiles: fakeProfiles,
        logs: fakeLogs,
        register,
    };
}
