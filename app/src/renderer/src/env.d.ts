/// <reference types="vite/client" />

/** `true` only in builds made with `--mode demo`. */
declare const __DEMO__: boolean;

/** `true` only in builds that have the log screen. See `electron.vite.config.ts`. */
declare const __LOGS__: boolean;

/** `true` only in builds that have the Settings screen. See `electron.vite.config.ts`. */
declare const __SETTINGS__: boolean;

/** The app's version, from `package.json`. */
declare const __APP_VERSION__: string;
