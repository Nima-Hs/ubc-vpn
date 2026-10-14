// The login details the client keeps for the user: the remembered username
// and the saved password.
//
// PROVISIONAL. The client does not have these commands yet. These shapes
// are the interface agreed for it (`settings get --json` carrying
// `password_saved` and `keyring`; `set-save-password`, `forget-password`,
// `forget-username`; the failure `keyring_unavailable`), written here by
// hand until it does. No production build contains any of this: see
// `__SETTINGS__`.

/** What the Settings screen shows about logging in. The password itself is never here. */
export interface AccountView {
    /** The remembered CWL username, if there is one. */
    username: string | null;
    /** Whether the password is to be kept in the system keyring. */
    save_password: boolean;
    /** Whether a password is in the keyring now. */
    password_saved: boolean;
    /** Whether this computer has a keyring the client can use. */
    keyring: "available" | "unavailable";
}

/** Why a change to the login details was not made. */
export type AccountError =
    /** The settings file could not be read or written. */
    | "unreadable"
    | "unwritable"
    /** There is no keyring the client can use. */
    | "keyring_unavailable"
    /** The client could not be run, or did not answer as it should. */
    | "unavailable";

export type AccountResult = { ok: true; value: AccountView } | { ok: false; error: AccountError };

/** Present only in builds that have the Settings screen. */
export interface AccountApi {
    get(): Promise<AccountResult>;
    /** Turns keeping the password on or off. Off also removes a saved one. */
    setSavePassword(save: boolean): Promise<AccountResult>;
    forgetPassword(): Promise<AccountResult>;
    forgetUsername(): Promise<AccountResult>;
}

export const ACCOUNT_IPC = {
    get: "account:get",
    setSavePassword: "account:set-save-password",
    forgetPassword: "account:forget-password",
    forgetUsername: "account:forget-username",
} as const;
