import { ACCOUNT_IPC, type AccountResult } from "@shared/account";
import type { BrowserWindow } from "electron";
import { handleFromInterface } from "./ipc";

/**
 * What the Settings screen needs from the client about logging in. The
 * client keeps the username and the password; the app only asks it to show
 * or forget them, or to keep the password or not. No call carries the
 * password, in either direction.
 */
export interface AccountService {
    get(): Promise<AccountResult>;
    setSavePassword(save: boolean): Promise<AccountResult>;
    forgetPassword(): Promise<AccountResult>;
    forgetUsername(): Promise<AccountResult>;
}

/**
 * Takes the one argument of "keep the password or not": a plain `true` or
 * `false`, alone. Anything else is refused before anything happens, and the
 * refusal says only "refused".
 */
export function takeSave(args: readonly unknown[]): boolean {
    const [save] = args;
    if (args.length !== 1 || typeof save !== "boolean") {
        throw new Error("refused");
    }
    return save;
}

/** What each of the screen's requests does, by channel. None takes more than a yes or no. */
export function accountHandlers(
    account: AccountService,
): Record<(typeof ACCOUNT_IPC)[keyof typeof ACCOUNT_IPC], (...args: unknown[]) => unknown> {
    const none = (args: readonly unknown[]) => {
        if (args.length !== 0) {
            throw new Error("refused");
        }
    };
    return {
        [ACCOUNT_IPC.get]: (...args) => {
            none(args);
            return account.get();
        },
        [ACCOUNT_IPC.setSavePassword]: (...args) => account.setSavePassword(takeSave(args)),
        [ACCOUNT_IPC.forgetPassword]: (...args) => {
            none(args);
            return account.forgetPassword();
        },
        [ACCOUNT_IPC.forgetUsername]: (...args) => {
            none(args);
            return account.forgetUsername();
        },
    };
}

/** The Settings screen's requests, each checked to come from the interface's own page. */
export function registerAccount(
    window: BrowserWindow,
    devServerUrl: string | undefined,
    account: AccountService,
): void {
    for (const [channel, handler] of Object.entries(accountHandlers(account))) {
        handleFromInterface(window, devServerUrl, channel, handler);
    }
}
