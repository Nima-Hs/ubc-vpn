// A stand-in for the client's login details, for demo builds only. It
// follows the interface agreed for the client and keeps no password: there
// is none to keep, only whether one would be saved.

import type { AccountError, AccountResult, AccountView } from "@shared/account";
import type { AccountService } from "../account";

export const DEMO_ACCOUNT_SCENARIOS = [
    "account-saved",
    "account-not-saved",
    "account-new",
    "account-no-keyring",
    "account-unwritable",
] as const;

const SAVED: AccountView = {
    username: "someone",
    save_password: true,
    password_saved: true,
    keyring: "available",
};

const VIEWS: Record<(typeof DEMO_ACCOUNT_SCENARIOS)[number], AccountView> = {
    "account-saved": SAVED,
    "account-not-saved": { ...SAVED, save_password: false, password_saved: false },
    "account-new": { ...SAVED, username: null, password_saved: false },
    "account-no-keyring": {
        ...SAVED,
        save_password: false,
        password_saved: false,
        keyring: "unavailable",
    },
    "account-unwritable": SAVED,
};

export interface DemoAccount extends AccountService {
    setScenario(name: string): void;
}

export function createDemoAccount(stepMs = 300): DemoAccount {
    let scenario: (typeof DEMO_ACCOUNT_SCENARIOS)[number] = "account-saved";
    let view: AccountView = { ...SAVED };
    const later = (result: AccountResult) =>
        new Promise<AccountResult>((resolve) => setTimeout(() => resolve(result), stepMs));
    const fail = (error: AccountError) => later({ ok: false, error });
    const change = (next: AccountView) => {
        if (scenario === "account-unwritable") {
            return fail("unwritable");
        }
        view = next;
        return later({ ok: true, value: { ...view } });
    };
    return {
        get: () => later({ ok: true, value: { ...view } }),
        setSavePassword: (save) => {
            if (save && view.keyring === "unavailable") {
                return fail("keyring_unavailable");
            }
            // Turning it off removes a saved password; turning it on saves
            // nothing until the next login that works.
            return change({
                ...view,
                save_password: save,
                password_saved: save && view.password_saved,
            });
        },
        forgetPassword: () => change({ ...view, password_saved: false }),
        forgetUsername: () => change({ ...view, username: null }),
        setScenario: (name) => {
            if ((DEMO_ACCOUNT_SCENARIOS as readonly string[]).includes(name)) {
                scenario = name as typeof scenario;
                view = { ...VIEWS[scenario] };
            }
        },
    };
}
