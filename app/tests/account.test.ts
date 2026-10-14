// The Settings screen's requests about logging in: what the interface may
// send, what the demo's fake answers, and the words.

import { ACCOUNT_IPC, type AccountError, type AccountResult } from "@shared/account";
import { describeAccountError, SETTINGS, whereKept } from "@shared/copy";
import { describe, expect, it } from "vitest";
import { type AccountService, accountHandlers, takeSave } from "../src/main/account";
import { createDemoAccount, DEMO_ACCOUNT_SCENARIOS } from "../src/main/demo/demo-account";

const ok: AccountResult = {
    ok: true,
    value: { username: "someone", save_password: true, password_saved: true, keyring: "available" },
};

function recording() {
    const calls: string[] = [];
    const service: AccountService = {
        get: async () => {
            calls.push("get");
            return ok;
        },
        setSavePassword: async (save) => {
            calls.push(`save ${save}`);
            return ok;
        },
        forgetPassword: async () => {
            calls.push("forget password");
            return ok;
        },
        forgetUsername: async () => {
            calls.push("forget username");
            return ok;
        },
    };
    return { calls, handlers: accountHandlers(service) };
}

describe("what the interface may send about logging in", () => {
    it("is four requests, by these names", () => {
        expect(Object.keys(recording().handlers).sort()).toEqual(
            [
                "account:forget-password",
                "account:forget-username",
                "account:get",
                "account:set-save-password",
            ].sort(),
        );
    });

    it("passes a plain yes or no to keep the password, and nothing else", async () => {
        const { calls, handlers } = recording();
        await handlers[ACCOUNT_IPC.setSavePassword](true);
        await handlers[ACCOUNT_IPC.setSavePassword](false);
        expect(calls).toEqual(["save true", "save false"]);
    });

    it.each([
        ["nothing", []],
        ["two arguments", [true, true]],
        ["text", ["true"]],
        ["a number", [1]],
        ["an object", [{ save: true }]],
        ["null", [null]],
        // A password has no way in.
        ["a password", ["not-a-real-password-0123456789"]],
    ] as [string, unknown[]][])("refuses %s for keeping the password", (_name, args) => {
        expect(() => takeSave(args)).toThrow(/^refused$/);
        const { calls, handlers } = recording();
        expect(() => handlers[ACCOUNT_IPC.setSavePassword](...args)).toThrow(/^refused$/);
        expect(calls).toEqual([]);
    });

    it("refuses anything sent with the requests that take nothing", () => {
        const { calls, handlers } = recording();
        for (const channel of [
            ACCOUNT_IPC.get,
            ACCOUNT_IPC.forgetPassword,
            ACCOUNT_IPC.forgetUsername,
        ]) {
            expect(() => handlers[channel]("not-a-real-password-0123456789"), channel).toThrow(
                /^refused$/,
            );
        }
        expect(calls).toEqual([]);
    });

    it("refuses without a word about what was sent", () => {
        const secret = "not-a-real-password-0123456789";
        try {
            takeSave([secret]);
        } catch (error) {
            expect(`${(error as Error).message} ${(error as Error).stack}`).not.toContain(secret);
        }
    });
});

describe("the demo's pretend login details", () => {
    const value = async (result: Promise<AccountResult>) => {
        const answer = await result;
        if (!answer.ok) {
            throw new Error(answer.error);
        }
        return answer.value;
    };

    it("forgets a saved password, and the username", async () => {
        const demo = createDemoAccount(1);
        expect((await value(demo.get())).password_saved).toBe(true);
        expect((await value(demo.forgetPassword())).password_saved).toBe(false);
        expect((await value(demo.forgetUsername())).username).toBeNull();
    });

    it("turning keeping off also removes a saved password; turning it on saves none yet", async () => {
        const demo = createDemoAccount(1);
        const off = await value(demo.setSavePassword(false));
        expect(off).toMatchObject({ save_password: false, password_saved: false });
        const on = await value(demo.setSavePassword(true));
        expect(on).toMatchObject({ save_password: true, password_saved: false });
    });

    it("refuses to keep a password where there is no keyring", async () => {
        const demo = createDemoAccount(1);
        demo.setScenario("account-no-keyring");
        expect(await demo.setSavePassword(true)).toEqual({
            ok: false,
            error: "keyring_unavailable",
        });
    });

    it("has a state for each thing the screen must show", async () => {
        const demo = createDemoAccount(1);
        for (const name of DEMO_ACCOUNT_SCENARIOS) {
            demo.setScenario(name);
            expect((await demo.get()).ok, name).toBe(true);
        }
        demo.setScenario("account-unwritable");
        expect(await demo.forgetPassword()).toEqual({ ok: false, error: "unwritable" });
    });
});

describe("the Settings screen's words", () => {
    it("names where the password is kept, as the user knows it", () => {
        expect(whereKept("win32")).toBe("Windows Credential Manager");
        expect(whereKept("darwin")).toBe("the macOS Keychain");
        expect(whereKept("linux")).toBe("your keyring");
        expect(SETTINGS.rememberBody(whereKept("win32"))).toBe(
            "Kept in Windows Credential Manager, so you are asked only for the code.",
        );
    });

    it("says what happened and what to do for every failure", () => {
        const errors: AccountError[] = [
            "unreadable",
            "unwritable",
            "keyring_unavailable",
            "unavailable",
        ];
        const texts = errors.map(describeAccountError);
        expect(new Set(texts).size).toBe(errors.length);
        for (const text of texts) {
            expect(text).toMatch(/\.$/);
            expect(text).not.toMatch(/!|\bplease\b|\boops\b/i);
        }
    });

    it("asks before forgetting the password, and says what follows", () => {
        expect(SETTINGS.forgetAsk).toContain("You will be asked for it at the next login.");
        expect(SETTINGS.footer("0.1.0")).toBe(
            "UBC VPN 0.1.0. A report for whoever is helping you is on the Logs screen.",
        );
    });
});
