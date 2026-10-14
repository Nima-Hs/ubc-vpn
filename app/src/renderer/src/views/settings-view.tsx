import type { AccountError, AccountResult, AccountView } from "@shared/account";
import { describeAccountError, SETTINGS, whereKept } from "@shared/copy";
import { KeyRound, UserRoundX } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { Switch } from "@/components/ui/switch";
import { Heading, Subheading, Text } from "@/components/ui/text";
import { api } from "@/lib/store";

type Held =
    | { state: "loading" }
    | { state: "failed"; error: AccountError }
    | { state: "ready"; view: AccountView };

/** The Settings screen: what the app keeps for the user to log in, and how to forget it. */
export default function SettingsView() {
    const [held, setHeld] = useState<Held>({ state: "loading" });
    const [attempt, setAttempt] = useState(0);
    /** A change under way, so nothing else is pressed meanwhile. */
    const [busy, setBusy] = useState(false);
    /** What the last change came to, when it was not made. */
    const [refused, setRefused] = useState<AccountError | null>(null);
    /** The question before a saved password is forgotten. */
    const [asking, setAsking] = useState(false);
    const remember = useId();
    const rememberWhy = useId();

    useEffect(() => {
        const account = api.account;
        if (account === undefined) {
            return;
        }
        let current = true;
        setHeld({ state: "loading" });
        void account.get().then((result) => {
            if (current) {
                setHeld(
                    result.ok
                        ? { state: "ready", view: result.value }
                        : { state: "failed", error: result.error },
                );
            }
        });
        return () => {
            current = false;
        };
    }, [attempt]);

    const change = async (call: () => Promise<AccountResult> | undefined) => {
        setBusy(true);
        setRefused(null);
        const result = (await call()) ?? { ok: false, error: "unavailable" };
        setBusy(false);
        setAsking(false);
        if (result.ok) {
            setHeld({ state: "ready", view: result.value });
        } else {
            setRefused(result.error);
        }
    };

    return (
        <main className="scroll-region flex min-h-0 flex-1 flex-col gap-5 px-5 pt-2 pb-5">
            <section className="flex shrink-0 flex-col gap-2">
                <Heading>{SETTINGS.title}</Heading>
                <Text tone="secondary">{SETTINGS.body}</Text>
            </section>

            {held.state === "loading" && (
                <div role="status">
                    <Text tone="tertiary">{SETTINGS.loading}</Text>
                </div>
            )}

            {held.state === "failed" && (
                <div className="flex shrink-0 flex-col gap-3">
                    <Panel tone="problem">
                        <Text>{describeAccountError(held.error)}</Text>
                    </Panel>
                    <div className="flex">
                        <Button size="sm" onClick={() => setAttempt((before) => before + 1)}>
                            Try again
                        </Button>
                    </div>
                </div>
            )}

            {held.state === "ready" && (
                <section className="flex shrink-0 flex-col gap-3">
                    <Subheading>{SETTINGS.loggingIn}</Subheading>
                    <Panel className="shrink-0">
                        <div className="flex flex-col">
                            <div className="flex items-center justify-between gap-4 px-4 py-3">
                                <div className="flex min-w-0 flex-col gap-1">
                                    <Text size="label" tone="secondary">
                                        {SETTINGS.username}
                                    </Text>
                                    <Text data selectable>
                                        {held.view.username ?? SETTINGS.noUsername}
                                    </Text>
                                </div>
                                {held.view.username !== null && (
                                    <Button
                                        size="sm"
                                        variant="quiet"
                                        icon={<UserRoundX aria-hidden />}
                                        disabled={busy}
                                        onClick={() =>
                                            void change(() => api.account?.forgetUsername())
                                        }
                                    >
                                        {SETTINGS.forgetUsername}
                                    </Button>
                                )}
                            </div>
                            <div className="flex items-start justify-between gap-4 px-4 py-3">
                                <div className="flex min-w-0 flex-col gap-1">
                                    <Text>
                                        <span id={remember}>{SETTINGS.remember}</span>
                                    </Text>
                                    <Text size="label" tone="secondary">
                                        <span id={rememberWhy}>
                                            {held.view.keyring === "unavailable"
                                                ? SETTINGS.noKeyring
                                                : SETTINGS.rememberBody(whereKept(api.platform))}
                                        </span>
                                    </Text>
                                </div>
                                <Switch
                                    on={held.view.save_password}
                                    labelledBy={remember}
                                    describedBy={rememberWhy}
                                    disabled={busy || held.view.keyring === "unavailable"}
                                    onChange={(save) =>
                                        void change(() => api.account?.setSavePassword(save))
                                    }
                                />
                            </div>
                        </div>
                    </Panel>

                    {held.view.password_saved && !asking && (
                        <div className="flex">
                            <Button
                                size="sm"
                                icon={<KeyRound aria-hidden />}
                                disabled={busy}
                                onClick={() => setAsking(true)}
                            >
                                {SETTINGS.forgetPassword}
                            </Button>
                        </div>
                    )}
                    {held.view.password_saved && asking && (
                        <div role="alert">
                            <Panel tone="attention">
                                <Text>{SETTINGS.forgetAsk}</Text>
                                <div className="flex gap-2 pt-1">
                                    {/* The question takes the keyboard, so it cannot be missed. */}
                                    <Button
                                        size="sm"
                                        loading={busy}
                                        ref={(button) => button?.focus()}
                                        onClick={() =>
                                            void change(() => api.account?.forgetPassword())
                                        }
                                    >
                                        {SETTINGS.forgetYes}
                                    </Button>
                                    <Button
                                        size="sm"
                                        variant="quiet"
                                        disabled={busy}
                                        onClick={() => setAsking(false)}
                                    >
                                        {SETTINGS.forgetNo}
                                    </Button>
                                </div>
                            </Panel>
                        </div>
                    )}

                    {refused !== null && (
                        <Panel tone="problem">
                            <Text>{describeAccountError(refused)}</Text>
                        </Panel>
                    )}
                </section>
            )}

            <Text size="label" tone="tertiary" className="shrink-0">
                {SETTINGS.footer(__APP_VERSION__)}
            </Text>
        </main>
    );
}
