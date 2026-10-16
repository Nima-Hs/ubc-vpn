import { type ProfilesError, type ProfilesResult, startupSupported } from "@shared/profiles";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { StartMode } from "@shared/protocol/StartMode";
import { describeProfilesError, SETTINGS, whereKept } from "@shared/settings-copy";
import { KeyRound } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ChoiceList } from "@/components/ui/choice-list";
import { Panel } from "@/components/ui/panel";
import { Switch } from "@/components/ui/switch";
import { Heading, Subheading, Text } from "@/components/ui/text";
import { api } from "@/lib/store";

type Held =
    | { state: "loading" }
    | { state: "failed"; error: ProfilesError }
    | { state: "ready"; view: ProfilesView };

const START_ORDER: readonly StartMode[] = ["off", "window", "tray"];

/**
 * The Settings screen: how UBC VPN starts, whether it connects by itself,
 * and the saved password. Every change is saved at once by the command-line
 * client; the screen shows what it saved, never what it hoped to.
 */
export default function SettingsView() {
    const [held, setHeld] = useState<Held>({ state: "loading" });
    const [attempt, setAttempt] = useState(0);
    /** A change under way, so nothing else is pressed meanwhile. */
    const [busy, setBusy] = useState(false);
    /** Why the last change was not made, when it was not. */
    const [refused, setRefused] = useState<ProfilesError | null>(null);
    /** The question before a saved password is forgotten. */
    const [asking, setAsking] = useState(false);
    /** Said once a saved password is forgotten. */
    const [forgotten, setForgotten] = useState(false);

    useEffect(() => {
        const profiles = api.profiles;
        if (profiles === undefined) {
            return;
        }
        let current = true;
        setHeld({ state: "loading" });
        void profiles.list().then((result) => {
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

    const change = async (call: () => Promise<ProfilesResult> | undefined) => {
        setBusy(true);
        setRefused(null);
        setForgotten(false);
        const result = (await call()) ?? { ok: false, error: "unavailable" };
        setBusy(false);
        setAsking(false);
        if (result.ok) {
            setHeld({ state: "ready", view: result.value });
        } else {
            setRefused(result.error);
        }
        return result.ok;
    };

    return (
        <main className="scroll-region flex min-h-0 flex-1 flex-col gap-6 px-5 pt-2 pb-5">
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
                        <Text>{describeProfilesError(held.error, "read")}</Text>
                    </Panel>
                    <div className="flex">
                        <Button size="sm" onClick={() => setAttempt((before) => before + 1)}>
                            {SETTINGS.tryAgain}
                        </Button>
                    </div>
                </div>
            )}

            {held.state === "ready" && (
                <Ready
                    view={held.view}
                    busy={busy}
                    asking={asking}
                    forgotten={forgotten}
                    onAsk={setAsking}
                    onStartup={(start, autoConnect) =>
                        void change(() => api.profiles?.setStartup(start, autoConnect))
                    }
                    onForget={() =>
                        void change(() => api.profiles?.forgetPassword(null)).then((done) =>
                            setForgotten(done),
                        )
                    }
                />
            )}

            {refused !== null && (
                <div role="alert" className="shrink-0">
                    <Panel tone="problem">
                        <Text>{describeProfilesError(refused, "change")}</Text>
                    </Panel>
                </div>
            )}
        </main>
    );
}

function Ready({
    view,
    busy,
    asking,
    forgotten,
    onAsk,
    onStartup,
    onForget,
}: {
    view: ProfilesView;
    busy: boolean;
    asking: boolean;
    forgotten: boolean;
    onAsk(asking: boolean): void;
    onStartup(start: StartMode, autoConnect: boolean): void;
    onForget(): void;
}) {
    const { start, auto_connect: autoConnect } = view.global;
    const active = view.profiles.find((profile) => profile.id === view.global.active_profile);
    const saved = active?.password_saved === true;
    const canStart = startupSupported(api.platform);
    const noKeyring = view.keyring === "unavailable";

    return (
        <>
            <section className="flex shrink-0 flex-col gap-3">
                <ChoiceList
                    legend={SETTINGS.startup.heading}
                    value={canStart ? start : "off"}
                    disabled={busy || !canStart}
                    note={canStart ? undefined : SETTINGS.startup.notHere}
                    options={START_ORDER.map((mode) => ({
                        value: mode,
                        ...SETTINGS.startup.options[mode],
                    }))}
                    onChange={(mode) => onStartup(mode, autoConnect)}
                />
                <Panel className="shrink-0">
                    <Switch
                        label={SETTINGS.autoConnect.label}
                        hint={
                            saved
                                ? SETTINGS.autoConnect.withPassword
                                : SETTINGS.autoConnect.withoutPassword
                        }
                        on={autoConnect}
                        disabled={busy}
                        onChange={(on) => onStartup(start, on)}
                    />
                </Panel>
            </section>

            <section className="flex shrink-0 flex-col gap-3">
                <Subheading>{SETTINGS.password.heading}</Subheading>
                <Text tone="secondary">
                    {noKeyring
                        ? SETTINGS.password.noKeyring
                        : saved
                          ? SETTINGS.password.saved(whereKept(api.platform))
                          : SETTINGS.password.notSaved}
                </Text>
                {saved && !asking && (
                    <div className="flex">
                        <Button
                            size="sm"
                            icon={<KeyRound aria-hidden />}
                            disabled={busy}
                            onClick={() => onAsk(true)}
                        >
                            {SETTINGS.password.forget}
                        </Button>
                    </div>
                )}
                {saved && asking && (
                    <div role="alert">
                        <Panel tone="attention">
                            <Text>{SETTINGS.password.ask}</Text>
                            <div className="flex gap-2 pt-1">
                                {/* The question takes the keyboard, so it cannot be missed. */}
                                <Button
                                    size="sm"
                                    variant="destructive"
                                    loading={busy}
                                    ref={(button) => button?.focus()}
                                    onClick={onForget}
                                >
                                    {SETTINGS.password.yes}
                                </Button>
                                <Button
                                    size="sm"
                                    variant="quiet"
                                    disabled={busy}
                                    onClick={() => onAsk(false)}
                                >
                                    {SETTINGS.password.no}
                                </Button>
                            </div>
                        </Panel>
                    </div>
                )}
                {forgotten && (
                    <p role="status" className="sr-only">
                        {SETTINGS.password.forgotten}
                    </p>
                )}
            </section>
        </>
    );
}
