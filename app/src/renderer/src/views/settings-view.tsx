import { type ProfilesError, type ProfilesResult, startupSupported } from "@shared/profiles";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { StartMode } from "@shared/protocol/StartMode";
import { describeProfilesError, SETTINGS, whereKept } from "@shared/settings-copy";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { ProfileList } from "@/components/profile-list";
import { Button } from "@/components/ui/button";
import { ChoiceList } from "@/components/ui/choice-list";
import { Confirm } from "@/components/ui/confirm";
import { Panel } from "@/components/ui/panel";
import { Switch } from "@/components/ui/switch";
import { Heading, Subheading, Text } from "@/components/ui/text";
import { useProfiles } from "@/lib/profiles";
import { api } from "@/lib/store";

const START_ORDER: readonly StartMode[] = ["off", "window", "tray"];

/**
 * The Settings screen: the profiles, how UBC VPN starts, whether it connects
 * by itself, and the saved password. Every change is saved at once by the
 * command-line client; the screen shows what it saved, never what it hoped
 * to, as the main process tells it after every change.
 */
export default function SettingsView() {
    const { held, reload } = useProfiles();
    /** A change under way, so nothing else is pressed meanwhile. */
    const [busy, setBusy] = useState(false);
    /** Why the last change was not made, when it was not and is not said elsewhere. */
    const [refused, setRefused] = useState<ProfilesError | null>(null);
    /** The question before a saved password is forgotten. */
    const [asking, setAsking] = useState(false);
    /** Said once a saved password is forgotten. */
    const [forgotten, setForgotten] = useState(false);

    /** Runs a change and gives back why it was refused, or `null` once it is saved. */
    const attempt = async (
        call: () => Promise<ProfilesResult> | undefined,
    ): Promise<ProfilesError | null> => {
        setBusy(true);
        setRefused(null);
        setForgotten(false);
        const result = (await call()) ?? { ok: false, error: "unavailable" };
        setBusy(false);
        return result.ok ? null : result.error;
    };
    /** A change whose refusal is said at the foot of the screen. */
    const change = async (call: () => Promise<ProfilesResult> | undefined) => {
        const error = await attempt(call);
        setAsking(false);
        setRefused(error);
        return error === null;
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
                        <Button size="sm" onClick={reload}>
                            {SETTINGS.tryAgain}
                        </Button>
                    </div>
                </div>
            )}

            {held.state === "ready" && (
                <ProfileList view={held.view} busy={busy} change={attempt} />
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
                    <Confirm
                        question={SETTINGS.password.ask}
                        confirm={SETTINGS.password.yes}
                        cancel={SETTINGS.password.no}
                        busy={busy}
                        onConfirm={onForget}
                        onCancel={() => onAsk(false)}
                    />
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
