import { describeInstallNotice, describeUpdate, UPDATES } from "@shared/settings-copy";
import { RefreshCw, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { Switch } from "@/components/ui/switch";
import { Subheading, Text } from "@/components/ui/text";
import { api } from "@/lib/store";
import { useUpdates } from "@/lib/updates";
import { UpdateNotices } from "./update-notices";

const WHEN = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

/**
 * "Automatic updates", where updates stand, "Restart to update" once an
 * update is ready, and "Check for updates now".
 * The setting is saved like the others; the rest comes from the updater in
 * the main process, which alone decides what to trust.
 */
export function UpdateSettings({
    automatic,
    busy,
    onAutomatic,
}: {
    automatic: boolean;
    busy: boolean;
    onAutomatic(on: boolean): void;
}) {
    const view = useUpdates();
    const phase = view?.status.phase;
    const said = view === null ? null : describeUpdate(view.status);
    const working = phase === "checking" || phase === "downloading" || phase === "installing";

    return (
        <section className="flex shrink-0 flex-col gap-3">
            <Subheading>{UPDATES.heading}</Subheading>
            <Panel className="shrink-0">
                <Switch
                    label={UPDATES.automatic.label}
                    hint={UPDATES.automatic.hint}
                    on={automatic}
                    disabled={busy}
                    onChange={onAutomatic}
                />
            </Panel>
            {said !== null && (
                <div role="status">
                    <Text tone="secondary">{said}</Text>
                </div>
            )}
            <UpdateNotices view={view} />
            {view?.notice != null && (
                <div role="alert">
                    <Panel tone="problem">
                        <Text>{describeInstallNotice(view.notice)}</Text>
                    </Panel>
                </div>
            )}
            {(phase === "ready" || phase === "installing") && (
                <div className="flex flex-col gap-2">
                    <div className="flex">
                        <Button
                            variant="primary"
                            size="sm"
                            icon={<RotateCcw aria-hidden />}
                            disabled={phase === "installing"}
                            onClick={() => void api.updates.install()}
                        >
                            {UPDATES.restart}
                        </Button>
                    </div>
                    <Text tone="tertiary">{UPDATES.restartHint}</Text>
                </div>
            )}
            {/* Shown even where this copy cannot update, and explained above. */}
            {view !== null && (
                <div className="flex flex-wrap items-center gap-3">
                    <Button
                        size="sm"
                        icon={<RefreshCw aria-hidden />}
                        disabled={working || phase === "unavailable"}
                        onClick={() => void api.updates.checkNow()}
                    >
                        {UPDATES.checkNow}
                    </Button>
                    {phase !== "unavailable" && (
                        <Text tone="tertiary">
                            {view.lastChecked === null
                                ? UPDATES.neverChecked
                                : UPDATES.lastChecked(WHEN.format(view.lastChecked))}
                        </Text>
                    )}
                </div>
            )}
        </section>
    );
}
