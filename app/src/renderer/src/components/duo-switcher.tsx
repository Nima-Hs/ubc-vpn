import { DUO, DUO_METHODS, describeDuo } from "@shared/copy";
import type { ProfilesError } from "@shared/profiles";
import type { DuoMethod } from "@shared/protocol/DuoMethod";
import { describeProfileRefusal } from "@shared/settings-copy";
import { ChevronDown } from "lucide-react";
import { useId, useState } from "react";
import { useProfiles } from "@/lib/profiles";
import { api } from "@/lib/store";

/** What the list offers for a username sent as typed. */
const AS_TYPED = "as_typed";

/**
 * "Duo: Push", on the main screen: how the profile Connect uses confirms a
 * login, and a quick way to change it without opening Settings. The choice
 * is saved in the profile, as the profile editor saves it, and the next
 * connect uses it, an automatic one included.
 */
export function DuoSwitcher() {
    const { held } = useProfiles();
    const [busy, setBusy] = useState(false);
    const [refused, setRefused] = useState<ProfilesError | null>(null);
    const id = useId();
    const noteId = useId();

    if (held.state !== "ready") {
        return null;
    }
    const view = held.view;
    const active = view.profiles.find((profile) => profile.id === view.global.active_profile);
    if (active === undefined) {
        return null;
    }
    const method = active.duo_method;
    const note = refused === null ? null : describeProfileRefusal(refused);

    return (
        <div className="flex shrink-0 flex-col gap-1">
            <div className="flex items-center gap-3">
                <label htmlFor={id} className="shrink-0 text-label text-text-secondary">
                    {DUO.short}
                </label>
                <div className="relative min-w-0 flex-1">
                    <select
                        id={id}
                        value={method ?? AS_TYPED}
                        disabled={busy}
                        aria-describedby={note === null ? undefined : noteId}
                        onChange={async (event) => {
                            const chosen = event.currentTarget.value;
                            const next = chosen === AS_TYPED ? null : (chosen as DuoMethod);
                            setBusy(true);
                            const result = await api.profiles?.update(active.id, {
                                duo_method: next,
                            });
                            setBusy(false);
                            setRefused(result === undefined || result.ok ? null : result.error);
                        }}
                        className="no-drag h-control-sm w-full cursor-default appearance-none truncate rounded-md border border-field-border bg-bg ps-3 pe-8 text-label text-text hover:bg-surface disabled:text-text-tertiary"
                    >
                        {DUO_METHODS.map((choice) => (
                            <option key={choice} value={choice}>
                                {describeDuo(choice).short}
                            </option>
                        ))}
                        {/* Offered only to keep a username saved with its own @ part. */}
                        {method === null && <option value={AS_TYPED}>{DUO.asTyped.short}</option>}
                    </select>
                    <ChevronDown
                        aria-hidden
                        className="pointer-events-none absolute end-2 top-1/2 size-4 -translate-y-1/2 text-text-secondary"
                    />
                </div>
            </div>
            {note !== null && (
                <p id={noteId} className="text-caption text-text-secondary">
                    {note}
                </p>
            )}
        </div>
    );
}
