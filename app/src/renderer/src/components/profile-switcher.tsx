import { profileSwitchNote } from "@shared/copy";
import type { ProfilesError } from "@shared/profiles";
import { describeProfileRefusal, PROFILES } from "@shared/settings-copy";
import { ChevronDown } from "lucide-react";
import { useId, useState } from "react";
import { useProfiles } from "@/lib/profiles";
import { api, useSnapshot } from "@/lib/store";

/**
 * Which profile Connect uses, and a quick way to choose another, on the main
 * screen. Shown only when there is a choice. A profile chosen while a
 * connection is up or on its way is used by the next connect, and it says so.
 */
export function ProfileSwitcher() {
    const { held } = useProfiles();
    const state = useSnapshot((snapshot) => snapshot.state);
    const [busy, setBusy] = useState(false);
    const [refused, setRefused] = useState<ProfilesError | null>(null);
    const id = useId();
    const noteId = useId();

    if (held.state !== "ready" || held.view.profiles.length < 2) {
        return null;
    }
    const note = refused === null ? profileSwitchNote(state) : describeProfileRefusal(refused);

    return (
        <div className="flex shrink-0 flex-col gap-1">
            <div className="flex items-center gap-3">
                <label htmlFor={id} className="shrink-0 text-label text-text-secondary">
                    {PROFILES.switcher}
                </label>
                <div className="relative min-w-0 flex-1">
                    <select
                        id={id}
                        value={held.view.global.active_profile}
                        disabled={busy}
                        aria-describedby={note === null ? undefined : noteId}
                        onChange={async (event) => {
                            const chosen = event.currentTarget.value;
                            setBusy(true);
                            const result = await api.profiles?.switchTo(chosen);
                            setBusy(false);
                            setRefused(result === undefined || result.ok ? null : result.error);
                        }}
                        className="no-drag h-control-sm w-full cursor-default appearance-none truncate rounded-md border border-field-border bg-bg ps-3 pe-8 text-label text-text hover:bg-surface disabled:text-text-tertiary"
                    >
                        {held.view.profiles.map((profile) => (
                            <option key={profile.id} value={profile.id}>
                                {profile.name}
                            </option>
                        ))}
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
