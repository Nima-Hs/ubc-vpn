// The user's profiles, as the screens that show them share them: read once
// from the main process, then kept as it says they are after every change,
// made here or from the tray.

import type { ProfilesError, ProfilesResult } from "@shared/profiles";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import { useEffect, useState } from "react";
import { api } from "@/lib/store";

export type HeldProfiles =
    | { state: "loading" }
    | { state: "failed"; error: ProfilesError }
    | { state: "ready"; view: ProfilesView };

/** The profiles, and a way to read them again. */
export function useProfiles(): { held: HeldProfiles; reload: () => void } {
    const [held, setHeld] = useState<HeldProfiles>({ state: "loading" });
    const [attempt, setAttempt] = useState(0);

    useEffect(() => {
        const profiles = api.profiles;
        if (profiles === undefined) {
            return;
        }
        let current = true;
        setHeld((before) => (before.state === "ready" ? before : { state: "loading" }));
        void profiles.list().then((result: ProfilesResult) => {
            if (current) {
                setHeld(
                    result.ok
                        ? { state: "ready", view: result.value }
                        : { state: "failed", error: result.error },
                );
            }
        });
        const stop = profiles.onChange((view) => {
            if (current) {
                setHeld({ state: "ready", view });
            }
        });
        return () => {
            current = false;
            stop();
        };
    }, [attempt]);

    return { held, reload: () => setAttempt((before) => before + 1) };
}
