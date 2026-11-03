// The user's profiles, as the screens that show them share them: read once
// from the main process, then kept as it says they are after every change,
// made here or from the tray.

import type { ProfilesError, ProfilesResult } from "@shared/profiles";
import type { DuoMethod } from "@shared/protocol/DuoMethod";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import { useEffect, useState } from "react";
import { api, useSnapshot } from "@/lib/store";

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

/**
 * The Duo method of the profile a login is for: the one in use when it
 * started, or the active one. `undefined` until the profiles are read, or
 * in a build without them.
 */
export function useLoginMethod(): DuoMethod | null | undefined {
    const { held } = useProfiles();
    const loginProfile = useSnapshot((snapshot) => snapshot.loginProfile);
    if (held.state !== "ready") {
        return undefined;
    }
    const bound = loginProfile ?? held.view.global.active_profile;
    return held.view.profiles.find((profile) => profile.id === bound)?.duo_method;
}
