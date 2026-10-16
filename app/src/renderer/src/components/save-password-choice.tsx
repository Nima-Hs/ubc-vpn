import type { ProfilesError } from "@shared/profiles";
import { describeProfileRefusal, LOGIN_SAVE, SETTINGS, whereKept } from "@shared/settings-copy";
import { useState } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { useProfiles } from "@/lib/profiles";
import { api, useSnapshot } from "@/lib/store";

/**
 * "Save password", beside the password question: whether the profile this
 * login is for keeps its password, which is the profile in use when the
 * login started, whatever is chosen since. Only the choice is saved here; the client saves the
 * password itself, and only after a login that works. Without a keyring the
 * choice is off and disabled, with the reason.
 */
export function SavePasswordChoice() {
    const { held } = useProfiles();
    // The login is bound to the profile it started with; this choice is that profile's.
    const loginProfile = useSnapshot((snapshot) => snapshot.loginProfile);
    const [busy, setBusy] = useState(false);
    const [refused, setRefused] = useState<ProfilesError | null>(null);
    if (held.state !== "ready") {
        return null;
    }
    const view = held.view;
    const bound = loginProfile ?? view.global.active_profile;
    const active = view.profiles.find((profile) => profile.id === bound);
    if (active === undefined) {
        return null;
    }
    const noKeyring = view.keyring === "unavailable";
    return (
        <Checkbox
            label={LOGIN_SAVE.label}
            hint={
                refused !== null
                    ? describeProfileRefusal(refused, view.keyring)
                    : noKeyring
                      ? SETTINGS.password.noKeyring
                      : LOGIN_SAVE.hint(whereKept(api.platform))
            }
            checked={!noKeyring && active.save_password}
            disabled={busy || noKeyring}
            onChange={async (save) => {
                setBusy(true);
                const result = await api.profiles?.update(active.id, { save_password: save });
                setBusy(false);
                setRefused(result === undefined || result.ok ? null : result.error);
            }}
        />
    );
}
