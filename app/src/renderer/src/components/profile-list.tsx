import type { ProfilesError, ProfilesResult } from "@shared/profiles";
import type { ProfilesView } from "@shared/protocol/ProfilesView";
import type { ProfileView } from "@shared/protocol/ProfileView";
import { describeProfileRefusal, PROFILES, SETTINGS, whereKept } from "@shared/settings-copy";
import { Plus, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Button } from "@/components/ui/button";
import { Confirm } from "@/components/ui/confirm";
import { Switch } from "@/components/ui/switch";
import { Subheading, Text } from "@/components/ui/text";
import { TextField } from "@/components/ui/text-field";
import { api } from "@/lib/store";

/** Runs a change and says whether it was made, or why not. */
type Change = (call: () => Promise<ProfilesResult> | undefined) => Promise<ProfilesError | null>;

/**
 * The user's profiles in Settings: one row each, the one in use marked, a
 * way to use another, an editor for one profile at a time, and a form to
 * add one. Every change is the client's to accept: a refusal is said beside
 * what was changed, and what is shown is always what is saved.
 */
export function ProfileList({
    view,
    busy,
    change,
}: {
    view: ProfilesView;
    busy: boolean;
    change: Change;
}) {
    const [editing, setEditing] = useState<string | null>(null);
    const active = view.global.active_profile;

    return (
        <section className="flex shrink-0 flex-col gap-3">
            <Subheading>{PROFILES.heading}</Subheading>
            <Text tone="secondary">{PROFILES.body}</Text>
            <ul className="flex flex-col divide-y divide-border overflow-hidden rounded-xl border border-border-strong bg-surface shadow-surface">
                {view.profiles.map((profile) => (
                    <li key={profile.id} className="flex flex-col">
                        <div className="flex items-center gap-3 px-4 py-3">
                            <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                                <span className="flex min-w-0 items-center gap-2">
                                    <span className="truncate text-body text-text">
                                        {profile.name}
                                    </span>
                                    {profile.id === active && (
                                        <span className="shrink-0 rounded-full bg-accent-subtle px-2 text-caption text-text">
                                            {PROFILES.inUse}
                                        </span>
                                    )}
                                </span>
                                <span
                                    translate="no"
                                    className="truncate font-data text-label text-text-secondary"
                                >
                                    {profile.username ?? PROFILES.noUsername}
                                </span>
                            </div>
                            {profile.id !== active && (
                                <Button
                                    size="sm"
                                    variant="quiet"
                                    disabled={busy}
                                    aria-label={PROFILES.use(profile.name)}
                                    onClick={() =>
                                        void change(() => api.profiles?.switchTo(profile.id))
                                    }
                                >
                                    Use
                                </Button>
                            )}
                            <Button
                                size="sm"
                                variant={editing === profile.id ? "secondary" : "quiet"}
                                aria-expanded={editing === profile.id}
                                aria-label={
                                    editing === profile.id
                                        ? PROFILES.done
                                        : PROFILES.edit(profile.name)
                                }
                                onClick={() =>
                                    setEditing((now) => (now === profile.id ? null : profile.id))
                                }
                            >
                                {editing === profile.id ? PROFILES.done : "Edit"}
                            </Button>
                        </div>
                        {editing === profile.id && (
                            <Editor
                                profile={profile}
                                keyring={view.keyring}
                                onlyOne={view.profiles.length === 1}
                                busy={busy}
                                change={change}
                                onDeleted={() => setEditing(null)}
                            />
                        )}
                    </li>
                ))}
            </ul>
            <Text size="label" tone="tertiary">
                {PROFILES.routesNote}
            </Text>
            <AddProfile busy={busy} change={change} />
        </section>
    );
}

function Editor({
    profile,
    keyring,
    onlyOne,
    busy,
    change,
    onDeleted,
}: {
    profile: ProfileView;
    keyring: ProfilesView["keyring"];
    onlyOne: boolean;
    busy: boolean;
    change: Change;
    onDeleted(): void;
}) {
    const [name, setName] = useState(profile.name);
    const [username, setUsername] = useState(profile.username ?? "");
    const [nameError, setNameError] = useState<string | undefined>();
    const [usernameError, setUsernameError] = useState<string | undefined>();
    const [asking, setAsking] = useState(false);
    const [deleteError, setDeleteError] = useState<string | undefined>();
    /** Why the last change to saving the password was refused, said under it. */
    const [saveError, setSaveError] = useState<string | undefined>();
    const noKeyring = keyring === "unavailable";

    const rename = async (event: FormEvent) => {
        event.preventDefault();
        const refused = await change(() => api.profiles?.rename(profile.id, name));
        setNameError(refused === null ? undefined : describeProfileRefusal(refused));
    };
    const saveUsername = async (event: FormEvent) => {
        event.preventDefault();
        const typed = username.trim();
        const refused = await change(() =>
            api.profiles?.update(profile.id, { username: typed === "" ? null : typed }),
        );
        setUsernameError(refused === null ? undefined : describeProfileRefusal(refused));
    };

    return (
        <div className="flex flex-col gap-4 border-t border-border bg-bg px-4 py-4">
            <form className="flex flex-col gap-2" onSubmit={rename} noValidate autoComplete="off">
                <TextField
                    label={PROFILES.name}
                    value={name}
                    maxLength={256}
                    onChange={(event) => setName(event.currentTarget.value)}
                    error={nameError}
                />
                <div className="flex">
                    <Button type="submit" size="sm" disabled={busy || name.trim() === profile.name}>
                        {PROFILES.rename}
                    </Button>
                </div>
            </form>
            <form
                className="flex flex-col gap-2"
                onSubmit={saveUsername}
                noValidate
                autoComplete="off"
            >
                <TextField
                    label={PROFILES.username}
                    hint={PROFILES.usernameHint}
                    value={username}
                    maxLength={256}
                    data
                    autoCapitalize="none"
                    onChange={(event) => setUsername(event.currentTarget.value)}
                    error={usernameError}
                />
                <div className="flex">
                    <Button
                        type="submit"
                        size="sm"
                        disabled={busy || username.trim() === (profile.username ?? "")}
                    >
                        {PROFILES.saveUsername}
                    </Button>
                </div>
            </form>
            <div className="-mx-4">
                <Switch
                    label={PROFILES.savePassword}
                    hint={
                        saveError ??
                        (noKeyring
                            ? SETTINGS.password.noKeyring
                            : PROFILES.savePasswordHint(whereKept(api.platform)))
                    }
                    on={profile.save_password}
                    disabled={busy || noKeyring}
                    onChange={async (on) => {
                        const refused = await change(() =>
                            api.profiles?.update(profile.id, { save_password: on }),
                        );
                        setSaveError(
                            refused === null ? undefined : describeProfileRefusal(refused, keyring),
                        );
                    }}
                />
            </div>
            {!asking ? (
                <div className="flex flex-col gap-1">
                    <div className="flex">
                        <Button
                            size="sm"
                            variant="quiet"
                            icon={<Trash2 aria-hidden />}
                            disabled={busy || onlyOne}
                            aria-describedby={onlyOne ? `${profile.id}-last` : undefined}
                            onClick={() => setAsking(true)}
                        >
                            {PROFILES.delete}
                        </Button>
                    </div>
                    {onlyOne && (
                        <span id={`${profile.id}-last`} className="text-label text-text-tertiary">
                            {PROFILES.lastOne}
                        </span>
                    )}
                </div>
            ) : (
                <Confirm
                    question={PROFILES.deleteAsk(profile.name)}
                    confirm={PROFILES.deleteYes}
                    cancel={PROFILES.deleteNo}
                    busy={busy}
                    onConfirm={async () => {
                        const refused = await change(() => api.profiles?.remove(profile.id));
                        if (refused === null) {
                            onDeleted();
                        } else {
                            setDeleteError(describeProfileRefusal(refused));
                        }
                    }}
                    onCancel={() => {
                        setAsking(false);
                        setDeleteError(undefined);
                    }}
                >
                    {deleteError !== undefined && (
                        <Text size="label" tone="danger">
                            {deleteError}
                        </Text>
                    )}
                </Confirm>
            )}
        </div>
    );
}

function AddProfile({ busy, change }: { busy: boolean; change: Change }) {
    const [name, setName] = useState("");
    const [error, setError] = useState<string | undefined>();
    const [added, setAdded] = useState<string | null>(null);

    const add = async (event: FormEvent) => {
        event.preventDefault();
        const typed = name;
        const refused = await change(() => api.profiles?.create(typed));
        if (refused === null) {
            setName("");
            setError(undefined);
            setAdded(typed.trim());
        } else {
            setError(describeProfileRefusal(refused));
            setAdded(null);
        }
    };

    return (
        <form className="flex flex-col gap-2" onSubmit={add} noValidate autoComplete="off">
            <TextField
                label={PROFILES.newName}
                hint={error === undefined ? PROFILES.newNameHint : undefined}
                value={name}
                maxLength={256}
                onChange={(event) => setName(event.currentTarget.value)}
                error={error}
            />
            <div className="flex">
                <Button
                    type="submit"
                    size="sm"
                    icon={<Plus aria-hidden />}
                    disabled={busy || name.trim() === ""}
                >
                    {PROFILES.add}
                </Button>
            </div>
            {added !== null && (
                <p role="status" className="sr-only">
                    {`Added ${added}.`}
                </p>
            )}
        </form>
    );
}
