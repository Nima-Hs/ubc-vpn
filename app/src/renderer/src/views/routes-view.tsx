import type { SettingsError } from "@shared/api";
import {
    describeRouteLimits,
    describeRouteProblem,
    describeSettingsError,
    ROUTES,
} from "@shared/copy";
import type { RouteInput } from "@shared/protocol/RouteInput";
import type { RouteList } from "@shared/protocol/RouteList";
import type { RouteProblem } from "@shared/protocol/RouteProblem";
import type { SettingsView } from "@shared/protocol/SettingsView";
import { Plus, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { Panel } from "@/components/ui/panel";
import { Heading, Subheading, Text } from "@/components/ui/text";
import { TextField } from "@/components/ui/text-field";
import { leave, setUnsaved, stay, useNavigation } from "@/lib/navigation";
import { api, useSnapshot } from "@/lib/store";

/** One line of a list. The id stays with the row as others come and go. */
interface Row {
    id: number;
    value: string;
}
type Rows = Record<RouteList, Row[]>;

let nextId = 1;
const rowsOf = (values: readonly string[]): Row[] =>
    values.map((value) => ({ id: nextId++, value }));

/** What is sent to be checked: the rows that have something in them, in order. */
function inputOf(rows: Rows): { input: RouteInput; ids: Record<RouteList, number[]> } {
    const filled = (list: Row[]) => list.filter((row) => row.value !== "");
    return {
        input: {
            subnets: filled(rows.subnets).map((row) => row.value),
            dns_domains: filled(rows.dns_domains).map((row) => row.value),
        },
        ids: {
            subnets: filled(rows.subnets).map((row) => row.id),
            dns_domains: filled(rows.dns_domains).map((row) => row.id),
        },
    };
}

type Check =
    | { state: "checking" }
    | { state: "ok" }
    | { state: "invalid"; problems: RouteProblem[]; ids: Record<RouteList, number[]> }
    | { state: "failed"; error: SettingsError };

const PLACEHOLDER: Record<RouteList, string> = {
    subnets: "203.0.113.0/24",
    dns_domains: "campus.example",
};
const ROW_NAME: Record<RouteList, string> = { subnets: "Subnet", dns_domains: "Domain" };
const ADD: Record<RouteList, string> = { subnets: "Add subnet", dns_domains: "Add domain" };

function Entries({
    list,
    rows,
    problems,
    onChange,
}: {
    list: RouteList;
    rows: Row[];
    problems: Map<number, string>;
    onChange(rows: Row[]): void;
}) {
    // The row that was just added takes the keyboard.
    const added = useRef<number | null>(null);
    return (
        <div className="flex flex-col gap-2">
            {rows.map((row, index) => (
                <div key={row.id} className="row-lazy flex items-start gap-1">
                    <TextField
                        label={`${ROW_NAME[list]} ${index + 1}`}
                        hideLabel
                        data
                        className="min-w-0 flex-1"
                        placeholder={PLACEHOLDER[list]}
                        value={row.value}
                        autoCapitalize="none"
                        autoCorrect="off"
                        ref={(field) => {
                            if (field !== null && added.current === row.id) {
                                added.current = null;
                                field.focus();
                            }
                        }}
                        onChange={(event) =>
                            onChange(
                                rows.map((other) =>
                                    other.id === row.id
                                        ? { ...other, value: event.target.value }
                                        : other,
                                ),
                            )
                        }
                        {...(problems.has(row.id) && { error: problems.get(row.id) as string })}
                    />
                    <IconButton
                        label={`Remove ${ROW_NAME[list].toLowerCase()} ${index + 1}`}
                        tooltipSide="left"
                        className="shrink-0"
                        onClick={() => onChange(rows.filter((other) => other.id !== row.id))}
                    >
                        <X />
                    </IconButton>
                </div>
            ))}
            <div className="flex">
                <Button
                    size="sm"
                    icon={<Plus aria-hidden />}
                    onClick={() => {
                        const row = { id: nextId++, value: "" };
                        added.current = row.id;
                        onChange([...rows, row]);
                    }}
                >
                    {ADD[list]}
                </Button>
            </div>
        </div>
    );
}

function Editor({ view, onSaved }: { view: SettingsView; onSaved(routes: RouteInput): void }) {
    const [rows, setRows] = useState<Rows>(() => ({
        subnets: rowsOf(view.settings.routes.subnets),
        dns_domains: rowsOf(view.settings.routes.dns_domains),
    }));
    const [check, setCheck] = useState<Check>({ state: "checking" });
    const [saving, setSaving] = useState(false);
    const [saveError, setSaveError] = useState<SettingsError | null>(null);
    const [justSaved, setJustSaved] = useState(false);
    const wanted = useNavigation((navigation) => navigation.wanted);
    const connected = useSnapshot(
        (snapshot) =>
            snapshot.state.link === "ready" && snapshot.state.conn.state !== "disconnected",
    );

    const { input, ids } = useMemo(() => inputOf(rows), [rows]);
    const signature = JSON.stringify(input);
    const changed = signature !== JSON.stringify(view.settings.routes);

    useEffect(() => {
        setUnsaved(changed);
        return () => setUnsaved(false);
    }, [changed]);

    // Check a moment after the typing stops, and once on opening, before
    // anything is typed: a stored entry the client would refuse is marked
    // on its row from the start. Only the newest answer counts, and a check
    // that a newer one replaced says nothing.
    useEffect(() => {
        let current = true;
        setCheck({ state: "checking" });
        const timer = setTimeout(() => {
            void api.checkRoutes(input).then((result) => {
                if (!current || (!result.ok && result.error === "superseded")) {
                    return;
                }
                if (!result.ok) {
                    setCheck({ state: "failed", error: result.error });
                } else if (result.value.type === "ok") {
                    setCheck({ state: "ok" });
                } else {
                    setCheck({ state: "invalid", problems: result.value.problems, ids });
                }
            });
        }, 300);
        return () => {
            current = false;
            clearTimeout(timer);
        };
    }, [signature]);

    const edit = useCallback((list: RouteList, next: Row[]) => {
        setJustSaved(false);
        setSaveError(null);
        setRows((before) => ({ ...before, [list]: next }));
    }, []);

    const save = async () => {
        setSaving(true);
        setSaveError(null);
        const result = await api.saveRoutes(input);
        setSaving(false);
        if (!result.ok) {
            setSaveError(result.error);
        } else if (result.value.type === "invalid") {
            setCheck({ state: "invalid", problems: result.value.problems, ids });
        } else {
            setJustSaved(true);
            onSaved(result.value.routes);
        }
    };

    // Each problem goes on its own row; one about the whole list is said once.
    const byRow: Record<RouteList, Map<number, string>> = {
        subnets: new Map(),
        dns_domains: new Map(),
    };
    const whole: string[] = [];
    if (check.state === "invalid") {
        for (const problem of check.problems) {
            const text = describeRouteProblem(problem.code, view);
            const id =
                problem.list === null ? undefined : check.ids[problem.list][problem.index ?? -1];
            if (problem.list !== null && id !== undefined) {
                byRow[problem.list].set(id, text);
            } else if (!whole.includes(text)) {
                whole.push(text);
            }
        }
    }
    const limits = describeRouteLimits(view);
    const status = saving
        ? null
        : check.state === "checking"
          ? ROUTES.checking
          : justSaved && !changed
            ? ROUTES.saved
            : null;

    return (
        <>
            <div className="scroll-region flex min-h-0 flex-1 flex-col gap-6">
                {limits.noPolicy !== undefined && (
                    <Panel tone="attention">
                        <Text>{limits.noPolicy}</Text>
                    </Panel>
                )}
                <Panel className="shrink-0">
                    <div className="flex flex-col gap-1 px-4 py-3">
                        <Text size="label" tone="secondary">
                            {limits.limits}
                        </Text>
                        {limits.allowed !== undefined && (
                            <>
                                <Text size="label" tone="secondary">
                                    {limits.allowed}
                                </Text>
                                <Text size="label" data selectable>
                                    {(view.allowed_routes ?? []).join(", ")}
                                </Text>
                            </>
                        )}
                    </div>
                </Panel>

                <section className="flex flex-col gap-3">
                    <Subheading>{ROUTES.subnets}</Subheading>
                    {rows.subnets.length === 0 && <Text tone="tertiary">{ROUTES.noSubnets}</Text>}
                    <Entries
                        list="subnets"
                        rows={rows.subnets}
                        problems={byRow.subnets}
                        onChange={(next) => edit("subnets", next)}
                    />
                </section>

                <section className="flex flex-col gap-3">
                    <Subheading>{ROUTES.domains}</Subheading>
                    <Text size="label" tone="secondary">
                        {rows.dns_domains.length === 0 ? ROUTES.noDomains : ROUTES.domainsBody}
                    </Text>
                    <Entries
                        list="dns_domains"
                        rows={rows.dns_domains}
                        problems={byRow.dns_domains}
                        onChange={(next) => edit("dns_domains", next)}
                    />
                </section>
            </div>

            <div className="flex shrink-0 flex-col gap-3">
                {whole.map((text) => (
                    <Panel key={text} tone="problem">
                        <Text>{text}</Text>
                    </Panel>
                ))}
                {check.state === "failed" && (
                    <Panel tone="problem">
                        <Text>{describeSettingsError(check.error, "check")}</Text>
                    </Panel>
                )}
                {saveError !== null && (
                    <Panel tone="problem">
                        <Text>{describeSettingsError(saveError, "save")}</Text>
                    </Panel>
                )}
                {wanted !== null && (
                    <Panel tone="attention">
                        <Text>{ROUTES.unsaved}</Text>
                        <div className="flex gap-2 pt-1">
                            {/* The question takes the keyboard, so it cannot be missed. */}
                            <Button size="sm" ref={(button) => button?.focus()} onClick={stay}>
                                Keep editing
                            </Button>
                            <Button size="sm" variant="quiet" onClick={leave}>
                                Discard changes
                            </Button>
                        </div>
                    </Panel>
                )}
                {connected && changed && (
                    <Text size="label" tone="secondary">
                        {ROUTES.whileConnected}
                    </Text>
                )}
                <Button
                    block
                    size="lg"
                    variant="primary"
                    loading={saving}
                    // Nothing is saved that has not just been checked and found acceptable.
                    disabled={!changed || check.state !== "ok"}
                    onClick={() => void save()}
                >
                    {saving ? "Saving…" : "Save routes"}
                </Button>
                {/* Read out, politely: checking, saved, and anything that went wrong. */}
                <p role="status" className="sr-only">
                    {status} {whole.join(" ")}{" "}
                    {saveError !== null && describeSettingsError(saveError, "save")}
                </p>
            </div>
        </>
    );
}

/** The Routes screen: which subnets and domains go through the VPN. */
export function RoutesView() {
    const [loaded, setLoaded] = useState<
        | { state: "loading" }
        | { state: "failed"; error: SettingsError }
        | { state: "ready"; view: SettingsView }
    >({ state: "loading" });
    const [attempt, setAttempt] = useState(0);

    useEffect(() => {
        let current = true;
        setLoaded({ state: "loading" });
        void api.getSettings().then((result) => {
            if (current) {
                setLoaded(
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

    return (
        <main className="flex min-h-0 flex-1 flex-col gap-5 px-5 pt-2 pb-5">
            <section className="flex shrink-0 flex-col gap-2">
                <Heading>{ROUTES.title}</Heading>
                <Text tone="secondary">{ROUTES.body}</Text>
            </section>
            {loaded.state === "loading" && (
                <div role="status">
                    <Text tone="tertiary">{ROUTES.loading}</Text>
                </div>
            )}
            {loaded.state === "failed" && (
                <>
                    <div className="flex min-h-0 flex-1 flex-col">
                        <Panel tone="problem">
                            <Text>{describeSettingsError(loaded.error, "read")}</Text>
                        </Panel>
                    </div>
                    <Button block size="lg" onClick={() => setAttempt((before) => before + 1)}>
                        Try again
                    </Button>
                </>
            )}
            {loaded.state === "ready" && (
                <Editor
                    view={loaded.view}
                    onSaved={(routes) =>
                        setLoaded({
                            state: "ready",
                            view: { ...loaded.view, settings: { ...loaded.view.settings, routes } },
                        })
                    }
                />
            )}
        </main>
    );
}
