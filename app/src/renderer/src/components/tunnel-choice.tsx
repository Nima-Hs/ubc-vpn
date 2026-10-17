import type { TunnelMode } from "@shared/protocol/TunnelMode";
import { describeProfilesError } from "@shared/settings-copy";
import {
    describeTunnelOutcome,
    shownMode,
    switchesLive,
    TUNNEL,
    TUNNEL_MODES,
    tunnelLocked,
} from "@shared/tunnel";
import { TriangleAlert } from "lucide-react";
import { useId } from "react";
import { ChoiceList } from "@/components/ui/choice-list";
import { Panel } from "@/components/ui/panel";
import { Text } from "@/components/ui/text";
import { cn } from "@/lib/cn";
import { api, useSnapshot } from "@/lib/store";

/**
 * The one tunnel setting, as the main screen and Settings both show it:
 * which mode is shown, whether each can be chosen, and the line to say
 * beside it. Whatever the window or the tray chose, both show the same,
 * from the snapshot.
 */
function useTunnelChoice() {
    const { state, tunnel, login } = useSnapshot();
    const locked = tunnelLocked(state, tunnel, login.phase !== "idle");
    const value = shownMode(state, tunnel);
    const unavailable = locked !== null || tunnel.switching !== null;
    // The same line before, during and after a switch, so nothing moves.
    const note =
        locked ??
        (!tunnel.fullAllowed ? TUNNEL.forbidden : switchesLive(state) ? TUNNEL.live : null);
    const outcome =
        tunnel.outcome === null
            ? null
            : describeTunnelOutcome(tunnel.outcome, (error) =>
                  describeProfilesError(error, "change"),
              );
    const choosable = (mode: TunnelMode) => !unavailable && (mode !== "full" || tunnel.fullAllowed);
    const choose = (mode: TunnelMode) => {
        if (mode !== value && choosable(mode)) {
            void api.setTunnel(mode);
        }
    };
    return { value, unavailable, note, outcome, choosable, choose };
}

/** What came of the last switch, when it did not go as asked. */
export function TunnelOutcome() {
    const { outcome } = useTunnelChoice();
    if (outcome === null) {
        return null;
    }
    return (
        <Panel tone="attention" className="shrink-0">
            <Text>{outcome.title}</Text>
            <Text size="label" tone="secondary" selectable>
                {outcome.body}
            </Text>
        </Panel>
    );
}

/** The words of the last outcome, for a screen's own polite status line. */
export function useTunnelOutcomeText(): string {
    const { outcome } = useTunnelChoice();
    return outcome === null ? "" : `${outcome.title}. ${outcome.body}`;
}

/**
 * The main screen's switch: split or full, side by side. Native radio
 * buttons, so the arrow keys move between them and a screen reader says
 * which is chosen and why one cannot be.
 */
export function TunnelSwitch({ className }: { className?: string }) {
    const { value, unavailable, note: plainNote, outcome, choosable, choose } = useTunnelChoice();
    // What came of a switch takes the note's place, right under the choice,
    // in as little room as it can: the main button stays in view.
    const note = outcome === null ? plainNote : `${outcome.title}: ${outcome.body}`;
    const name = useId();
    const labelId = useId();
    const noteId = useId();
    return (
        <div className={cn("flex min-w-0 shrink-0 flex-col gap-1", className)}>
            <div className="flex items-center gap-3">
                <span id={labelId} className="shrink-0 text-label text-text-secondary">
                    {TUNNEL.legend}
                </span>
                <div
                    role="radiogroup"
                    aria-labelledby={labelId}
                    aria-describedby={note === null ? undefined : noteId}
                    className="flex h-control-sm min-w-0 flex-1 gap-0.5 rounded-md border border-field-border bg-bg p-0.5"
                >
                    {TUNNEL_MODES.map((mode) => {
                        const checked = value === mode;
                        const enabled = choosable(mode);
                        return (
                            <label
                                key={mode}
                                className={cn(
                                    "segment no-drag relative flex min-w-0 flex-1 items-center justify-center rounded-sm px-2 text-label",
                                    "transition-[background-color,color,box-shadow] duration-(--dur-fast) ease-out",
                                    checked
                                        ? "bg-control text-text shadow-control"
                                        : "text-text-secondary",
                                    !checked && enabled && "hover:bg-surface hover:text-text",
                                    !enabled && !checked && "text-text-tertiary",
                                )}
                            >
                                <input
                                    type="radio"
                                    name={name}
                                    value={mode}
                                    checked={checked}
                                    // The one being used stays reachable, so the
                                    // keyboard can find the group and hear why.
                                    disabled={!enabled && !checked}
                                    aria-disabled={unavailable || undefined}
                                    onChange={() => choose(mode)}
                                    className="sr-only"
                                />
                                <span className="truncate">{TUNNEL.names[mode]}</span>
                            </label>
                        );
                    })}
                </div>
            </div>
            {note !== null && (
                <p
                    id={noteId}
                    className={cn(
                        "flex items-start gap-1.5 text-caption",
                        outcome === null ? "text-text-secondary" : "select-text text-attention",
                    )}
                >
                    {/* Something did not go as asked: marked as well as coloured. */}
                    {outcome !== null && (
                        <TriangleAlert aria-hidden className="mt-0.5 size-3 shrink-0" />
                    )}
                    {note}
                </p>
            )}
        </div>
    );
}

/** Settings' version: each mode on its own row, with what it does. */
export function TunnelSettings() {
    const { value, unavailable, note, choosable, choose } = useTunnelChoice();
    return (
        <section className="flex shrink-0 flex-col gap-3">
            <ChoiceList
                legend={TUNNEL.legend}
                value={value}
                note={note ?? undefined}
                // As on the main screen: what cannot be chosen is disabled,
                // and the one chosen stays reachable while it is locked.
                options={TUNNEL_MODES.map((mode) => ({
                    value: mode,
                    label: TUNNEL.names[mode],
                    hint: TUNNEL.hints[mode],
                    disabled: mode !== value && !choosable(mode),
                    locked: mode === value && unavailable,
                }))}
                onChange={choose}
            />
            <TunnelOutcome />
        </section>
    );
}
