import { useId } from "react";
import { cn } from "@/lib/cn";

/**
 * One choice out of a few, each on its own row with a line saying what it
 * does. Native radio buttons, so the arrow keys move between them and a
 * screen reader says which is chosen; the group is named by `legend`.
 */
export function ChoiceList<T extends string>({
    legend,
    options,
    value,
    onChange,
    disabled = false,
    note,
}: {
    legend: string;
    /** An option with `disabled` is shown but cannot be chosen; `note` should say why. */
    options: readonly {
        value: T;
        label: string;
        hint?: string | undefined;
        disabled?: boolean;
    }[];
    value: T;
    onChange(value: T): void;
    disabled?: boolean;
    /** Said under the list, for example why it cannot be changed. */
    note?: string | undefined;
}) {
    const name = useId();
    const noteId = useId();
    return (
        <fieldset
            className="flex min-w-0 flex-col gap-2"
            aria-describedby={note === undefined ? undefined : noteId}
            disabled={disabled}
        >
            <legend className="pb-2 font-strong text-title text-text">{legend}</legend>
            <div className="flex flex-col divide-y divide-border overflow-hidden rounded-xl border border-border-strong bg-surface shadow-surface">
                {options.map((option) => {
                    const off = disabled || option.disabled === true;
                    return (
                        <label
                            key={option.value}
                            className={cn(
                                "flex items-start gap-3 px-4 py-3",
                                !off && "hover:bg-quiet-hover",
                            )}
                        >
                            <input
                                type="radio"
                                name={name}
                                value={option.value}
                                checked={value === option.value}
                                disabled={option.disabled === true}
                                onChange={() => onChange(option.value)}
                                className="mt-1 size-4 shrink-0 accent-accent"
                            />
                            <span className="flex min-w-0 flex-col gap-0.5">
                                <span
                                    className={cn(
                                        "text-body",
                                        off ? "text-text-tertiary" : "text-text",
                                    )}
                                >
                                    {option.label}
                                </span>
                                {option.hint !== undefined && (
                                    <span className="text-label text-text-secondary">
                                        {option.hint}
                                    </span>
                                )}
                            </span>
                        </label>
                    );
                })}
            </div>
            {note !== undefined && (
                <p id={noteId} className="text-label text-text-secondary">
                    {note}
                </p>
            )}
        </fieldset>
    );
}
