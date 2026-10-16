import { useId } from "react";
import { cn } from "@/lib/cn";
import { pressable } from "./button";

/**
 * An on-off setting: its name, a line saying what it does, and a switch.
 * The switch is a button with the switch role, so the keyboard turns it
 * with Space or Enter and a screen reader says whether it is on; it is named
 * by the label and described by the hint.
 */
export function Switch({
    label,
    hint,
    on,
    onChange,
    disabled = false,
}: {
    label: string;
    hint?: string;
    on: boolean;
    onChange(on: boolean): void;
    disabled?: boolean;
}) {
    const labelId = useId();
    const hintId = useId();
    return (
        <div className="flex items-start justify-between gap-4 px-4 py-3">
            <div className="flex min-w-0 flex-col gap-1">
                <span id={labelId} className="text-body text-text">
                    {label}
                </span>
                {hint !== undefined && (
                    <span id={hintId} className="text-label text-text-secondary">
                        {hint}
                    </span>
                )}
            </div>
            <button
                type="button"
                role="switch"
                aria-checked={on}
                aria-labelledby={labelId}
                aria-describedby={hint === undefined ? undefined : hintId}
                aria-disabled={disabled || undefined}
                onClick={() => {
                    if (!disabled) {
                        onChange(!on);
                    }
                }}
                className={cn(
                    pressable,
                    // The track. The knob sits in it, centred, with the same
                    // room on every side.
                    "mt-0.5 h-6 w-10 justify-start rounded-full p-0.5",
                    on
                        ? "border-accent bg-accent hover:bg-accent-hover"
                        : "border-field-border bg-control hover:bg-control-hover",
                    disabled && "border-border bg-control",
                )}
            >
                <span
                    aria-hidden
                    className={cn(
                        "size-4.5 rounded-full shadow-control",
                        "transition-transform duration-(--dur-fast) ease-out",
                        on ? "translate-x-4 bg-on-accent" : "translate-x-0 bg-text-secondary",
                        disabled && "bg-text-tertiary",
                    )}
                />
            </button>
        </div>
    );
}
