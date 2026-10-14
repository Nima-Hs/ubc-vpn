import { cn } from "@/lib/cn";
import { pressable } from "./button";

/**
 * An on-off switch. It is a button with the switch role, so the keyboard
 * turns it with Space or Enter and a screen reader says whether it is on.
 * Its name comes from the text it sits beside (\`labelledBy\`), and its
 * explanation from the text under that (\`describedBy\`).
 */
export function Switch({
    on,
    onChange,
    labelledBy,
    describedBy,
    disabled = false,
}: {
    on: boolean;
    onChange(on: boolean): void;
    labelledBy: string;
    describedBy?: string;
    disabled?: boolean;
}) {
    return (
        <button
            type="button"
            role="switch"
            aria-checked={on}
            aria-labelledby={labelledBy}
            aria-describedby={describedBy}
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
                "h-6 w-10 justify-start rounded-full p-0.5",
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
    );
}
