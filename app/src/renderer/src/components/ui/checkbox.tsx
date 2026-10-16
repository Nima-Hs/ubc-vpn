import { useId } from "react";
import { cn } from "@/lib/cn";

/**
 * A yes-or-no choice in a form: a native checkbox, named by its label and
 * described by the line under it, so the keyboard and screen readers treat
 * it as the platform's own.
 */
export function Checkbox({
    label,
    hint,
    checked,
    onChange,
    disabled = false,
}: {
    label: string;
    hint?: string | undefined;
    checked: boolean;
    onChange(checked: boolean): void;
    disabled?: boolean;
}) {
    const id = useId();
    const hintId = useId();
    return (
        <div className="flex items-start gap-3">
            <input
                id={id}
                type="checkbox"
                checked={checked}
                disabled={disabled}
                aria-describedby={hint === undefined ? undefined : hintId}
                onChange={(event) => onChange(event.currentTarget.checked)}
                className="mt-0.5 size-4 shrink-0 accent-accent"
            />
            <div className="flex min-w-0 flex-col gap-0.5">
                <label
                    htmlFor={id}
                    className={cn("text-body", disabled ? "text-text-tertiary" : "text-text")}
                >
                    {label}
                </label>
                {hint !== undefined && (
                    <span id={hintId} className="text-label text-text-secondary">
                        {hint}
                    </span>
                )}
            </div>
        </div>
    );
}
