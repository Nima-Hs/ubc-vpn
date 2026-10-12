import { CircleAlert } from "lucide-react";
import { type ComponentProps, useId } from "react";
import { cn } from "@/lib/cn";

type TextFieldProps = Omit<ComponentProps<"input">, "id" | "aria-invalid" | "aria-describedby"> & {
    /** Always shown: a placeholder is an example, not a label. */
    label: string;
    /** Says what to enter, before the user has to guess. */
    hint?: string;
    /** Says how to fix what was entered. Replaces the hint while present. */
    error?: string;
    /** Keeps the label for screen readers only, for a field in a list that names it. */
    hideLabel?: boolean;
    /** Sets the value in the fixed-width face, for addresses. */
    data?: boolean;
};

/** A labelled single-line input with room for a hint or an error. */
export function TextField({
    label,
    hint,
    error,
    hideLabel = false,
    data = false,
    className,
    ...props
}: TextFieldProps) {
    const id = useId();
    const noteId = `${id}-note`;
    const note = error ?? hint;
    return (
        <div className={cn("flex flex-col gap-1.5", className)}>
            <label
                htmlFor={id}
                className={cn(
                    "wrap-anywhere text-label text-text-secondary",
                    hideLabel && "sr-only",
                )}
            >
                {label}
            </label>
            <input
                id={id}
                // What goes in these fields is not prose, and not for a password manager.
                spellCheck={false}
                autoComplete="off"
                aria-invalid={error !== undefined || undefined}
                aria-describedby={note === undefined ? undefined : noteId}
                className={cn(
                    "no-drag h-control-md cursor-text select-text rounded-md border bg-bg px-3 text-body text-text",
                    "transition-[border-color,background-color] duration-(--dur-fast) ease-out",
                    "placeholder:text-text-tertiary hover:bg-surface",
                    "disabled:cursor-default disabled:border-border disabled:bg-surface disabled:text-text-tertiary",
                    error === undefined ? "border-field-border" : "border-danger",
                    data && "font-data",
                )}
                {...props}
            />
            {note !== undefined && (
                <p
                    id={noteId}
                    className={cn(
                        "flex items-start gap-1.5 text-caption",
                        error === undefined ? "text-text-tertiary" : "text-danger",
                    )}
                >
                    {/* An error is marked as well as coloured. */}
                    {error !== undefined && (
                        <CircleAlert aria-hidden className="mt-0.5 size-3 shrink-0" />
                    )}
                    {note}
                </p>
            )}
        </div>
    );
}
