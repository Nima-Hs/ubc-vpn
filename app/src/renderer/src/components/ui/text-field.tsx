import { type ComponentProps, useId } from "react";
import { cn } from "@/lib/cn";

type TextFieldProps = Omit<ComponentProps<"input">, "id" | "aria-invalid" | "aria-describedby"> & {
    /** Always shown: a placeholder is an example, not a label. */
    label: string;
    /** Says what to enter, before the user has to guess. */
    hint?: string;
    /** Says how to fix what was entered. Replaces the hint while present. */
    error?: string;
};

/** A labelled single-line input with room for a hint or an error. */
export function TextField({ label, hint, error, className, ...props }: TextFieldProps) {
    const id = useId();
    const noteId = `${id}-note`;
    const note = error ?? hint;
    return (
        <div className={cn("flex flex-col gap-1.5", className)}>
            <label htmlFor={id} className="text-label text-text-secondary">
                {label}
            </label>
            <input
                id={id}
                aria-invalid={error !== undefined || undefined}
                aria-describedby={note === undefined ? undefined : noteId}
                className={cn(
                    "no-drag h-control-md cursor-text select-text rounded-md border bg-bg px-3 text-body text-text",
                    "transition-[border-color,background-color] duration-(--dur-fast) ease-out",
                    "placeholder:text-text-tertiary hover:bg-surface",
                    "disabled:cursor-default disabled:border-border disabled:bg-surface disabled:text-text-tertiary",
                    error === undefined ? "border-field-border" : "border-danger",
                )}
                {...props}
            />
            {note !== undefined && (
                <p
                    id={noteId}
                    className={cn(
                        "text-caption",
                        error === undefined ? "text-text-tertiary" : "text-danger",
                    )}
                >
                    {note}
                </p>
            )}
        </div>
    );
}
