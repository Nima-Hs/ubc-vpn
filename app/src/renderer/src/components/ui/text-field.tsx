import { CircleAlert, Eye, EyeOff } from "lucide-react";
import { type ComponentProps, useId } from "react";
import { cn } from "@/lib/cn";
import { IconButton } from "./icon-button";

type TextFieldProps = Omit<ComponentProps<"input">, "id" | "aria-invalid" | "aria-describedby"> & {
    /** Always shown: a placeholder is an example, not a label. */
    label: string;
    /** Says what to enter, before the user has to guess. */
    hint?: string | undefined;
    /** Says how to fix what was entered. Replaces the hint while present. */
    error?: string | undefined;
    /** Keeps the label for screen readers only, for a field in a list that names it. */
    hideLabel?: boolean;
    /** Sets the value in the fixed-width face, for addresses. */
    data?: boolean;
    /**
     * A button at the end of the field that shows or hides what is typed,
     * for a password. `label` names what pressing it does ("Show password",
     * "Hide password"), so the name says the state; the caller keeps the state.
     */
    reveal?: { shown: boolean; label: string; onToggle: () => void };
};

/** A labelled single-line input with room for a hint or an error. */
export function TextField({
    label,
    hint,
    error,
    hideLabel = false,
    data = false,
    reveal,
    className,
    ...props
}: TextFieldProps) {
    const id = useId();
    const noteId = `${id}-note`;
    const note = error ?? hint;
    const input = (
        <input
            id={id}
            // What goes in these fields is not prose, and not for a password
            // manager or a list of earlier entries: nothing typed is kept.
            spellCheck={false}
            autoComplete="off"
            aria-invalid={error !== undefined || undefined}
            aria-describedby={note === undefined ? undefined : noteId}
            className={cn(
                "no-drag h-control-md w-full cursor-text select-text rounded-md border bg-bg px-3 text-body text-text",
                "transition-[border-color,background-color] duration-(--dur-fast) ease-out",
                "placeholder:text-text-tertiary hover:bg-surface",
                "disabled:cursor-default disabled:border-border disabled:bg-surface disabled:text-text-tertiary",
                error === undefined ? "border-field-border" : "border-danger",
                data && "font-data",
                reveal !== undefined && "pe-10",
            )}
            {...props}
            {...(reveal !== undefined && { type: reveal.shown ? "text" : "password" })}
        />
    );
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
            {reveal === undefined ? (
                input
            ) : (
                <div className="relative">
                    {input}
                    {/* Pinned to the field's middle: the button sits inside the
                        tooltip's wrapper, so the row's alignment does not reach it. */}
                    <IconButton
                        label={reveal.label}
                        aria-controls={id}
                        onClick={reveal.onToggle}
                        tooltipSide="left"
                        className="absolute inset-y-0 end-1 my-auto"
                    >
                        {reveal.shown ? <EyeOff /> : <Eye />}
                    </IconButton>
                </div>
            )}
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
