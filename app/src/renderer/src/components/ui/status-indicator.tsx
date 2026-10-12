import type { Tone } from "@shared/copy";
import { cn } from "@/lib/cn";

const dot: Record<Tone, string> = {
    idle: "bg-text-tertiary",
    busy: "bg-accent",
    on: "bg-positive",
    attention: "bg-attention",
    problem: "bg-danger",
};

const halo: Record<Tone, string> = {
    idle: "bg-control",
    busy: "bg-accent-subtle motion-safe:animate-breathe",
    on: "bg-positive-subtle",
    attention: "bg-attention-subtle",
    problem: "bg-danger-subtle",
};

/**
 * A coloured mark for a state. Colour is never the only signal: pass `label`
 * to show the state in words beside it, or place it next to text that does.
 */
export function StatusIndicator({
    tone,
    label,
    size = "sm",
    className,
}: {
    tone: Tone;
    label?: string;
    /** `lg` sits beside a heading. */
    size?: "sm" | "lg";
    className?: string;
}) {
    return (
        <span
            className={cn(
                "inline-flex items-center gap-2 text-label text-text-secondary",
                className,
            )}
        >
            <span
                aria-hidden
                className={cn(
                    "relative grid shrink-0 place-items-center",
                    size === "lg" ? "size-mark-lg" : "size-mark-sm",
                )}
            >
                <span
                    className={cn(
                        "absolute inset-0 rounded-full transition-colors duration-(--dur-base)",
                        halo[tone],
                    )}
                />
                <span
                    className={cn(
                        "relative rounded-full transition-colors duration-(--dur-base)",
                        size === "lg" ? "size-mark-dot-lg" : "size-mark-dot-sm",
                        dot[tone],
                    )}
                />
            </span>
            {label}
        </span>
    );
}
