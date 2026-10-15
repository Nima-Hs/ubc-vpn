import type { Tone } from "@shared/copy";
import { useRef } from "react";
import { cn } from "@/lib/cn";
import { duration } from "@/lib/motion";
import { useClockLock, useLinger } from "@/lib/steady-loop";

const dot: Record<Tone, string> = {
    idle: "bg-text-tertiary",
    busy: "bg-accent",
    on: "bg-positive",
    attention: "bg-attention",
    problem: "bg-danger",
};

const halo: Record<Tone, string> = {
    idle: "bg-control",
    // Drawn by the breathing layer above it instead.
    busy: "bg-transparent",
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
    const busy = tone === "busy";
    // Working, the halo breathes. It runs on the page's clock, so a new mark
    // picks up the breath where the last one was, and when the work ends it
    // fades out still breathing instead of snapping to full strength.
    const breathing = useLinger(busy, duration.base * 1000);
    const breath = useRef<HTMLSpanElement>(null);
    useClockLock(breath, breathing);
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
                        "absolute inset-0 transition-opacity duration-(--dur-base) ease-out",
                        busy ? "opacity-100" : "opacity-0",
                    )}
                >
                    <span
                        ref={breath}
                        className={cn(
                            "absolute inset-0 rounded-full bg-accent-subtle",
                            breathing && "motion-safe:animate-breathe",
                        )}
                    />
                </span>
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
