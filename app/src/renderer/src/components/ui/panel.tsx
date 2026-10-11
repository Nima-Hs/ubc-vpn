import type { ComponentProps } from "react";
import { cn } from "@/lib/cn";

const tones = {
    default: "border-border bg-surface",
    attention: "border-transparent bg-attention-subtle",
    problem: "border-transparent bg-danger-subtle",
} as const;

/**
 * The surface content sits on. `attention` and `problem` tint it for a
 * message the user should not miss; the message itself must say why.
 */
export function Panel({
    tone = "default",
    className,
    ...props
}: ComponentProps<"div"> & { tone?: keyof typeof tones }) {
    return (
        <div
            className={cn("rounded-xl border shadow-surface", tones[tone], className)}
            {...props}
        />
    );
}
