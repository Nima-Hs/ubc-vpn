import { CircleAlert, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

const tones = {
    default: "border-border-strong bg-surface",
    attention: "border-transparent bg-attention-subtle",
    problem: "border-transparent bg-danger-subtle",
} as const;

/** A tinted panel says what kind of message it is with a mark, not by colour alone. */
const marks = {
    attention: <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-attention" />,
    problem: <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-danger" />,
} as const;

/**
 * The surface content sits on. `attention` and `problem` tint it, mark it and
 * pad it, for a message the user should not miss; the message itself must say
 * why.
 *
 * Content taller than the panel scrolls inside it. `scrollLabel` names that
 * region for screen readers, and is needed wherever the content can grow.
 */
export function Panel({
    tone = "default",
    scrollLabel,
    className,
    children,
}: {
    tone?: keyof typeof tones;
    scrollLabel?: string;
    className?: string;
    children: ReactNode;
}) {
    return (
        <div
            className={cn(
                "flex max-h-full flex-col overflow-hidden rounded-xl border shadow-surface",
                tones[tone],
                className,
            )}
        >
            <div
                className="scroll-region"
                {...(scrollLabel !== undefined && { role: "group", "aria-label": scrollLabel })}
            >
                {tone === "default" ? (
                    children
                ) : (
                    <div className="flex gap-3 px-4 py-3">
                        {marks[tone]}
                        <div className="flex min-w-0 flex-1 flex-col gap-1">{children}</div>
                    </div>
                )}
            </div>
        </div>
    );
}
