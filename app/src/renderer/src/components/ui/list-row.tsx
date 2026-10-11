import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/** A list of labelled values. Put {@link ListRow}s inside. */
export function List({ children, className }: { children: ReactNode; className?: string }) {
    return <dl className={cn("divide-y divide-border", className)}>{children}</dl>;
}

/**
 * One labelled value. A short value sits on the label's line; `stacked`
 * puts a long or multi-part value underneath. `data` sets the value in the
 * fixed-width face, for addresses and other things read character by character.
 */
export function ListRow({
    label,
    children,
    stacked = false,
    data = false,
}: {
    label: string;
    children: ReactNode;
    stacked?: boolean;
    data?: boolean;
}) {
    return (
        <div
            className={cn(
                "px-4 py-3",
                stacked ? "flex flex-col gap-1.5" : "flex items-baseline justify-between gap-4",
            )}
        >
            <dt className="shrink-0 text-label text-text-secondary">{label}</dt>
            <dd
                className={cn(
                    "min-w-0 select-text wrap-anywhere text-text",
                    data ? "font-data text-label" : "text-body",
                    !stacked && "text-right",
                )}
            >
                {children}
            </dd>
        </div>
    );
}
