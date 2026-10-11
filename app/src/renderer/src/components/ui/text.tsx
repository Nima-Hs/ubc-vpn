import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

const sizes = {
    body: "text-body",
    label: "text-label",
    caption: "text-caption",
} as const;

const tones = {
    primary: "text-text",
    secondary: "text-text-secondary",
    tertiary: "text-text-tertiary",
    danger: "text-danger",
} as const;

/** The largest text on a screen: what the screen is saying, in a few words. */
export function Heading({ children, className }: { children: ReactNode; className?: string }) {
    return <h1 className={cn("font-strong text-display text-text", className)}>{children}</h1>;
}

/** A heading for a part of a screen. */
export function Subheading({ children, className }: { children: ReactNode; className?: string }) {
    return <h2 className={cn("font-strong text-title text-text", className)}>{children}</h2>;
}

/**
 * Running text. `selectable` is for text the user may want to copy, such as
 * an error message; `data` sets it in the fixed-width face.
 */
export function Text({
    size = "body",
    tone = "primary",
    selectable = false,
    data = false,
    className,
    children,
}: {
    size?: keyof typeof sizes;
    tone?: keyof typeof tones;
    selectable?: boolean;
    data?: boolean;
    className?: string;
    children: ReactNode;
}) {
    return (
        <p
            className={cn(
                "wrap-anywhere text-pretty",
                sizes[size],
                tones[tone],
                selectable && "select-text",
                data && "font-data",
                className,
            )}
        >
            {children}
        </p>
    );
}
