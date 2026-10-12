import { cva, type VariantProps } from "class-variance-authority";
import { LoaderCircle } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";
import { cn } from "@/lib/cn";

/** Shared by every pressable control, so they all feel the same under the hand. */
export const pressable = cn(
    "no-drag inline-flex shrink-0 select-none items-center justify-center whitespace-nowrap font-medium",
    // Every control has an edge, even where it is the colour of the control.
    "border border-transparent",
    "transition-[background-color,color,box-shadow,scale] duration-(--dur-fast) ease-out",
    "active:scale-(--motion-press-scale) active:duration-(--dur-press)",
    "aria-disabled:pointer-events-none aria-disabled:scale-100",
);

const button = cva(pressable, {
    variants: {
        variant: {
            primary:
                "bg-accent text-on-accent shadow-accent hover:bg-accent-hover active:bg-accent-active",
            secondary:
                "border-border-strong bg-control text-text shadow-control hover:bg-control-hover active:bg-control-active",
            quiet: "text-text-secondary hover:bg-quiet-hover hover:text-text active:bg-quiet-active",
            destructive:
                "bg-danger text-on-danger shadow-accent hover:bg-danger-hover active:bg-danger-active",
        },
        size: {
            sm: "h-control-sm gap-1.5 rounded-md px-3 text-label",
            md: "h-control-md gap-2 rounded-md px-4 text-body",
            lg: "h-control-lg gap-2.5 rounded-lg px-5 text-title",
        },
        // A button that cannot be used, or is already doing its work, steps
        // back to one muted look whatever its variant.
        inactive: {
            true: "border-border bg-control text-text-tertiary shadow-none",
            false: "",
        },
        block: { true: "w-full", false: "" },
    },
    defaultVariants: { variant: "secondary", size: "md", inactive: false, block: false },
});

type ButtonProps = Omit<ComponentProps<"button">, "disabled"> &
    Pick<VariantProps<typeof button>, "variant" | "size" | "block"> & {
        disabled?: boolean;
        /** The action is under way: shows a spinner and ignores presses. */
        loading?: boolean;
        /** An icon shown before the label. A spinner replaces it while loading. */
        icon?: ReactNode;
    };

/**
 * The app's button. A disabled or loading button stays focusable and is
 * announced as unavailable, so keyboard focus is never lost when a button
 * changes state under it.
 */
export function Button({
    variant,
    size,
    block,
    disabled = false,
    loading = false,
    icon,
    className,
    children,
    onClick,
    type = "button",
    ...props
}: ButtonProps) {
    const inactive = disabled || loading;
    return (
        <button
            type={type}
            aria-disabled={inactive || undefined}
            aria-busy={loading || undefined}
            className={cn(button({ variant, size, block, inactive }), className)}
            onClick={inactive ? undefined : onClick}
            {...props}
        >
            {loading ? (
                <LoaderCircle aria-hidden className="size-4 motion-safe:animate-spin" />
            ) : (
                icon
            )}
            {children}
        </button>
    );
}
