import type { ComponentProps, ReactNode } from "react";
import { cn } from "@/lib/cn";
import { pressable } from "./button";
import { Tooltip } from "./tooltip";

type IconButtonProps = Omit<ComponentProps<"button">, "aria-label" | "children"> & {
    /** Names the action, for the tooltip and for screen readers. Required. */
    label: string;
    /** The icon. It is sized and coloured by the button. */
    children: ReactNode;
    tone?: "neutral" | "danger";
    tooltipSide?: ComponentProps<typeof Tooltip>["side"];
};

/** A square button that shows only an icon, and always says what it does. */
export function IconButton({
    label,
    children,
    tone = "neutral",
    tooltipSide,
    className,
    type = "button",
    ...props
}: IconButtonProps) {
    return (
        <Tooltip label={label} {...(tooltipSide !== undefined && { side: tooltipSide })}>
            <button
                type={type}
                aria-label={label}
                className={cn(
                    pressable,
                    "size-control-sm rounded-sm text-text-secondary [&_svg]:size-4",
                    tone === "danger"
                        ? "hover:bg-danger hover:text-on-danger active:bg-danger-active"
                        : "hover:bg-quiet-hover hover:text-text active:bg-quiet-active",
                    className,
                )}
                {...props}
            >
                {children}
            </button>
        </Tooltip>
    );
}
