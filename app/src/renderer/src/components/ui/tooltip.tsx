import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import type { ReactElement, ReactNode } from "react";
import { tooltipDelay, tooltipSpace } from "@/lib/motion";

/** Wrap the app once. After one tooltip has shown, the next appears at once. */
export function TooltipProvider({ children }: { children: ReactNode }) {
    return (
        <TooltipPrimitive.Provider
            delayDuration={tooltipDelay.open}
            skipDelayDuration={tooltipDelay.skip}
        >
            {children}
        </TooltipPrimitive.Provider>
    );
}

/** A short label that appears beside a control on hover or keyboard focus. */
export function Tooltip({
    label,
    side = "bottom",
    repeatsName = false,
    children,
}: {
    label: string;
    side?: "top" | "bottom" | "left" | "right";
    /**
     * Set when the tooltip shows the same words as the control's accessible
     * name, as on an icon button. A tooltip is normally attached to its
     * control as a description; here that would have a screen reader say the
     * name twice, so the description goes on a plain wrapper, where it is
     * not read.
     */
    repeatsName?: boolean;
    /** The control being described. */
    children: ReactElement;
}) {
    return (
        <TooltipPrimitive.Root>
            <TooltipPrimitive.Trigger asChild>
                {repeatsName ? <span className="inline-flex">{children}</span> : children}
            </TooltipPrimitive.Trigger>
            <TooltipPrimitive.Portal>
                <TooltipPrimitive.Content
                    side={side}
                    sideOffset={tooltipSpace.gap}
                    collisionPadding={tooltipSpace.inset}
                    className={[
                        "z-(--layer-overlay) rounded-sm bg-overlay px-2 py-1 text-caption text-text shadow-overlay",
                        // Grows from the control it belongs to, and skips the
                        // animation when it follows another tooltip.
                        "origin-(--radix-tooltip-content-transform-origin)",
                        "transition-[opacity,scale] duration-(--dur-fast) ease-out",
                        "starting:scale-(--motion-pop-scale) starting:opacity-0",
                        "data-[state=instant-open]:transition-none",
                    ].join(" ")}
                >
                    {label}
                </TooltipPrimitive.Content>
            </TooltipPrimitive.Portal>
        </TooltipPrimitive.Root>
    );
}
