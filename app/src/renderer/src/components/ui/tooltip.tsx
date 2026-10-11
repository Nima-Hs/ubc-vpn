import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import type { ReactElement, ReactNode } from "react";

/** Wrap the app once. After one tooltip has shown, the next appears at once. */
export function TooltipProvider({ children }: { children: ReactNode }) {
    return (
        <TooltipPrimitive.Provider delayDuration={500} skipDelayDuration={300}>
            {children}
        </TooltipPrimitive.Provider>
    );
}

/** A short label that appears beside a control on hover or keyboard focus. */
export function Tooltip({
    label,
    side = "bottom",
    children,
}: {
    label: string;
    side?: "top" | "bottom" | "left" | "right";
    /** The control being described. */
    children: ReactElement;
}) {
    return (
        <TooltipPrimitive.Root>
            <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
            <TooltipPrimitive.Portal>
                <TooltipPrimitive.Content
                    side={side}
                    sideOffset={6}
                    collisionPadding={8}
                    className={[
                        "z-50 rounded-sm bg-overlay px-2 py-1 text-caption text-text shadow-overlay",
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
