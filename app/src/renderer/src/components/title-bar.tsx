import { describe, type Tone } from "@shared/copy";
import {
    curvePath,
    DIRECT_CURVE,
    DIRECT_WIDTH,
    MARK_BOX,
    TUNNEL_CURVE,
    TUNNEL_WIDTH,
} from "@shared/mark";
import { Minus, Shapes, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { api, useSnapshot } from "@/lib/store";
import { IconButton } from "./ui/icon-button";

/** The tunnel's colour in each state: the tray's colours. */
const tunnel: Record<Tone, string> = {
    idle: "stroke-text-secondary",
    busy: "stroke-accent",
    on: "stroke-positive",
    attention: "stroke-attention",
    problem: "stroke-danger",
};

/**
 * The app's mark: one line in, two lines out. The upper line, the tunnel,
 * takes the colour of the state and moves to a new one smoothly, from
 * wherever it is. The words beside it say the state; the colour only echoes it.
 */
function Mark({ tone }: { tone: Tone }) {
    return (
        <svg
            viewBox={`0 0 ${MARK_BOX} ${MARK_BOX}`}
            aria-hidden
            data-tone={tone}
            className="size-4 shrink-0"
            fill="none"
            strokeLinecap="round"
        >
            <path
                d={curvePath(TUNNEL_CURVE)}
                className={cn("transition-[stroke] duration-(--dur-base) ease-out", tunnel[tone])}
                strokeWidth={TUNNEL_WIDTH}
            />
            <path
                d={curvePath(DIRECT_CURVE)}
                className="stroke-text-tertiary"
                strokeWidth={DIRECT_WIDTH}
            />
        </svg>
    );
}

/**
 * The window's own title bar, drawn by the app so it looks the same on every
 * OS. It drags the window. macOS places its window buttons at the left, so
 * there the bar leaves room for them and shows none of its own.
 */
export function TitleBar({
    onGallery,
}: {
    /** Demo builds only: opens the screen showing every component. */
    onGallery?: () => void;
}) {
    const mac = api.platform === "darwin";
    const closeHides = useSnapshot((snapshot) => snapshot.closeHides);
    const tone = useSnapshot((snapshot) => describe(snapshot.state).tone);
    return (
        <header
            className={cn(
                "drag-region flex h-11 shrink-0 items-center gap-2 pe-1.5",
                mac ? "ps-20" : "ps-4",
            )}
        >
            <Mark tone={tone} />
            <span className="shrink-0 whitespace-nowrap font-strong text-label text-text">
                UBC VPN
            </span>
            <div className="ms-auto flex items-center gap-1">
                {onGallery !== undefined && (
                    <IconButton label="Parts" onClick={onGallery}>
                        <Shapes />
                    </IconButton>
                )}
                {!mac && (
                    <>
                        <IconButton label="Minimize" onClick={() => void api.minimizeWindow()}>
                            <Minus />
                        </IconButton>
                        <IconButton
                            label={closeHides ? "Close to tray" : "Close"}
                            tone="danger"
                            tooltipSide="left"
                            onClick={() => void api.closeWindow()}
                        >
                            <X />
                        </IconButton>
                    </>
                )}
            </div>
        </header>
    );
}
