import { Minus, X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { api, useSnapshot } from "@/lib/store";
import { IconButton } from "./ui/icon-button";

/** The app's mark: one line in, two lines out. */
function Mark() {
    return (
        <svg
            viewBox="0 0 16 16"
            aria-hidden
            className="size-4 shrink-0"
            fill="none"
            strokeLinecap="round"
        >
            <path d="M2 8 C7 8 7 3.5 14 3.5" className="stroke-accent" strokeWidth={2.5} />
            <path d="M2 8 C7 8 7 12.5 14 12.5" className="stroke-text-tertiary" strokeWidth={1.5} />
        </svg>
    );
}

/**
 * The window's own title bar, drawn by the app so it looks the same on every
 * OS. It drags the window. macOS places its window buttons at the left, so
 * there the bar leaves room for them and shows none of its own.
 */
export function TitleBar({ children }: { children?: ReactNode }) {
    const mac = api.platform === "darwin";
    const closeHides = useSnapshot((snapshot) => snapshot.closeHides);
    return (
        <header
            className={cn(
                "drag-region flex h-11 shrink-0 items-center gap-2 pe-1.5",
                mac ? "ps-20" : "ps-4",
            )}
        >
            <Mark />
            <span className="shrink-0 whitespace-nowrap font-strong text-label text-text">
                UBC VPN
            </span>
            <div className="ms-auto flex items-center gap-1">
                {children}
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
