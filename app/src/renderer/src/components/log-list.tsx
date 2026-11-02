import { LOGS } from "@shared/copy";
import type { ShownLine } from "@shared/logs";
import { ArrowDown, CircleAlert, TriangleAlert } from "lucide-react";
import { type KeyboardEvent, useEffect, useLayoutEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import { Button } from "./ui/button";

const clock = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
});

/** A level is said in a word and marked with a shape, as well as coloured. */
function Level({ level }: { level: ShownLine["level"] }) {
    if (level === "info") {
        return null;
    }
    const Mark = level === "error" ? CircleAlert : TriangleAlert;
    return (
        <span
            className={cn(
                "flex items-center gap-1 font-strong",
                level === "error" ? "text-danger" : "text-attention",
            )}
        >
            <Mark aria-hidden className="size-3 shrink-0" />
            {LOGS.level[level]}
        </span>
    );
}

/** How close to the end still counts as being at the end. */
const NEAR_END = 24;

/** Keys that start a scroll towards the oldest lines. */
const UP_KEYS = new Set(["ArrowUp", "PageUp"]);

/**
 * The log's lines, oldest first, in a box that scrolls. It keeps to the end
 * as lines arrive, unless the reader has scrolled up to read something; then
 * it stays where it is and offers a way back to the newest.
 *
 * The reader leaves the end as soon as they start to scroll up, not once
 * the scroll has gone some way: a scroll by key or wheel is animated, and a
 * line that arrived meanwhile would otherwise pull the box back to the end.
 * On macOS that pull moves where the animation stops, so Home did not
 * reach the top.
 *
 * Each line's text is put on the page as text. Nothing in a line is ever
 * treated as markup or as a link.
 */
export function LogList({ lines, className }: { lines: readonly ShownLine[]; className?: string }) {
    const box = useRef<HTMLDivElement>(null);
    const atEnd = useRef(true);
    /** Where the box was scrolled to when last seen, to tell which way it moves. */
    const lastTop = useRef(0);
    const [behind, setBehind] = useState(false);
    const newest = lines.at(-1)?.seq;

    const toEnd = () => {
        const element = box.current;
        if (element !== null) {
            element.scrollTop = element.scrollHeight;
            lastTop.current = element.scrollTop;
        }
        atEnd.current = true;
        setBehind(false);
    };

    /** The reader has started up the log, if there is anywhere up to go. */
    const leaveEnd = (element: HTMLElement) => {
        if (element.scrollTop > 0) {
            atEnd.current = false;
        }
    };

    const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
        const element = event.currentTarget;
        // Home and End go all the way at once, on every system, rather than
        // in an animation the arriving lines could interrupt. Command with
        // an arrow is how a Mac keyboard without those keys says the same.
        const toTop = event.key === "Home" || (event.metaKey && event.key === "ArrowUp");
        const toBottom = event.key === "End" || (event.metaKey && event.key === "ArrowDown");
        if (toTop) {
            event.preventDefault();
            leaveEnd(element);
            element.scrollTop = 0;
        } else if (toBottom) {
            event.preventDefault();
            toEnd();
        } else if (UP_KEYS.has(event.key) || (event.key === " " && event.shiftKey)) {
            leaveEnd(element);
        }
    };

    // Before the screen is drawn, so a new line never shows half out of view.
    useLayoutEffect(() => {
        if (atEnd.current) {
            toEnd();
        } else if (newest !== undefined) {
            setBehind(true);
        }
    }, [newest]);

    useEffect(() => {
        const element = box.current;
        if (element === null) {
            return;
        }
        const onScroll = () => {
            const top = element.scrollTop;
            const gap = element.scrollHeight - top - element.clientHeight;
            const goingUp = top < lastTop.current;
            lastTop.current = top;
            // Near the end counts as at the end, unless the reader is on
            // the way up. At the very end it always does: a taller window
            // also moves the box up, and nothing is hidden below.
            atEnd.current = gap < 1 || (gap <= NEAR_END && !goingUp);
            if (atEnd.current) {
                setBehind(false);
            }
        };
        const onWheel = (event: WheelEvent) => {
            if (event.deltaY < 0) {
                leaveEnd(element);
            }
        };
        element.addEventListener("scroll", onScroll, { passive: true });
        element.addEventListener("wheel", onWheel, { passive: true });
        return () => {
            element.removeEventListener("scroll", onScroll);
            element.removeEventListener("wheel", onWheel);
        };
    }, []);

    return (
        <div
            className={cn(
                "relative flex min-h-0 flex-col overflow-hidden rounded-xl border border-border-strong bg-surface shadow-surface",
                className,
            )}
        >
            <div
                ref={box}
                // Read when asked for, not announced line by line as they arrive.
                role="log"
                aria-live="off"
                aria-label={LOGS.listLabel}
                // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrolling region must be reachable by keyboard.
                tabIndex={0}
                onKeyDown={onKeyDown}
                className="scroll-region min-h-0 flex-1"
            >
                <ol className="flex flex-col">
                    {lines.map((line) => (
                        <li
                            key={line.seq}
                            className="flex flex-col gap-0.5 border-border border-b px-4 py-2 last:border-b-0"
                        >
                            {/* Lines written just before this one have gone. */}
                            {line.gap === true && (
                                <p className="pb-1 text-caption text-text-tertiary">{LOGS.gap}</p>
                            )}
                            <div className="flex flex-wrap items-center gap-x-2 text-caption text-text-tertiary">
                                <time dateTime={new Date(line.at_unix_ms).toISOString()}>
                                    {clock.format(line.at_unix_ms)}
                                </time>
                                <span>{LOGS.source[line.source]}</span>
                                <Level level={line.level} />
                            </div>
                            <p className="wrap-anywhere select-text font-data text-label text-text">
                                {line.text}
                            </p>
                        </li>
                    ))}
                </ol>
            </div>
            {/* Said once, when the reader has fallen behind: there is more below. */}
            <p aria-live="polite" className="sr-only">
                {behind ? LOGS.newBelow : ""}
            </p>
            {behind && (
                <div className="absolute inset-x-0 bottom-2 flex justify-center">
                    <Button size="sm" icon={<ArrowDown aria-hidden />} onClick={toEnd}>
                        {LOGS.toNewest}
                    </Button>
                </div>
            )}
        </div>
    );
}
