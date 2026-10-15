// Keeps the app's endless animations (the "working" pulse, the breathing
// status mark, the spinner) continuous. A CSS animation starts from its
// first frame whenever its element appears or its class is added, so each
// change of state or screen made it jump back to the start. Here every one
// of them runs on one clock, the page's: whenever an element appears, its
// animation is already where it would have been had it never stopped.

import { type RefObject, useEffect, useLayoutEffect, useState } from "react";

/** Puts every CSS animation on `element` on the page's clock. Transitions are left alone. */
export function lockToClock(element: Element | null): void {
    if (element === null) {
        return;
    }
    for (const animation of element.getAnimations()) {
        if (animation instanceof CSSAnimation) {
            animation.startTime = 0;
        }
    }
}

/**
 * Locks the element's endless CSS animation to the page's clock each time
 * it starts. Pass whether it is running, so a class added later is caught.
 */
export function useClockLock(ref: RefObject<Element | null>, running = true): void {
    useLayoutEffect(() => {
        if (running) {
            lockToClock(ref.current);
        }
    }, [ref, running]);
}

/**
 * True while `on` is, and for `ms` after it turns false: how long an
 * animation keeps running while its element fades away, so it fades out in
 * motion instead of stopping and then fading.
 */
export function useLinger(on: boolean, ms: number): boolean {
    const [lingering, setLingering] = useState(on);
    useEffect(() => {
        if (on) {
            setLingering(true);
            return;
        }
        const timer = setTimeout(() => setLingering(false), ms);
        return () => clearTimeout(timer);
    }, [on, ms]);
    return on || lingering;
}
