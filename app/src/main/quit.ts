/**
 * Stops what the app started, when it quits. The order matters: the
 * controller goes first, so that nothing it publishes on the way out reaches
 * a tray that is no longer there.
 */
export function stopForQuit(
    controller: { dispose(): void },
    settings: { stop(): void },
    tray: { destroy(): void } | null,
): void {
    controller.dispose();
    settings.stop();
    tray?.destroy();
}

/** How long a quit waits for a login the user gave up to be wound up. */
export const QUIT_WIND_DOWN_MS = 3_000;

/**
 * Makes what handles "the app is about to quit". If a login the user gave up
 * is still being wound up, the quit is put off until that is done, or the
 * limit has passed, and then asked for again; the service is told to
 * disconnect either way. Any other quit goes straight through, a login that
 * was merely under way included: nobody cancelled that one.
 */
export function holdQuitForCancel(
    controller: { windDown(limitMs: number): Promise<void> | null },
    quit: () => void,
    limitMs = QUIT_WIND_DOWN_MS,
): (event: { preventDefault(): void }) => void {
    let waiting = false;
    let released = false;
    return (event) => {
        if (released) {
            return;
        }
        if (waiting) {
            // Asked to quit again while waiting: still not yet.
            event.preventDefault();
            return;
        }
        const woundUp = controller.windDown(limitMs);
        if (woundUp === null) {
            return;
        }
        event.preventDefault();
        waiting = true;
        void woundUp.then(() => {
            released = true;
            quit();
        });
    };
}
