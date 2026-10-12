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
