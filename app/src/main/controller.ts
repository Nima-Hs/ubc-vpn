import type { ActionResult, Snapshot } from "@shared/api";
import type { ServiceLink } from "./link";

/**
 * The one place actions are taken, whether the user asked in the window or
 * from the tray, so both see the same state and the same explanation when an
 * action does not start.
 */
export class Controller {
    private snapshot: Snapshot;
    private readonly listeners = new Set<(snapshot: Snapshot) => void>();
    private readonly unsubscribe: () => void;
    private closeHides = false;

    constructor(private readonly link: ServiceLink) {
        this.snapshot = { state: link.getState(), notice: null, closeHides: false };
        // A change of state makes any earlier notice out of date.
        this.unsubscribe = link.subscribe((state) => this.publish({ state, notice: null }));
    }

    getSnapshot(): Snapshot {
        return this.snapshot;
    }

    subscribe(listener: (snapshot: Snapshot) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    connect(): Promise<void> {
        return this.run(() => this.link.connect());
    }

    disconnect(): Promise<void> {
        return this.run(() => this.link.disconnect());
    }

    /** Says whether closing the window hides it or quits the app. */
    setCloseHides(closeHides: boolean): void {
        this.closeHides = closeHides;
        this.publish(this.snapshot);
    }

    retry(): void {
        this.link.retry();
    }

    dispose(): void {
        this.unsubscribe();
        this.link.dispose();
    }

    private async run(action: () => Promise<ActionResult>): Promise<void> {
        const result = await action();
        if (!result.ok) {
            this.publish({ state: this.link.getState(), notice: result.error });
        }
    }

    private publish(next: Pick<Snapshot, "state" | "notice">): void {
        const snapshot = { state: next.state, notice: next.notice, closeHides: this.closeHides };
        this.snapshot = snapshot;
        for (const listener of this.listeners) {
            listener(snapshot);
        }
    }
}
