// A hard stop for test fakes that never end, such as a download with no last
// byte or a service with no last page. Such a fake exists to show that the
// code under test stops by itself. If a change takes that limit away, the code
// reads for as long as the fake serves, and it may never give a test timeout
// the chance to fire: a loop over promises that are already resolved yields to
// no timer. So the fake itself stops, with an error, long before the machine
// is in any danger, and the test fails instead.

/** Far above anything the code under test reads, and far below harm. */
export const ENDLESS_CAP_BYTES = 32 * 1024 * 1024;
/** The same for a fake that serves items rather than bytes. */
export const ENDLESS_CAP_ITEMS = 4096;

/** Counts what an endless fake has served, and throws once it passes `cap`. */
export class EndlessMeter {
    private count = 0;

    constructor(private readonly cap: number = ENDLESS_CAP_BYTES) {}

    /** How much has been served. */
    get served(): number {
        return this.count;
    }

    /** Call before serving `amount` more. Throws, serving nothing, past the cap. */
    take(amount: number): void {
        if (this.count + amount > this.cap) {
            throw new Error(`an endless fake passed its cap of ${this.cap}: a limit is gone`);
        }
        this.count += amount;
    }
}
