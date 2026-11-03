import { describe, expect, it } from "vitest";
import { ENDLESS_CAP_BYTES, ENDLESS_CAP_ITEMS, EndlessMeter } from "./endless-fake";

describe("the hard stop on endless fakes", () => {
    it("serves up to its cap and stops there, with nothing more counted", () => {
        const meter = new EndlessMeter(10);
        meter.take(4);
        meter.take(6);
        expect(meter.served).toBe(10);
        expect(() => meter.take(1)).toThrow(/passed its cap of 10/);
        expect(meter.served).toBe(10);
    });

    it("keeps to a size that cannot hurt the machine", () => {
        expect(ENDLESS_CAP_BYTES).toBeLessThanOrEqual(32 * 1024 * 1024);
        expect(ENDLESS_CAP_ITEMS).toBeLessThanOrEqual(4096);
        const meter = new EndlessMeter();
        expect(() => meter.take(ENDLESS_CAP_BYTES + 1)).toThrow(/passed its cap/);
    });
});
