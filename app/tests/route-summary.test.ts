import { describeLeftOut } from "@shared/copy";
import { describe, expect, it } from "vitest";
import { summariseSubnets } from "../src/renderer/src/lib/route-summary";

// Made-up networks only: 10.0.0.0/8 is private, and 192.0.2.0/24,
// 198.51.100.0/24 and 203.0.113.0/24 are reserved for documentation.

/** 10.20.0.0/16 without its one address 10.20.255.254, as a route table must hold it: 16 pieces. */
const PIECES = [
    "10.20.0.0/17",
    "10.20.128.0/18",
    "10.20.192.0/19",
    "10.20.224.0/20",
    "10.20.240.0/21",
    "10.20.248.0/22",
    "10.20.252.0/23",
    "10.20.254.0/24",
    "10.20.255.0/25",
    "10.20.255.128/26",
    "10.20.255.192/27",
    "10.20.255.224/28",
    "10.20.255.240/29",
    "10.20.255.248/30",
    "10.20.255.252/31",
    "10.20.255.255/32",
];

describe("the subnets shown on the connection screen", () => {
    it("shows pieces of one range as that range, naming what was left out", () => {
        expect(summariseSubnets(PIECES)).toEqual([
            {
                subnet: "10.20.0.0/16",
                parts: PIECES,
                leftOut: ["10.20.255.254"],
                leftOutCount: 1,
            },
        ]);
    });

    it("keeps the other subnets as they are, in the order they were saved", () => {
        const saved = [
            "198.51.100.0/24",
            ...PIECES.slice(0, 8),
            "10.30.0.0/16",
            ...PIECES.slice(8),
        ];
        const shown = summariseSubnets(saved);
        expect(shown.map((entry) => entry.subnet)).toEqual([
            "198.51.100.0/24",
            "10.20.0.0/16",
            "10.30.0.0/16",
        ]);
        expect(shown[0]).toEqual({
            subnet: "198.51.100.0/24",
            parts: ["198.51.100.0/24"],
            leftOut: [],
            leftOutCount: 0,
        });
        // Every saved subnet is still there, once, behind what is shown.
        expect(shown.flatMap((entry) => entry.parts).sort()).toEqual([...saved].sort());
    });

    it("combines halves that make a whole exactly", () => {
        expect(summariseSubnets(["203.0.113.0/25", "203.0.113.128/25"])).toEqual([
            {
                subnet: "203.0.113.0/24",
                parts: ["203.0.113.0/25", "203.0.113.128/25"],
                leftOut: [],
                leftOutCount: 0,
            },
        ]);
    });

    it("does not combine neighbours that would cover much the user did not choose", () => {
        const saved = ["10.0.1.0/24", "10.0.2.0/24"];
        expect(summariseSubnets(saved).map((entry) => entry.subnet)).toEqual(saved);
        // Two subnets far apart in one /8 stay two.
        expect(summariseSubnets(["10.1.0.0/16", "10.200.0.0/16"])).toHaveLength(2);
    });

    it("names a gap of more than one address as a range", () => {
        // 192.0.2.0/24 without 192.0.2.4/30.
        const shown = summariseSubnets([
            "192.0.2.0/30",
            "192.0.2.8/29",
            "192.0.2.16/28",
            "192.0.2.32/27",
            "192.0.2.64/26",
            "192.0.2.128/25",
        ]);
        expect(shown).toHaveLength(1);
        expect(shown[0]).toMatchObject({
            subnet: "192.0.2.0/24",
            leftOut: ["192.0.2.4–192.0.2.7"],
            leftOutCount: 4,
        });
    });

    it("leaves anything it cannot read exactly as it was", () => {
        const odd = ["10.0.0.5/24", "not a subnet", "10.0.0.0/33", "10.0.0.256/32", ""];
        expect(summariseSubnets(odd).map((entry) => entry.subnet)).toEqual(odd);
    });

    it("never hides a duplicate or an overlap inside a combined range", () => {
        const saved = ["203.0.113.0/25", "203.0.113.0/25", "203.0.113.128/25"];
        expect(summariseSubnets(saved).flatMap((entry) => entry.parts)).toEqual(saved);
        const nested = ["203.0.113.0/24", "203.0.113.0/25"];
        expect(summariseSubnets(nested).map((entry) => entry.subnet)).toEqual(nested);
    });

    it("handles an empty list and the largest one allowed", () => {
        expect(summariseSubnets([])).toEqual([]);
        const many = Array.from({ length: 256 }, (_, i) => `203.0.113.${i}/32`);
        expect(summariseSubnets(many)).toEqual([
            { subnet: "203.0.113.0/24", parts: many, leftOut: [], leftOutCount: 0 },
        ]);
    });
});

describe("what a combined range says it leaves out", () => {
    it("names one address, or counts several", () => {
        expect(describeLeftOut(16, ["10.20.255.254"], 1)).toBe(
            "Saved as 16 subnets, leaving out 10.20.255.254",
        );
        expect(describeLeftOut(6, ["192.0.2.4–192.0.2.7"], 4)).toBe(
            "Saved as 6 subnets, leaving out 4 addresses",
        );
        expect(describeLeftOut(2, [], 0)).toBe("Saved as 2 subnets");
    });
});
