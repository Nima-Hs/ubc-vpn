import { describe, expect, it } from "vitest";
import { compareVersions, isNewer, parseVersion, type Version } from "../src/main/update/semver";

function version(text: string): Version {
    const parsed = parseVersion(text);
    if (parsed === null) {
        throw new Error(`${text} did not parse`);
    }
    return parsed;
}

describe("reading a version", () => {
    it("reads releases, pre-releases and build metadata", () => {
        expect(version("1.2.3")).toEqual({ major: 1n, minor: 2n, patch: 3n, pre: [] });
        expect(version("0.1.0-rc.1+build.5").pre).toEqual(["rc", 1n]);
        expect(version("99999999999999999999.0.0").major).toBe(99999999999999999999n);
    });

    it("refuses what Semantic Versioning does not allow", () => {
        for (const text of [
            "",
            "1.2",
            "v1.2.3",
            "01.2.3",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-a..b",
            " 1.2.3",
            "1.2.3\n",
            `1.2.3-${"a".repeat(60)}`,
        ]) {
            expect(parseVersion(text), text).toBeNull();
        }
    });
});

describe("ordering versions", () => {
    it("follows the order semver.org gives, pre-releases included", () => {
        const ordered = [
            "0.9.9",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.9.0",
            "1.10.0",
            "1.11.0",
            "2.0.0",
        ];
        for (let at = 0; at < ordered.length; at++) {
            for (let other = 0; other < ordered.length; other++) {
                const a = ordered[at] as string;
                const b = ordered[other] as string;
                expect(Math.sign(compareVersions(version(a), version(b))), `${a} vs ${b}`).toBe(
                    Math.sign(at - other),
                );
            }
        }
    });

    it("ignores build metadata", () => {
        expect(compareVersions(version("1.0.0+a"), version("1.0.0+b"))).toBe(0);
    });
});

describe("whether an update is newer", () => {
    it("is only for a higher version", () => {
        expect(isNewer("0.2.0", "0.1.0")).toBe(true);
        expect(isNewer("0.1.1", "0.1.0")).toBe(true);
        expect(isNewer("0.1.0", "0.1.0-rc.2")).toBe(true);
    });

    it("refuses a downgrade, the same version, and anything that is not a version", () => {
        expect(isNewer("0.1.0", "0.2.0")).toBe(false);
        expect(isNewer("0.1.0", "0.1.0")).toBe(false);
        expect(isNewer("0.1.0+rebuilt", "0.1.0")).toBe(false);
        expect(isNewer("0.1.0-rc.2", "0.1.0")).toBe(false);
        expect(isNewer("0.1.0-rc.1", "0.1.0-rc.2")).toBe(false);
        expect(isNewer("latest", "0.1.0")).toBe(false);
        expect(isNewer("9.9.9", "dev")).toBe(false);
    });
});
