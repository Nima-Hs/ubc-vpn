// Enforces the design system's one rule: a screen is built from shared
// components and tokens, and never styles anything by hand.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { colourPalette, TEMPLATE_PALETTE, type TrayKind, trayIconPng } from "../src/main/tray-icon";

const renderer = join(__dirname, "../src/renderer/src");

function sources(folder: string): { file: string; text: string }[] {
    return readdirSync(join(renderer, folder), { recursive: true, encoding: "utf8" })
        .filter((file) => /\.tsx?$/.test(file))
        .map((file) => ({
            file: `${folder}/${file}`,
            text: readFileSync(join(renderer, folder, file), "utf8"),
        }));
}

/** Every class name written in a file's string literals. */
function classNames(text: string): string[] {
    return [...text.matchAll(/"([^"\n]*)"/g)].flatMap(([, literal = ""]) => literal.split(/\s+/));
}

describe("screens", () => {
    // Layout only: how components are arranged, in steps of the spacing scale.
    const layout =
        /^(flex(-(1|col|row|wrap))?|grid(-cols-\d)?|(min-|max-)?[hw]-(0|full)|shrink-0|items-(start|center|end|baseline)|justify-(start|center|end|between)|(gap|gap-x|gap-y|p|px|py|pt|pb)-\d(\.5)?|scroll-region|overflow-hidden|animate-arrive|sr-only)$/;

    it.each(sources("views"))("$file uses components for everything but layout", ({ text }) => {
        const classes = [...text.matchAll(/className="([^"]*)"/g)].flatMap(([, value = ""]) =>
            value.split(/\s+/),
        );
        expect(classes.length).toBeGreaterThan(0);
        expect(classes.filter((name) => !layout.test(name))).toEqual([]);
        expect(text).not.toMatch(/\bstyle=/);
    });
});

describe("everything the interface draws", () => {
    const files = [
        ...sources("components"),
        ...sources("views"),
        ...sources("demo"),
        ...sources("lib"),
    ];

    it.each(files)("$file writes down no colour or size of its own", ({ text }) => {
        // No colour literals: colours come from tokens.
        expect(text).not.toMatch(/#[0-9a-fA-F]{3,8}\b|\b(rgb|hsl|oklch)a?\(/);
        // No arbitrary values such as `w-[13px]` or `bg-[#123]`. Variants such
        // as `[&_svg]:` and `aria-[current]:` select, and `transition-[...]`
        // lists properties; none of them sets a value.
        const arbitrary = classNames(text).filter(
            (name) => /-\[[^\]]+\]$/.test(name) && !/(^|:)transition-\[/.test(name),
        );
        expect(arbitrary).toEqual([]);
        expect(text).not.toMatch(/\bstyle=\{\{/);
    });
});

describe("the tray icon", () => {
    const kinds: TrayKind[] = ["off", "on", "busy", "attention"];

    function alpha(kind: TrayKind, size: number): number[] {
        const png = trayIconPng(kind, TEMPLATE_PALETTE, size);
        expect(png.subarray(0, 8)).toEqual(
            Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        );
        expect(png.readUInt32BE(16)).toBe(size);
        expect(png.readUInt32BE(20)).toBe(size);
        const length = png.readUInt32BE(33);
        const raw = inflateSync(png.subarray(41, 41 + length));
        const out: number[] = [];
        for (let y = 0; y < size; y++) {
            for (let x = 0; x < size; x++) {
                out.push(raw[y * (size * 4 + 1) + 1 + x * 4 + 3] ?? 0);
            }
        }
        return out;
    }

    it("is a valid image at every size the tray asks for", () => {
        for (const size of [16, 32, 48]) {
            expect(alpha("off", size)).toHaveLength(size * size);
        }
    });

    it("has a different shape for each state, so it reads in one colour", () => {
        const shapes = kinds.map((kind) => alpha(kind, 32).join(","));
        expect(new Set(shapes).size).toBe(kinds.length);
    });

    it("fills the middle only when connected", () => {
        const middle = (kind: TrayKind) => alpha(kind, 32)[16 * 32 + 8];
        expect(middle("on")).toBe(255);
        expect(middle("off")).toBe(0);
    });

    it("uses colour as well where the OS allows it", () => {
        expect(colourPalette(true).on).not.toEqual(colourPalette(true).ink);
        expect(colourPalette(true).ink).not.toEqual(colourPalette(false).ink);
    });
});
