// Measures the design tokens instead of trusting them: contrast, gamut, and
// the few values that have to be repeated outside `tokens.css`.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { WINDOW_BACKGROUND } from "@shared/api";
import { describe, expect, it } from "vitest";
import { COLOURS } from "../src/main/icon/designs";
import { COLOUR_PALETTE } from "../src/main/tray/icon";
import { duration, easeOut, tooltipDelay, tooltipSpace } from "../src/renderer/src/lib/motion";

const css = readFileSync(join(__dirname, "../src/renderer/src/styles/tokens.css"), "utf8");

/** Every `--name: value;` in the file. The reduced-motion overrides come last and are skipped. */
const tokens = new Map<string, string>();
for (const [, name, value] of css.matchAll(/^\s*(--[\w-]+):\s*([^;]+);/gm)) {
    if (name !== undefined && value !== undefined && !tokens.has(name)) {
        tokens.set(name, value.trim());
    }
}

function resolve(name: string): string {
    let value = tokens.get(name);
    for (let hops = 0; value?.startsWith("var("); hops++) {
        expect(hops, `${name} refers to itself`).toBeLessThan(8);
        value = tokens.get(value.slice(4, -1));
    }
    if (value === undefined) {
        throw new Error(`no token ${name}`);
    }
    return value;
}

type Rgb = [number, number, number];

/** OKLCH to linear sRGB, by Björn Ottosson's published matrices. */
function linearRgb(name: string): Rgb {
    const match = resolve(name).match(/^oklch\(([\d.]+) ([\d.]+) ([\d.]+)\)$/);
    if (match === null) {
        throw new Error(`${name} is not a plain oklch() colour`);
    }
    const [lightness, chroma, hue] = match.slice(1).map(Number) as Rgb;
    const a = chroma * Math.cos((hue * Math.PI) / 180);
    const b = chroma * Math.sin((hue * Math.PI) / 180);
    const l = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3;
    const m = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3;
    const s = (lightness - 0.0894841775 * a - 1.291485548 * b) ** 3;
    return [
        4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
        -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
        -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
    ];
}

function luminance(name: string): number {
    const [r, g, b] = linearRgb(name).map((channel) => Math.min(1, Math.max(0, channel))) as Rgb;
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** The WCAG 2 contrast ratio between two colour tokens. */
function contrast(foreground: string, background: string): number {
    const [dark, light] = [luminance(foreground), luminance(background)].sort((x, y) => x - y) as [
        number,
        number,
    ];
    return (light + 0.05) / (dark + 0.05);
}

function hex(name: string): string {
    const gamma = (channel: number) =>
        channel <= 0.0031308 ? 12.92 * channel : 1.055 * channel ** (1 / 2.4) - 0.055;
    return `#${linearRgb(name)
        .map((channel) =>
            Math.round(gamma(Math.min(1, Math.max(0, channel))) * 255)
                .toString(16)
                .padStart(2, "0"),
        )
        .join("")}`;
}

const SURFACES = ["--c-bg", "--c-surface", "--c-surface-raised"];

/** Text on the background it is drawn on. WCAG AA asks for 4.5:1. */
const TEXT_PAIRS: [string, string][] = [
    ...SURFACES.flatMap((surface): [string, string][] => [
        ["--c-text", surface],
        ["--c-text-secondary", surface],
        ["--c-text-tertiary", surface],
    ]),
    // Buttons, in every state they can be read in.
    ["--c-on-accent", "--c-accent"],
    ["--c-on-accent", "--c-accent-hover"],
    ["--c-on-accent", "--c-accent-active"],
    ["--c-on-danger", "--c-danger"],
    ["--c-on-danger", "--c-danger-hover"],
    ["--c-on-danger", "--c-danger-active"],
    ["--c-text", "--c-control"],
    ["--c-text", "--c-control-hover"],
    ["--c-text", "--c-control-active"],
    ["--c-text", "--c-quiet-hover"],
    ["--c-text", "--c-quiet-active"],
    ["--c-text-secondary", "--c-control"],
    // A disabled or working button. Exempt under WCAG, held to AA anyway.
    ["--c-text-tertiary", "--c-control"],
    // Tooltips, tinted panels, error text, selected text.
    ["--c-text", "--c-overlay"],
    ["--c-text", "--c-attention-subtle"],
    ["--c-text", "--c-danger-subtle"],
    ["--c-text-secondary", "--c-danger-subtle"],
    ["--c-danger", "--c-bg"],
    ["--c-danger", "--c-surface"],
    // A log line's "Warning", on the list's surface.
    ["--c-attention", "--c-surface"],
    ["--c-text", "--c-accent-subtle"],
];

/** Marks and outlines that carry meaning. WCAG AA asks for 3:1. */
const NON_TEXT_PAIRS: [string, string][] = [
    ["--c-focus", "--c-bg"],
    ["--c-focus", "--c-surface"],
    ["--c-focus", "--c-control"],
    ["--c-field-border", "--c-bg"],
    ["--c-field-border", "--c-surface"],
    ["--c-accent", "--c-bg"],
    ["--c-positive", "--c-bg"],
    ["--c-positive", "--c-positive-subtle"],
    ["--c-attention", "--c-bg"],
    ["--c-attention", "--c-attention-subtle"],
    ["--c-danger", "--c-danger-subtle"],
    ["--c-accent", "--c-accent-subtle"],
    ["--c-text-tertiary", "--c-control"],
];

/**
 * Edges that only tidy a shape whose text already identifies it: a secondary
 * button, a panel. WCAG sets no minimum for these; they must still be seen.
 */
const EDGE_PAIRS: [string, string][] = [
    ["--c-border-strong", "--c-bg"],
    ["--c-border-strong", "--c-surface"],
    ["--c-border-strong", "--c-control"],
];

describe("colour contrast", () => {
    it.each(TEXT_PAIRS)("%s on %s reaches 4.5:1", (foreground, background) => {
        expect(contrast(foreground, background)).toBeGreaterThanOrEqual(4.5);
    });

    it.each(NON_TEXT_PAIRS)("%s against %s reaches 3:1", (foreground, background) => {
        expect(contrast(foreground, background)).toBeGreaterThanOrEqual(3);
    });
});

describe("edges", () => {
    it.each(EDGE_PAIRS)("%s against %s can be seen", (edge, background) => {
        expect(contrast(edge, background)).toBeGreaterThanOrEqual(1.5);
    });
});

describe("the colours themselves", () => {
    const colours = [...tokens.keys()].filter((name) => resolve(name).startsWith("oklch("));

    it("has a colour for every role", () => {
        expect(colours.length).toBeGreaterThan(40);
    });

    it("stays inside sRGB, so every screen shows the same colour", () => {
        for (const name of colours.filter((colour) => !resolve(colour).includes("/"))) {
            for (const channel of linearRgb(name)) {
                expect(channel, name).toBeGreaterThanOrEqual(-0.002);
                expect(channel, name).toBeLessThanOrEqual(1.002);
            }
        }
    });

    it("keeps status hues apart from the accent and from each other", () => {
        const hue = (name: string) => Number(resolve(name).match(/([\d.]+)\)$/)?.[1]);
        const hues = ["--c-accent", "--c-positive", "--c-attention", "--c-danger"].map(hue);
        for (const [index, first] of hues.entries()) {
            for (const second of hues.slice(index + 1)) {
                const apart = Math.abs(first - second);
                expect(Math.min(apart, 360 - apart)).toBeGreaterThanOrEqual(15);
            }
        }
    });

    it("defines roles only by pointing at a primitive", () => {
        for (const [name, value] of tokens) {
            if (name.startsWith("--c-")) {
                expect(value, name).toMatch(/^var\(--[a-z]+-\d+\)$/);
            }
        }
    });
});

describe("values repeated outside the token file", () => {
    it("paints the empty window in the background colour", () => {
        expect(WINDOW_BACKGROUND).toBe(hex("--c-bg"));
    });

    it("draws the icons outside the window in the interface's own colours", () => {
        const rgb = (name: string) => {
            const value = hex(name);
            return [1, 3, 5].map((at) => Number.parseInt(value.slice(at, at + 2), 16));
        };
        // Each is named for the token it copies, in `src/main/icon/designs.ts`.
        const names: Record<keyof typeof COLOURS, string> = {
            bg: "--c-bg",
            surface: "--c-surface",
            edge: "--c-border-strong",
            text: "--c-text",
            secondary: "--c-text-secondary",
            tertiary: "--c-text-tertiary",
            accent: "--c-accent",
            positive: "--c-positive",
            attention: "--c-attention",
            danger: "--c-danger",
        };
        for (const [key, token] of Object.entries(names)) {
            expect(COLOURS[key as keyof typeof COLOURS], token).toEqual(rgb(token));
        }
        expect(COLOUR_PALETTE.ink).toEqual(rgb("--c-text-secondary"));
        expect(COLOUR_PALETTE.busy).toEqual(rgb("--c-accent"));
        expect(COLOUR_PALETTE.on).toEqual(rgb("--c-positive"));
        expect(COLOUR_PALETTE.attention).toEqual(rgb("--c-attention"));
        expect(COLOUR_PALETTE.problem).toEqual(rgb("--c-danger"));
        expect(COLOUR_PALETTE.rim).toEqual(rgb("--c-bg"));
    });

    it("gives tooltips the delays and gaps the tokens name", () => {
        expect(tooltipDelay.open).toBe(Number.parseFloat(resolve("--delay-tooltip")));
        expect(tooltipDelay.skip).toBe(Number.parseFloat(resolve("--delay-tooltip-skip")));
        expect(tooltipSpace.gap).toBe(Number.parseFloat(resolve("--tooltip-gap")));
        expect(tooltipSpace.inset).toBe(Number.parseFloat(resolve("--tooltip-inset")));
    });

    it("gives script-driven motion the same timings as CSS", () => {
        const seconds = (name: string) => Number.parseFloat(resolve(name)) / 1000;
        expect(duration.fast).toBe(seconds("--dur-fast"));
        expect(duration.base).toBe(seconds("--dur-base"));
        expect(duration.slow).toBe(seconds("--dur-slow"));
        expect(resolve("--motion-ease-out")).toBe(`cubic-bezier(${easeOut.join(", ")})`);
    });
});
