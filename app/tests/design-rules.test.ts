// Enforces the design system's one rule: a screen is built from shared
// components and tokens, and never styles anything by hand.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { appIcon, COLOURS } from "../src/main/icon/designs";
import { draw } from "../src/main/icon/raster";
import {
    BUSY_FRAME_MS,
    BUSY_FRAMES,
    COLOUR_PALETTE,
    closeHidesWindow,
    connectFromTray,
    createStateIcons,
    drawTrayIcon,
    drawWindowIcon,
    STATE_PICTURES,
    stateIconFile,
    TEMPLATE_PALETTE,
    TRAY_KINDS,
    type TrayKind,
    trayIconPng,
    WINDOW_ICON_SIZES,
} from "../src/main/tray-icon";

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
        /^(flex(-(1|col|row|wrap))?|grid(-cols-\d)?|(min-|max-)?[hw]-(0|full|\d+)|shrink(-0)?|items-(start|center|end|baseline)|justify-(start|center|end|between)|(gap|gap-x|gap-y|p|px|py|pt|pb)-\d(\.5)?|scroll-region|row-lazy|ring-room|overflow-hidden|animate-arrive|sr-only)$/;

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

/** WCAG relative luminance of an sRGB colour. */
function luminance([r, g, b]: readonly number[]): number {
    const linear = (channel = 0) => {
        const c = channel / 255;
        return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
}
const contrast = (a: readonly number[], b: readonly number[]) => {
    const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return ((light ?? 0) + 0.05) / ((dark ?? 0) + 0.05);
};
/** Windows 11's taskbar, dark and light, and a light macOS menu bar. */
const DARK_BAR = [32, 32, 32];
const LIGHT_BAR = [243, 243, 243];

/** The colours a drawing uses where it is solid. */
function solidColours(pixels: Buffer): Set<string> {
    const found = new Set<string>();
    for (let at = 0; at < pixels.length; at += 4) {
        if (pixels[at + 3] === 255) {
            found.add([pixels[at], pixels[at + 1], pixels[at + 2]].join(","));
        }
    }
    return found;
}

describe("the tray icon", () => {
    const kinds = TRAY_KINDS;
    const stateColour: Record<Exclude<TrayKind, "off">, readonly number[]> = {
        busy: COLOUR_PALETTE.busy,
        on: COLOUR_PALETTE.on,
        "busy-full": COLOUR_PALETTE.busy,
        "on-full": COLOUR_PALETTE.on,
        attention: COLOUR_PALETTE.attention,
        problem: COLOUR_PALETTE.problem,
    };

    function alpha(kind: TrayKind, size: number, frame = 0): number[] {
        const png = trayIconPng(kind, TEMPLATE_PALETTE, size, frame);
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
        expect([...kinds]).toEqual([
            "off",
            "busy",
            "on",
            "busy-full",
            "on-full",
            "attention",
            "problem",
        ]);
        for (const size of [16, 32]) {
            const shapes = kinds.map((kind) => alpha(kind, size).join(","));
            expect(new Set(shapes).size).toBe(kinds.length);
        }
    });

    it("draws the tunnel wide only while it is open or opening", () => {
        // How much of the upper part, where the tunnel runs, is covered.
        const tunnel = (kind: TrayKind) =>
            alpha(kind, 32)
                .slice(0, 12 * 32)
                .reduce((sum, value) => sum + value, 0);
        expect(tunnel("on")).toBeGreaterThan(tunnel("off") * 1.4);
        expect(tunnel("busy")).toBeGreaterThan(tunnel("off"));
        expect(tunnel("attention")).toBe(tunnel("off"));
    });

    it("shows full tunnel by a short lower line, and a line on from the tunnel's end", () => {
        // Down the right-hand edge, between the two lines' ends: only full
        // tunnel draws there, the line on to everything else.
        const onward = (kind: TrayKind) => alpha(kind, 32)[16 * 32 + 28] ?? 0;
        expect(onward("on-full")).toBe(255);
        expect(onward("busy-full")).toBe(255);
        expect(onward("on")).toBe(0);
        expect(onward("busy")).toBe(0);
        // Where the lower line ends in split tunnel, and no longer reaches in full.
        const lowerEnd = (kind: TrayKind) => alpha(kind, 32)[25 * 32 + 22] ?? 0;
        expect(lowerEnd("on")).toBe(255);
        expect(lowerEnd("on-full")).toBe(0);
        // The tunnel is as wide in either mode.
        const tunnel = (kind: TrayKind) =>
            alpha(kind, 32)
                .slice(0, 10 * 32)
                .reduce((sum, value) => sum + value, 0);
        expect(tunnel("on-full")).toBeGreaterThanOrEqual(tunnel("on"));
    });

    it("moves while working in full tunnel too, in as many pictures", () => {
        const frames = Array.from({ length: BUSY_FRAMES }, (_, frame) =>
            alpha("busy-full", 16, frame).join(","),
        );
        expect(new Set(frames).size).toBe(BUSY_FRAMES);
    });

    it("marks needing attention with a triangle and a problem with a diamond", () => {
        // The badge sits over the lower right; nothing else reaches its middle.
        const badge = (kind: TrayKind) => alpha(kind, 32)[19 * 32 + 24];
        expect(badge("attention")).toBe(255);
        expect(badge("problem")).toBe(255);
        expect(badge("off")).toBe(0);
        // A diamond reaches its right-hand corner at mid-height, a triangle does not.
        const corner = (kind: TrayKind) => alpha(kind, 32)[24 * 32 + 29] ?? 0;
        expect(corner("problem")).toBeGreaterThan(200);
        expect(corner("attention")).toBeLessThan(255);
        expect(alpha("attention", 32).join()).not.toBe(alpha("problem", 32).join());
    });

    it("moves while working, in a few pictures that come round again", () => {
        const frames = Array.from({ length: BUSY_FRAMES }, (_, frame) =>
            alpha("busy", 16, frame).join(","),
        );
        expect(BUSY_FRAMES).toBeLessThanOrEqual(4);
        expect(new Set(frames).size).toBe(BUSY_FRAMES);
        expect(alpha("busy", 16, BUSY_FRAMES).join(",")).toBe(frames[0]);
    });

    it("gives each state its own colour, from the tokens, and draws it", () => {
        const colours = Object.values(stateColour).map((colour) => colour.join(","));
        expect(new Set([...colours, COLOUR_PALETTE.ink.join(",")]).size).toBe(5);
        for (const [kind, colour] of Object.entries(stateColour)) {
            const used = solidColours(drawTrayIcon(kind as TrayKind, COLOUR_PALETTE, 32));
            expect(used.has(colour.join(",")), `${kind} is drawn in its colour`).toBe(true);
        }
        // Off is drawn in the neutral colour alone.
        const off = solidColours(drawTrayIcon("off", COLOUR_PALETTE, 32));
        expect([...off]).toEqual([COLOUR_PALETTE.ink.join(",")]);
    });

    it("shows on a dark taskbar by its colours, and on a light one by its rim", () => {
        for (const colour of [COLOUR_PALETTE.ink, ...Object.values(stateColour)]) {
            // WCAG asks 3:1 of a graphic that carries meaning.
            expect(contrast(colour, DARK_BAR)).toBeGreaterThanOrEqual(3);
            expect(contrast(colour, COLOUR_PALETTE.rim ?? [0, 0, 0])).toBeGreaterThanOrEqual(3);
        }
        expect(contrast(COLOUR_PALETTE.rim ?? [255, 255, 255], LIGHT_BAR)).toBeGreaterThanOrEqual(
            3,
        );
    });

    it("carries its own contrast, since it cannot know the taskbar's colour", () => {
        // Light shapes for a dark bar, rimmed in dark for a light one.
        const pixels = drawTrayIcon("off", COLOUR_PALETTE, 32);
        const opaque: number[] = [];
        for (let at = 0; at < pixels.length; at += 4) {
            if ((pixels[at + 3] ?? 0) > 180) {
                opaque.push(pixels[at] ?? 0);
            }
        }
        expect(Math.max(...opaque)).toBe(COLOUR_PALETTE.ink[0]);
        expect(Math.min(...opaque)).toBeLessThan(60);
        // macOS tints the icon itself, so there it has one colour and no rim.
        expect(TEMPLATE_PALETTE.rim).toBeNull();
    });

    it("uses colour as well as shape where the OS allows it", () => {
        expect(COLOUR_PALETTE.on).not.toEqual(COLOUR_PALETTE.ink);
        expect(COLOUR_PALETTE.attention).not.toEqual(COLOUR_PALETTE.ink);
    });
});

describe("the state icon, shared by the tray and the taskbar button", () => {
    /** Timers the test steps by hand. */
    function fakeTimers() {
        const running = new Set<number>();
        let next = 0;
        let step: (() => void) | undefined;
        return {
            timers: {
                set: (callback: () => void, ms: number) => {
                    expect(ms).toBe(BUSY_FRAME_MS);
                    step = callback;
                    running.add(++next);
                    return next;
                },
                clear: (timer: unknown) => {
                    running.delete(timer as number);
                },
            },
            tick: () => step?.(),
            running: () => running.size,
        };
    }

    it("is the tray's own drawing on the taskbar, for every state and frame", () => {
        // Every size, 256 included, is compared with the files Windows reads
        // in tests/icons.test.ts; here, the sizes of the taskbar button.
        for (const { kind, frame } of STATE_PICTURES) {
            for (const size of [32, 40, 48, 64]) {
                expect(drawWindowIcon(kind, size, frame)).toEqual(
                    drawTrayIcon(kind, COLOUR_PALETTE, size, frame),
                );
            }
        }
        // Two working kinds, split and full, with all their frames.
        expect(STATE_PICTURES).toHaveLength(TRAY_KINDS.length - 2 + 2 * BUSY_FRAMES);
    });

    it("paints every place with the same state and the same working frame", () => {
        const clock = fakeTimers();
        const icons = createStateIcons(clock.timers);
        const tray: string[] = [];
        const taskbar: string[] = [];
        icons.add((kind, frame) => tray.push(`${kind}-${frame}`));
        icons.show("busy");
        icons.add((kind, frame) => taskbar.push(`${kind}-${frame}`));
        clock.tick();
        clock.tick();
        clock.tick();
        expect(tray).toEqual(["busy-0", "busy-1", "busy-2", "busy-0"]);
        expect(taskbar).toEqual(["busy-0", "busy-1", "busy-2", "busy-0"]);
        // One timer for both.
        expect(clock.running()).toBe(1);
    });

    it("steps only while working, and stops when the state settles", () => {
        const clock = fakeTimers();
        const icons = createStateIcons(clock.timers);
        const painted: string[] = [];
        icons.add((kind, frame) => painted.push(`${kind}-${frame}`));
        icons.show("off");
        expect(icons.stepping).toBe(false);
        icons.show("busy");
        expect(icons.stepping).toBe(true);
        clock.tick();
        icons.show("on");
        expect(icons.stepping).toBe(false);
        expect(clock.running()).toBe(0);
        expect(painted).toEqual(["off-0", "busy-0", "busy-1", "on-0"]);
        // Working again starts from the first frame.
        icons.show("busy");
        expect(painted.at(-1)).toBe("busy-0");
        // The same state again changes nothing.
        icons.show("busy");
        expect(clock.running()).toBe(1);
    });

    it("stops when nothing is left to paint, the window closed and no tray", () => {
        const clock = fakeTimers();
        const icons = createStateIcons(clock.timers);
        icons.show("busy");
        // Nothing to paint yet: no timer.
        expect(icons.stepping).toBe(false);
        const letGo = icons.add(() => {});
        expect(icons.stepping).toBe(true);
        letGo();
        expect(icons.stepping).toBe(false);
        expect(clock.running()).toBe(0);
    });

    it("stops for good when the app quits", () => {
        const clock = fakeTimers();
        const icons = createStateIcons(clock.timers);
        const painted: string[] = [];
        icons.add((kind) => painted.push(kind));
        icons.show("busy");
        icons.dispose();
        expect(clock.running()).toBe(0);
        icons.show("on");
        icons.add(() => painted.push("late"));
        expect(painted).toEqual(["busy"]);
        expect(icons.stepping).toBe(false);
    });

    it("names one file per state and per working frame", () => {
        const names = STATE_PICTURES.map(({ kind, frame }) => stateIconFile(kind, frame));
        expect(names).toEqual([
            "off.ico",
            "busy-0.ico",
            "busy-1.ico",
            "busy-2.ico",
            "on.ico",
            "busy-full-0.ico",
            "busy-full-1.ico",
            "busy-full-2.ico",
            "on-full.ico",
            "attention.ico",
            "problem.ico",
        ]);
        expect([...WINDOW_ICON_SIZES]).toEqual([16, 20, 24, 32, 40, 48, 64, 256]);
    });
});

describe("the app icon", () => {
    it("is the mark on the app's surface, edged so it shows on any taskbar", () => {
        for (const size of [16, 32, 256]) {
            const used = solidColours(draw(appIcon(size), size));
            expect(used.has(COLOURS.surface.join(",")), `${size}: surface`).toBe(true);
            expect(used.has(COLOURS.accent.join(",")), `${size}: tunnel`).toBe(true);
            expect(used.has(COLOURS.edge.join(",")), `${size}: edge`).toBe(true);
        }
        expect(contrast(COLOURS.edge, DARK_BAR)).toBeGreaterThan(1.5);
        expect(contrast(COLOURS.surface, LIGHT_BAR)).toBeGreaterThanOrEqual(3);
        expect(contrast(COLOURS.accent, COLOURS.surface)).toBeGreaterThanOrEqual(3);
        expect(contrast(COLOURS.tertiary, COLOURS.surface)).toBeGreaterThanOrEqual(3);
    });
});

describe("Connect, from the tray menu", () => {
    it("shows the window before a login can ask anything", () => {
        const order: string[] = [];
        connectFromTray(
            () => order.push("window shown"),
            () => order.push("login started"),
        );
        expect(order).toEqual(["window shown", "login started"]);
    });
});

describe("closing the window", () => {
    it("hides it to the tray where there is a way back", () => {
        expect(closeHidesWindow("win32", {}, true)).toBe(true);
        expect(closeHidesWindow("linux", { XDG_CURRENT_DESKTOP: "KDE" }, true)).toBe(true);
        expect(closeHidesWindow("linux", { XDG_CURRENT_DESKTOP: "ubuntu:GNOME" }, true)).toBe(true);
        // The Dock is always there.
        expect(closeHidesWindow("darwin", {}, false)).toBe(true);
    });

    it("quits where a hidden window could not be brought back", () => {
        expect(closeHidesWindow("win32", {}, false)).toBe(false);
        expect(closeHidesWindow("linux", {}, false)).toBe(false);
        // GNOME shows no tray without an extension, and gives no error either.
        expect(closeHidesWindow("linux", { XDG_CURRENT_DESKTOP: "GNOME" }, true)).toBe(false);
        expect(
            closeHidesWindow("linux", { XDG_CURRENT_DESKTOP: "GNOME-Classic:GNOME" }, true),
        ).toBe(false);
    });
});
