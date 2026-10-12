// Draws the tray icon. It is drawn in code, not shipped as image files, so
// every state and size comes from one description and nothing can go stale.
// This file has no Electron import, so it can be tested on its own.

import { crc32, deflateSync } from "node:zlib";
import type { LinkState } from "@shared/api";
import { describe } from "@shared/copy";

/**
 * The four things the tray can say. Each has its own shape as well as its
 * own colour, because macOS draws tray icons in one colour.
 */
export type TrayKind = "off" | "on" | "busy" | "attention";

export function trayKind(state: LinkState): TrayKind {
    switch (describe(state).tone) {
        case "idle":
            return "off";
        case "on":
            return "on";
        case "busy":
            return "busy";
        case "attention":
        case "problem":
            return "attention";
    }
}

/**
 * Whether closing the window should hide it and leave the app in the tray.
 * That is only safe where there is a way back to a hidden window.
 *
 * macOS always has the Dock. Windows always has a tray. On Linux, GNOME has
 * none unless an extension adds one (Ubuntu ships that extension; Debian and
 * Fedora do not), and Electron cannot tell: it creates the icon without
 * error either way. So GNOME without Ubuntu's extension is assumed to have
 * no tray, and there closing the window quits the app.
 */
export function closeHidesWindow(
    platform: NodeJS.Platform,
    env: Record<string, string | undefined>,
    trayCreated: boolean,
): boolean {
    if (platform === "darwin") {
        return true;
    }
    if (!trayCreated) {
        return false;
    }
    if (platform === "linux") {
        const desktop = (env.XDG_CURRENT_DESKTOP ?? "").toLowerCase();
        return !desktop.includes("gnome") || desktop.includes("ubuntu");
    }
    return true;
}

type Rgb = readonly [number, number, number];

export interface TrayPalette {
    /** The outline of the mark. */
    ink: Rgb;
    on: Rgb;
    attention: Rgb;
    /**
     * A thin dark rim around every shape, or `null` for none. The icon cannot
     * know the colour of the taskbar it sits on (the OS can theme that apart
     * from apps), so it carries its own contrast: light shapes that show on a
     * dark bar, rimmed so they also show on a light one.
     */
    rim: Rgb | null;
}

/** One colour and no rim, for macOS, which tints template images itself. */
export const TEMPLATE_PALETTE: TrayPalette = {
    ink: [0, 0, 0],
    on: [0, 0, 0],
    attention: [0, 0, 0],
    rim: null,
};

/**
 * For Windows and Linux. These are the design tokens `--c-text`,
 * `--c-positive`, `--c-attention` and `--c-bg`; a test fails if they drift.
 */
export const COLOUR_PALETTE: TrayPalette = {
    ink: [238, 240, 244],
    on: [89, 225, 162],
    attention: [245, 194, 95],
    rim: [11, 14, 20],
};

/** Samples per pixel along each axis, for smooth edges. */
const SAMPLES = 4;
/** How far the rim reaches beyond a shape, and how solid it is. */
const RIM_WIDTH = 0.07;
const RIM_ALPHA = 0.8;

/**
 * Which colour covers a point, in units where the icon is 1 wide, with every
 * shape grown by `grow`. Off is a ring, on is a filled disc, busy is a ring
 * around a dot, and attention is a ring with a solid badge at the lower right.
 */
function shapeAt(
    kind: TrayKind,
    x: number,
    y: number,
    grow: number,
): "ink" | "on" | "attention" | null {
    const fromCentre = Math.hypot(x - 0.5, y - 0.5);
    if (kind === "on") {
        return fromCentre <= 0.4 + grow ? "on" : null;
    }
    if (kind === "attention") {
        const fromBadge = Math.hypot(x - 0.74, y - 0.74);
        if (fromBadge <= 0.19 + grow) {
            return "attention";
        }
        // A clear gap keeps the badge apart from the ring in one colour.
        if (fromBadge <= 0.29) {
            return null;
        }
    }
    if (fromCentre <= 0.4 + grow && fromCentre >= 0.28 - grow) {
        return "ink";
    }
    if (kind === "busy" && fromCentre <= 0.13 + grow) {
        return "ink";
    }
    return null;
}

/** The icon as RGBA pixels, `size` wide and high. */
export function drawTrayIcon(kind: TrayKind, palette: TrayPalette, size: number): Buffer {
    const pixels = Buffer.alloc(size * size * 4);
    for (let py = 0; py < size; py++) {
        for (let px = 0; px < size; px++) {
            let red = 0;
            let green = 0;
            let blue = 0;
            let alpha = 0;
            for (let sy = 0; sy < SAMPLES; sy++) {
                for (let sx = 0; sx < SAMPLES; sx++) {
                    const x = (px + (sx + 0.5) / SAMPLES) / size;
                    const y = (py + (sy + 0.5) / SAMPLES) / size;
                    const shape = shapeAt(kind, x, y, 0);
                    let colour: Rgb;
                    let weight: number;
                    if (shape !== null) {
                        colour = palette[shape];
                        weight = 1;
                    } else if (palette.rim !== null && shapeAt(kind, x, y, RIM_WIDTH) !== null) {
                        colour = palette.rim;
                        weight = RIM_ALPHA;
                    } else {
                        continue;
                    }
                    red += colour[0] * weight;
                    green += colour[1] * weight;
                    blue += colour[2] * weight;
                    alpha += weight;
                }
            }
            if (alpha === 0) {
                continue;
            }
            const at = (py * size + px) * 4;
            pixels[at] = Math.round(red / alpha);
            pixels[at + 1] = Math.round(green / alpha);
            pixels[at + 2] = Math.round(blue / alpha);
            pixels[at + 3] = Math.round((alpha / (SAMPLES * SAMPLES)) * 255);
        }
    }
    return pixels;
}

function chunk(type: string, data: Buffer): Buffer {
    const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const frame = Buffer.alloc(8);
    frame.writeUInt32BE(data.length, 0);
    frame.writeUInt32BE(crc32(body), 4);
    return Buffer.concat([frame.subarray(0, 4), body, frame.subarray(4)]);
}

/** Wraps RGBA pixels as a PNG file. */
export function encodePng(pixels: Buffer, size: number): Buffer {
    const header = Buffer.alloc(13);
    header.writeUInt32BE(size, 0);
    header.writeUInt32BE(size, 4);
    header[8] = 8; // bits per channel
    header[9] = 6; // RGBA
    const row = size * 4;
    const raw = Buffer.alloc((row + 1) * size);
    for (let y = 0; y < size; y++) {
        // Each row starts with a zero: "no filter".
        pixels.copy(raw, y * (row + 1) + 1, y * row, (y + 1) * row);
    }
    return Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        chunk("IHDR", header),
        chunk("IDAT", deflateSync(raw)),
        chunk("IEND", Buffer.alloc(0)),
    ]);
}

export function trayIconPng(kind: TrayKind, palette: TrayPalette, size: number): Buffer {
    return encodePng(drawTrayIcon(kind, palette, size), size);
}
