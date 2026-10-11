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

type Rgb = readonly [number, number, number];

export interface TrayPalette {
    /** The outline, chosen to stand out against the OS's tray. */
    ink: Rgb;
    on: Rgb;
    attention: Rgb;
}

/** One colour throughout, for macOS, which tints template images itself. */
export const TEMPLATE_PALETTE: TrayPalette = {
    ink: [0, 0, 0],
    on: [0, 0, 0],
    attention: [0, 0, 0],
};

export function colourPalette(darkTray: boolean): TrayPalette {
    return {
        ink: darkTray ? [236, 239, 245] : [32, 36, 46],
        on: darkTray ? [77, 214, 160] : [0, 135, 90],
        attention: darkTray ? [245, 183, 77] : [176, 106, 0],
    };
}

/** Samples per pixel along each axis, for smooth edges. */
const SAMPLES = 4;

/**
 * Colour and coverage at one point, in units where the icon is 1 wide.
 * Off is a ring, on is a filled disc, busy is a ring around a dot, and
 * attention is a ring with a solid badge at the lower right.
 */
function sample(kind: TrayKind, palette: TrayPalette, x: number, y: number): Rgb | null {
    const fromCentre = Math.hypot(x - 0.5, y - 0.5);
    if (kind === "on") {
        return fromCentre <= 0.44 ? palette.on : null;
    }
    if (kind === "attention") {
        const fromBadge = Math.hypot(x - 0.76, y - 0.76);
        if (fromBadge <= 0.2) {
            return palette.attention;
        }
        // A clear gap keeps the badge apart from the ring in one colour.
        if (fromBadge <= 0.29) {
            return null;
        }
    }
    if (fromCentre <= 0.44 && fromCentre >= 0.31) {
        return palette.ink;
    }
    if (kind === "busy" && fromCentre <= 0.14) {
        return palette.ink;
    }
    return null;
}

/** The icon as RGBA pixels, `size` wide and high. */
export function drawTrayIcon(kind: TrayKind, palette: TrayPalette, size: number): Buffer {
    const pixels = Buffer.alloc(size * size * 4);
    for (let py = 0; py < size; py++) {
        for (let px = 0; px < size; px++) {
            let covered = 0;
            let colour: Rgb = palette.ink;
            for (let sy = 0; sy < SAMPLES; sy++) {
                for (let sx = 0; sx < SAMPLES; sx++) {
                    const hit = sample(
                        kind,
                        palette,
                        (px + (sx + 0.5) / SAMPLES) / size,
                        (py + (sy + 0.5) / SAMPLES) / size,
                    );
                    if (hit !== null) {
                        covered++;
                        colour = hit;
                    }
                }
            }
            const at = (py * size + px) * 4;
            pixels[at] = colour[0];
            pixels[at + 1] = colour[1];
            pixels[at + 2] = colour[2];
            pixels[at + 3] = Math.round((covered / (SAMPLES * SAMPLES)) * 255);
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
