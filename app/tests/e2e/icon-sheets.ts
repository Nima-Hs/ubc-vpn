// Pictures of the icons the app draws outside its window, for the screenshots
// a run keeps: the app icon at the sizes Windows uses, the tray icon in every
// state, and the taskbar button, which shows the tray's picture. Each on a
// dark and a light taskbar, at real size and, where small, enlarged with hard
// pixel edges.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import {
    appIcon,
    COLOUR_PALETTE,
    ICO_SIZES,
    STATE_PICTURES,
    TEMPLATE_PALETTE,
    trayIcon,
} from "../../src/main/icon/designs";
import { encodePng } from "../../src/main/icon/formats";
import { type Drawing, draw, type Rgb } from "../../src/main/icon/raster";

/** Windows 11's taskbar, dark and light. */
const DARK: Rgb = [32, 32, 32];
const LIGHT: Rgb = [243, 243, 243];
const GAP = 12;

class Sheet {
    readonly pixels: Buffer;
    constructor(
        readonly width: number,
        readonly height: number,
    ) {
        this.pixels = Buffer.alloc(width * height * 4, 255);
    }

    fill(x: number, y: number, w: number, h: number, [r, g, b]: Rgb): void {
        for (let row = y; row < y + h; row++) {
            for (let col = x; col < x + w; col++) {
                const at = (row * this.width + col) * 4;
                this.pixels[at] = r;
                this.pixels[at + 1] = g;
                this.pixels[at + 2] = b;
                this.pixels[at + 3] = 255;
            }
        }
    }

    /** Lays a drawing over the sheet at `size` pixels, each shown `zoom` times larger. */
    put(drawing: Drawing, size: number, x: number, y: number, zoom = 1): void {
        const source = draw(drawing, size);
        for (let row = 0; row < size * zoom; row++) {
            for (let col = 0; col < size * zoom; col++) {
                const from = (Math.floor(row / zoom) * size + Math.floor(col / zoom)) * 4;
                const alpha = (source[from + 3] ?? 0) / 255;
                const at = ((y + row) * this.width + x + col) * 4;
                for (let channel = 0; channel < 3; channel++) {
                    this.pixels[at + channel] = Math.round(
                        (source[from + channel] ?? 0) * alpha +
                            (this.pixels[at + channel] ?? 0) * (1 - alpha),
                    );
                }
            }
        }
    }

    save(path: string): void {
        // encodePng takes squares; pad to one.
        const side = Math.max(this.width, this.height);
        const square = Buffer.alloc(side * side * 4, 255);
        for (let row = 0; row < this.height; row++) {
            this.pixels.copy(
                square,
                row * side * 4,
                row * this.width * 4,
                (row + 1) * this.width * 4,
            );
        }
        writeFileSync(path, encodePng(square, side));
    }
}

/** The app icon at every size in the `.ico`, then 16, 24 and 32 enlarged. */
function appIconSheet(path: string): void {
    const sizes = [...ICO_SIZES];
    const zooms = [
        [16, 8],
        [24, 6],
        [32, 4],
    ] as const;
    const realWidth = sizes.reduce((sum, size) => sum + size + GAP, GAP);
    const zoomWidth = zooms.reduce((sum, [size, zoom]) => sum + size * zoom + GAP, GAP);
    // Real sizes on one line, bottoms aligned; the enlarged ones on the next.
    const band = 256 + 128 + 3 * GAP;
    const sheet = new Sheet(Math.max(realWidth, zoomWidth), 2 * band);
    [DARK, LIGHT].forEach((background, index) => {
        const top = index * band;
        sheet.fill(0, top, sheet.width, band, background);
        let x = GAP;
        for (const size of sizes) {
            sheet.put(appIcon(size), size, x, top + GAP + 256 - size);
            x += size + GAP;
        }
        x = GAP;
        for (const [size, zoom] of zooms) {
            sheet.put(appIcon(size), size, x, top + 2 * GAP + 256, zoom);
            x += size * zoom + GAP;
        }
    });
    sheet.save(path);
}

/**
 * The tray icon: one row per state (off, the working frames, on, attention,
 * problem). Columns: colour on a dark bar, colour on a light bar, and the
 * one-colour macOS image on a light bar; each at 16 pixels, then enlarged.
 */
function traySheet(path: string): void {
    const rows = STATE_PICTURES;
    const zoom = 6;
    const cell = 16 + GAP + 16 * zoom + 2 * GAP;
    const columns = [
        { background: DARK, palette: COLOUR_PALETTE },
        { background: LIGHT, palette: COLOUR_PALETTE },
        { background: LIGHT, palette: TEMPLATE_PALETTE },
    ];
    const rowHeight = 16 * zoom + GAP;
    const sheet = new Sheet(columns.length * (cell + GAP), rows.length * rowHeight + GAP);
    columns.forEach(({ background, palette }, column) => {
        const left = column * (cell + GAP);
        sheet.fill(left, 0, cell, sheet.height, background);
        rows.forEach(({ kind, frame }, row) => {
            const top = GAP + row * rowHeight;
            const drawing = trayIcon(kind, palette, frame);
            sheet.put(drawing, 16, left + GAP, top + (16 * zoom - 16) / 2);
            sheet.put(drawing, 16, left + GAP + 16 + GAP, top, zoom);
        });
    });
    sheet.save(path);
}

/**
 * The taskbar button on Windows: the tray's own picture for each state and
 * working frame (one row each), at the size Windows takes for the button at
 * 100%, 125%, 150% and 200% scaling (32, 40, 48 and 64 pixels), on a dark
 * taskbar and then a light one.
 */
function taskbarSheet(path: string): void {
    const sizes = [32, 40, 48, 64];
    const bandWidth = sizes.reduce((sum, size) => sum + size + GAP, GAP);
    const rowHeight = 64 + GAP;
    const sheet = new Sheet(2 * bandWidth, STATE_PICTURES.length * rowHeight + GAP);
    [DARK, LIGHT].forEach((background, band) => {
        const left = band * bandWidth;
        sheet.fill(left, 0, bandWidth, sheet.height, background);
        STATE_PICTURES.forEach(({ kind, frame }, row) => {
            const top = GAP + row * rowHeight;
            let x = left + GAP;
            for (const size of sizes) {
                sheet.put(trayIcon(kind, COLOUR_PALETTE, frame), size, x, top + 64 - size);
                x += size + GAP;
            }
        });
    });
    sheet.save(path);
}

export function photographIcons(folder: string): string[] {
    const files = ["icon-app.png", "icon-tray.png", "icon-taskbar.png"];
    appIconSheet(join(folder, files[0] as string));
    traySheet(join(folder, files[1] as string));
    taskbarSheet(join(folder, files[2] as string));
    return files;
}
