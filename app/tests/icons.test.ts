// The icon files in `build/` (the app icon, and the state icons the taskbar
// button shows on Windows) are drawn from the mark's description in code
// (`src/main/icon`). This test draws them again and fails if a committed file
// differs, so they can never go stale. `pnpm icons` writes them afresh.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { appIcon, ICNS_SIZES, ICO_SIZES, PNG_SIZES } from "../src/main/icon/designs";
import {
    encodeIcns,
    encodeIco,
    encodePng,
    ICNS_TYPES,
    type Square,
} from "../src/main/icon/formats";
import { draw } from "../src/main/icon/raster";
import {
    COLOUR_PALETTE,
    drawTrayIcon,
    drawWindowIcon,
    STATE_PICTURES,
    stateIconFile,
    type TrayKind,
    WINDOW_ICON_SIZES,
} from "../src/main/tray-icon";

const build = join(__dirname, "../build");
const update = process.env.UPDATE_ICONS === "1";

/** Each size is drawn once: the largest take a moment. */
const drawn = new Map<number, Square>();
function square(size: number): Square {
    let image = drawn.get(size);
    if (image === undefined) {
        image = { size, pixels: draw(appIcon(size), size) };
        drawn.set(size, image);
    }
    return image;
}

/** A state picture at one size: the tray's own drawing, as the taskbar button shows it. */
function statePicture(kind: TrayKind, frame: number, size: number): Square {
    return { size, pixels: drawWindowIcon(kind, size, frame) };
}

const stateFile = ({ kind, frame }: { kind: TrayKind; frame: number }) =>
    `state-icons/${stateIconFile(kind, frame)}`;

const NAMES = [
    "icon.ico",
    "icon.icns",
    ...PNG_SIZES.map((size) => `icons/${size}x${size}.png`),
    ...STATE_PICTURES.map(stateFile),
];
/** Drawing every size up to 1024 pixels, while other tests run beside it. */
const SLOW = { timeout: 60_000 };

/** Every file, as it should be. */
function expected(): Map<string, Buffer> {
    const files = new Map<string, Buffer>();
    files.set("icon.ico", encodeIco(ICO_SIZES.map(square)));
    files.set("icon.icns", encodeIcns(ICNS_SIZES.map(square)));
    for (const size of PNG_SIZES) {
        files.set(`icons/${size}x${size}.png`, encodePng(square(size).pixels, size));
    }
    for (const picture of STATE_PICTURES) {
        files.set(
            stateFile(picture),
            encodeIco(
                WINDOW_ICON_SIZES.map((size) => statePicture(picture.kind, picture.frame, size)),
            ),
        );
    }
    return files;
}

/** The RGBA pixels of a PNG this app wrote: 8-bit RGBA, unfiltered rows. */
function decodePng(png: Buffer): Square {
    expect(png.subarray(0, 8)).toEqual(
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    );
    let at = 8;
    let size = 0;
    const data: Buffer[] = [];
    while (at < png.length) {
        const length = png.readUInt32BE(at);
        const type = png.toString("latin1", at + 4, at + 8);
        const body = png.subarray(at + 8, at + 8 + length);
        if (type === "IHDR") {
            size = body.readUInt32BE(0);
            expect(body.readUInt32BE(4)).toBe(size);
            expect([body[8], body[9]]).toEqual([8, 6]);
        } else if (type === "IDAT") {
            data.push(body);
        }
        at += 12 + length;
    }
    const raw = inflateSync(Buffer.concat(data));
    const pixels = Buffer.alloc(size * size * 4);
    for (let y = 0; y < size; y++) {
        expect(raw[y * (size * 4 + 1)], "row filter").toBe(0);
        raw.copy(pixels, y * size * 4, y * (size * 4 + 1) + 1, (y + 1) * (size * 4 + 1));
    }
    return { size, pixels };
}

/** The images in an `.ico`: bitmaps below 256, PNG at 256. */
function decodeIco(ico: Buffer): Square[] {
    expect(ico.readUInt16LE(2)).toBe(1);
    return Array.from({ length: ico.readUInt16LE(4) }, (_, index) => {
        const entry = 6 + 16 * index;
        const size = ico[entry] === 0 ? 256 : (ico[entry] ?? 0);
        const offset = ico.readUInt32LE(entry + 12);
        const body = ico.subarray(offset, offset + ico.readUInt32LE(entry + 8));
        if (size === 256) {
            return decodePng(body);
        }
        expect(body.readInt32LE(4)).toBe(size);
        expect(body.readUInt16LE(14)).toBe(32);
        const pixels = Buffer.alloc(size * size * 4);
        for (let y = 0; y < size; y++) {
            for (let x = 0; x < size; x++) {
                const from = 40 + ((size - 1 - y) * size + x) * 4;
                const to = (y * size + x) * 4;
                pixels[to] = body[from + 2] ?? 0;
                pixels[to + 1] = body[from + 1] ?? 0;
                pixels[to + 2] = body[from] ?? 0;
                pixels[to + 3] = body[from + 3] ?? 0;
            }
        }
        return { size, pixels };
    });
}

/** The images in an `.icns`, with their types. */
function decodeIcns(icns: Buffer): { type: string; image: Square }[] {
    expect(icns.toString("latin1", 0, 4)).toBe("icns");
    expect(icns.readUInt32BE(4)).toBe(icns.length);
    const found: { type: string; image: Square }[] = [];
    for (let at = 8; at < icns.length; at += icns.readUInt32BE(at + 4)) {
        found.push({
            type: icns.toString("latin1", at, at + 4),
            image: decodePng(icns.subarray(at + 8, at + icns.readUInt32BE(at + 4))),
        });
    }
    return found;
}

/** Whether two drawings match, allowing a step of one in a channel for rounding. */
function same(actual: Square, wanted: Square): boolean {
    if (actual.size !== wanted.size) {
        return false;
    }
    return actual.pixels.every((value, at) => Math.abs(value - (wanted.pixels[at] ?? 0)) <= 1);
}

describe("the app icon files", () => {
    it.runIf(update)("are written afresh", SLOW, () => {
        const files = expected();
        expect([...files.keys()]).toEqual(NAMES);
        for (const [name, bytes] of files) {
            mkdirSync(join(build, name, ".."), { recursive: true });
            writeFileSync(join(build, name), bytes);
        }
    });

    it.skipIf(update)("are up to date with the mark: run `pnpm icons` if not", SLOW, () => {
        for (const name of NAMES) {
            expect(existsSync(join(build, name)), `build/${name} is missing`).toBe(true);
        }
        const ico = decodeIco(readFileSync(join(build, "icon.ico")));
        expect(ico.map(({ size }) => size)).toEqual([...ICO_SIZES]);
        for (const image of ico) {
            expect(same(image, square(image.size)), `icon.ico at ${image.size}`).toBe(true);
        }
        const icns = decodeIcns(readFileSync(join(build, "icon.icns")));
        expect(icns.map(({ type }) => type)).toEqual(ICNS_SIZES.map((size) => ICNS_TYPES[size]));
        for (const { image } of icns) {
            expect(same(image, square(image.size)), `icon.icns at ${image.size}`).toBe(true);
        }
        for (const size of PNG_SIZES) {
            const png = decodePng(readFileSync(join(build, `icons/${size}x${size}.png`)));
            expect(same(png, square(size)), `icons/${size}x${size}.png`).toBe(true);
        }
    });

    it.skipIf(update)(
        "give the taskbar button the tray's own picture, for every state and frame",
        SLOW,
        () => {
            for (const picture of STATE_PICTURES) {
                const name = stateFile(picture);
                const images = decodeIco(readFileSync(join(build, name)));
                // Every size Windows asks for at 100%, 125%, 150% and 200%.
                expect(
                    images.map(({ size }) => size),
                    name,
                ).toEqual([...WINDOW_ICON_SIZES]);
                for (const image of images) {
                    // The very drawing the tray shows, in the tray's colours.
                    const tray = {
                        size: image.size,
                        pixels: drawTrayIcon(
                            picture.kind,
                            COLOUR_PALETTE,
                            image.size,
                            picture.frame,
                        ),
                    };
                    expect(same(image, tray), `${name} at ${image.size}`).toBe(true);
                }
            }
            // One file per state, and one per working frame, each different.
            const files = STATE_PICTURES.map((picture) =>
                readFileSync(join(build, stateFile(picture))).toString("base64"),
            );
            expect(new Set(files).size).toBe(STATE_PICTURES.length);
        },
    );

    it("has every size Windows asks for, and fills each to its edges", () => {
        expect([...ICO_SIZES]).toEqual([16, 24, 32, 48, 64, 256]);
        for (const size of [16, 24]) {
            const { pixels } = square(size);
            // Small icons fill the image, so they are not shrunk to a speck.
            expect(pixels[(Math.floor(size / 2) * size + 0) * 4 + 3]).toBe(255);
        }
    });
});
