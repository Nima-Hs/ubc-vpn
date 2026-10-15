// Wraps RGBA pixels as the image files an OS reads icons from. Written here,
// in a few lines each, rather than with an image tool: nothing to install,
// pin or run on anyone's machine.

import { crc32, deflateSync } from "node:zlib";

/** One square image: its size and its RGBA pixels, top row first. */
export interface Square {
    size: number;
    pixels: Buffer;
}

function chunk(type: string, data: Buffer): Buffer {
    const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const frame = Buffer.alloc(8);
    frame.writeUInt32BE(data.length, 0);
    frame.writeUInt32BE(crc32(body), 4);
    return Buffer.concat([frame.subarray(0, 4), body, frame.subarray(4)]);
}

/** A PNG file. */
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
        chunk("IDAT", deflateSync(raw, { level: 9 })),
        chunk("IEND", Buffer.alloc(0)),
    ]);
}

/**
 * A 32-bit bitmap as an icon file holds it: a header, the pixels in blue,
 * green, red, alpha order from the bottom row up, then a one-bit mask that
 * the alpha channel makes redundant, left empty.
 */
function iconBitmap({ size, pixels }: Square): Buffer {
    const header = Buffer.alloc(40);
    header.writeUInt32LE(40, 0);
    header.writeInt32LE(size, 4);
    // The height counts the mask as well.
    header.writeInt32LE(size * 2, 8);
    header.writeUInt16LE(1, 12); // planes
    header.writeUInt16LE(32, 14); // bits per pixel
    const colours = Buffer.alloc(size * size * 4);
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            const from = (y * size + x) * 4;
            const to = ((size - 1 - y) * size + x) * 4;
            colours[to] = pixels[from + 2] ?? 0;
            colours[to + 1] = pixels[from + 1] ?? 0;
            colours[to + 2] = pixels[from] ?? 0;
            colours[to + 3] = pixels[from + 3] ?? 0;
        }
    }
    const maskRow = Math.ceil(size / 32) * 4;
    return Buffer.concat([header, colours, Buffer.alloc(maskRow * size)]);
}

/**
 * A Windows `.ico`. Sizes below 256 are stored as bitmaps, which every part
 * of Windows and the installer reads; 256 as PNG, as Windows expects.
 */
export function encodeIco(images: readonly Square[]): Buffer {
    const bodies = images.map((image) =>
        image.size >= 256 ? encodePng(image.pixels, image.size) : iconBitmap(image),
    );
    const directory = Buffer.alloc(6 + 16 * images.length);
    directory.writeUInt16LE(0, 0);
    directory.writeUInt16LE(1, 2); // an icon, not a cursor
    directory.writeUInt16LE(images.length, 4);
    let offset = directory.length;
    images.forEach((image, index) => {
        const at = 6 + 16 * index;
        const body = bodies[index] as Buffer;
        // A size of 256 is written as 0.
        directory[at] = image.size >= 256 ? 0 : image.size;
        directory[at + 1] = image.size >= 256 ? 0 : image.size;
        directory.writeUInt16LE(1, at + 4); // planes
        directory.writeUInt16LE(32, at + 6); // bits per pixel
        directory.writeUInt32LE(body.length, at + 8);
        directory.writeUInt32LE(offset, at + 12);
        offset += body.length;
    });
    return Buffer.concat([directory, ...bodies]);
}

/** The `.icns` type that holds a PNG of each size. */
export const ICNS_TYPES: Readonly<Record<number, string>> = {
    16: "icp4",
    32: "icp5",
    64: "icp6",
    128: "ic07",
    256: "ic08",
    512: "ic09",
    1024: "ic10",
};

/** A macOS `.icns`, each size a PNG. */
export function encodeIcns(images: readonly Square[]): Buffer {
    const entries = images.map(({ size, pixels }) => {
        const type = ICNS_TYPES[size];
        if (type === undefined) {
            throw new Error(`.icns holds no ${size}-pixel image`);
        }
        const png = encodePng(pixels, size);
        const head = Buffer.alloc(8);
        head.write(type, 0, "latin1");
        head.writeUInt32BE(png.length + 8, 4);
        return Buffer.concat([head, png]);
    });
    const body = Buffer.concat(entries);
    const head = Buffer.alloc(8);
    head.write("icns", 0, "latin1");
    head.writeUInt32BE(body.length + 8, 4);
    return Buffer.concat([head, body]);
}
