// Draws vector shapes into RGBA pixels. Every image the app shows outside its
// window (the app icon, the tray icon, the taskbar badge) is drawn here from a
// description in code, so every size comes from one source and nothing can go
// stale. No Electron and no alias imports, so tests and scripts can load it.

import type { Curve } from "../../shared/mark";

export type Rgb = readonly [number, number, number];

/** A dash pattern along a curve, in fractions of its length. */
export interface Dash {
    on: number;
    off: number;
    /** How far along the pattern starts. */
    phase: number;
}

export type Shape =
    | { kind: "curve"; curve: Curve; width: number; dash?: Dash }
    | { kind: "box"; x0: number; y0: number; x1: number; y1: number; radius: number }
    | { kind: "disc"; cx: number; cy: number; r: number }
    | { kind: "ring"; cx: number; cy: number; r: number; width: number }
    | { kind: "polygon"; points: readonly (readonly [number, number])[] };

/** A shape painted in a colour, or, with `colour: null`, cut out of everything below it. */
export interface Layer {
    shape: Shape;
    colour: Rgb | null;
}

export interface Drawing {
    /** The layers are laid out on a square this many units wide. */
    box: number;
    layers: readonly Layer[];
    /**
     * A dark edge around everything painted, so light shapes also show on a
     * light background. `width` is in pixels at whatever size is drawn.
     */
    rim?: { colour: Rgb; width: number; alpha: number };
}

/** Segments a curve is cut into for measuring. Enough for 1024 pixels. */
const STEPS = 64;

interface Prepared {
    /** Signed distance in units: negative inside. */
    distance(x: number, y: number): number;
    /** Bounds in units, beyond which the shape covers nothing. */
    bounds: readonly [number, number, number, number];
}

function point(curve: Curve, t: number): [number, number] {
    const [a, b, c, d] = curve;
    const u = 1 - t;
    const w = [u * u * u, 3 * u * u * t, 3 * u * t * t, t * t * t] as const;
    return [
        w[0] * a[0] + w[1] * b[0] + w[2] * c[0] + w[3] * d[0],
        w[0] * a[1] + w[1] * b[1] + w[2] * c[1] + w[3] * d[1],
    ];
}

function prepareCurve(curve: Curve, width: number, dash: Dash | undefined): Prepared {
    const points = Array.from({ length: STEPS + 1 }, (_, i) => point(curve, i / STEPS));
    // How far along the curve each point is.
    const along = [0];
    for (let i = 1; i <= STEPS; i++) {
        const [x0, y0] = points[i - 1] as [number, number];
        const [x1, y1] = points[i] as [number, number];
        along.push((along[i - 1] ?? 0) + Math.hypot(x1 - x0, y1 - y0));
    }
    const length = along[STEPS] ?? 1;
    const xs = points.map(([x]) => x);
    const ys = points.map(([, y]) => y);
    const half = width / 2;
    return {
        bounds: [
            Math.min(...xs) - half,
            Math.min(...ys) - half,
            Math.max(...xs) + half,
            Math.max(...ys) + half,
        ],
        distance(x, y) {
            let best = Number.POSITIVE_INFINITY;
            let bestAlong = 0;
            for (let i = 0; i < STEPS; i++) {
                const [x0, y0] = points[i] as [number, number];
                const [x1, y1] = points[i + 1] as [number, number];
                const dx = x1 - x0;
                const dy = y1 - y0;
                const span = dx * dx + dy * dy;
                const t =
                    span === 0
                        ? 0
                        : Math.min(1, Math.max(0, ((x - x0) * dx + (y - y0) * dy) / span));
                const d = Math.hypot(x - (x0 + t * dx), y - (y0 + t * dy));
                if (d < best) {
                    best = d;
                    bestAlong = (along[i] ?? 0) + t * Math.sqrt(span);
                }
            }
            if (dash !== undefined) {
                // Outside a dash, the distance runs on to the nearest dash end,
                // which gives each dash a round cap.
                const period = dash.on + dash.off;
                const at = (((bestAlong / length - dash.phase) % period) + period) % period;
                if (at > dash.on) {
                    const gap = Math.min(at - dash.on, period - at) * length;
                    best = Math.hypot(best, gap);
                }
            }
            return best - half;
        },
    };
}

function prepare(shape: Shape): Prepared {
    switch (shape.kind) {
        case "curve":
            return prepareCurve(shape.curve, shape.width, shape.dash);
        case "box": {
            const cx = (shape.x0 + shape.x1) / 2;
            const cy = (shape.y0 + shape.y1) / 2;
            const hx = (shape.x1 - shape.x0) / 2 - shape.radius;
            const hy = (shape.y1 - shape.y0) / 2 - shape.radius;
            return {
                bounds: [shape.x0, shape.y0, shape.x1, shape.y1],
                distance(x, y) {
                    const qx = Math.abs(x - cx) - hx;
                    const qy = Math.abs(y - cy) - hy;
                    return (
                        Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) +
                        Math.min(Math.max(qx, qy), 0) -
                        shape.radius
                    );
                },
            };
        }
        case "disc":
            return {
                bounds: [
                    shape.cx - shape.r,
                    shape.cy - shape.r,
                    shape.cx + shape.r,
                    shape.cy + shape.r,
                ],
                distance: (x, y) => Math.hypot(x - shape.cx, y - shape.cy) - shape.r,
            };
        case "ring": {
            const outer = shape.r + shape.width / 2;
            return {
                bounds: [shape.cx - outer, shape.cy - outer, shape.cx + outer, shape.cy + outer],
                distance: (x, y) =>
                    Math.abs(Math.hypot(x - shape.cx, y - shape.cy) - shape.r) - shape.width / 2,
            };
        }
        case "polygon": {
            const points = shape.points;
            const xs = points.map(([x]) => x);
            const ys = points.map(([, y]) => y);
            return {
                bounds: [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)],
                distance(x, y) {
                    let best = Number.POSITIVE_INFINITY;
                    let inside = false;
                    for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
                        const [xi, yi] = points[i] as readonly [number, number];
                        const [xj, yj] = points[j] as readonly [number, number];
                        const dx = xi - xj;
                        const dy = yi - yj;
                        const t = Math.min(
                            1,
                            Math.max(0, ((x - xj) * dx + (y - yj) * dy) / (dx * dx + dy * dy)),
                        );
                        best = Math.min(best, Math.hypot(x - (xj + t * dx), y - (yj + t * dy)));
                        if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) {
                            inside = !inside;
                        }
                    }
                    return inside ? -best : best;
                },
            };
        }
    }
}

/** How much of a pixel a shape covers, from its signed distance in pixels. */
const cover = (distance: number) => Math.min(1, Math.max(0, 0.5 - distance));

/** The drawing as RGBA pixels, `size` wide and high. */
export function draw(drawing: Drawing, size: number): Buffer {
    const scale = size / drawing.box;
    const rim = drawing.rim;
    const rimUnits = rim === undefined ? 0 : rim.width / scale;
    const layers = drawing.layers.map((layer) => ({ ...layer, prepared: prepare(layer.shape) }));
    const pixels = Buffer.alloc(size * size * 4);
    for (let py = 0; py < size; py++) {
        for (let px = 0; px < size; px++) {
            const x = (px + 0.5) / scale;
            const y = (py + 0.5) / scale;
            // Painted colour, premultiplied by its coverage.
            let red = 0;
            let green = 0;
            let blue = 0;
            let alpha = 0;
            let rimAlpha = 0;
            for (const { colour, prepared } of layers) {
                const [x0, y0, x1, y1] = prepared.bounds;
                const reach = rimUnits + 1 / scale;
                if (x < x0 - reach || x > x1 + reach || y < y0 - reach || y > y1 + reach) {
                    continue;
                }
                const distance = prepared.distance(x, y) * scale;
                const covered = cover(distance);
                if (colour === null) {
                    red *= 1 - covered;
                    green *= 1 - covered;
                    blue *= 1 - covered;
                    alpha *= 1 - covered;
                    // The rim stays along the cut edge, so it is edged too.
                    rimAlpha *= 1 - cover(distance + (rim?.width ?? 0));
                    continue;
                }
                red = colour[0] * covered + red * (1 - covered);
                green = colour[1] * covered + green * (1 - covered);
                blue = colour[2] * covered + blue * (1 - covered);
                alpha = covered + alpha * (1 - covered);
                if (rim !== undefined) {
                    rimAlpha = Math.max(rimAlpha, cover(distance - rim.width));
                }
            }
            // The rim goes under the paint.
            if (rim !== undefined && rimAlpha > 0) {
                const under = rimAlpha * rim.alpha * (1 - alpha);
                red += rim.colour[0] * under;
                green += rim.colour[1] * under;
                blue += rim.colour[2] * under;
                alpha += under;
            }
            if (alpha <= 0) {
                continue;
            }
            const at = (py * size + px) * 4;
            pixels[at] = Math.round(red / alpha);
            pixels[at + 1] = Math.round(green / alpha);
            pixels[at + 2] = Math.round(blue / alpha);
            pixels[at + 3] = Math.round(alpha * 255);
        }
    }
    return pixels;
}
