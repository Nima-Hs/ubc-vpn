// What each icon looks like, built from the app's mark (`shared/mark.ts`):
// the app icon, the tray icon in each state, and the badge on the taskbar
// button. Every colour is a design token; `tests/tokens.test.ts` fails if one
// drifts.

import {
    type Curve,
    DIRECT_CURVE,
    DIRECT_WIDTH,
    MARK_BOX,
    TUNNEL_CURVE,
    TUNNEL_WIDTH,
} from "../../shared/mark";
import type { Drawing, Layer, Rgb, Shape } from "./raster";

/** Design tokens, as sRGB. */
export const COLOURS = {
    /** `--c-bg` */
    bg: [11, 14, 20],
    /** `--c-surface` */
    surface: [20, 23, 30],
    /** `--c-border-strong` */
    edge: [79, 86, 98],
    /** `--c-text` */
    text: [238, 240, 244],
    /** `--c-text-secondary` */
    secondary: [184, 190, 200],
    /** `--c-text-tertiary` */
    tertiary: [152, 159, 171],
    /** `--c-accent` */
    accent: [102, 198, 253],
    /** `--c-positive` */
    positive: [89, 225, 162],
    /** `--c-attention` */
    attention: [245, 194, 95],
    /** `--c-danger` */
    danger: [252, 122, 121],
} as const satisfies Record<string, Rgb>;

/** Moves and scales a curve about the middle of the mark's square. */
function scaled(curve: Curve, scale: number): Curve {
    const middle = MARK_BOX / 2;
    return curve.map(([x, y]) => [
        middle + (x - middle) * scale,
        middle + (y - middle) * scale,
    ]) as unknown as Curve;
}

// The app icon -------------------------------------------------------------

/** The sizes Windows asks an `.ico` for. */
export const ICO_SIZES = [16, 24, 32, 48, 64, 256] as const;
/** The sizes in the macOS `.icns`. */
export const ICNS_SIZES = [16, 32, 64, 128, 256, 512, 1024] as const;
/** The sizes Linux desktops look for, one PNG each. */
export const PNG_SIZES = [16, 24, 32, 48, 64, 128, 256, 512] as const;

/**
 * The app icon: the mark on a rounded square of the app's dark surface, with
 * an edge, so it reads on a dark taskbar and a light one alike. At 24 pixels
 * and below the square fills the image and the lines are drawn thicker, so the
 * lower one does not fade to nothing.
 */
export function appIcon(size: number): Drawing {
    const small = size <= 24;
    // In whole pixels, so the edge is drawn crisp at every size.
    const pixel = MARK_BOX / size;
    const inset = small ? 0 : Math.round(size * 0.0375) * pixel;
    const edge = Math.max(1, Math.round(size / 64)) * pixel;
    const radius = small ? 3 : 3.4;
    const mark = small ? 0.8 : 0.74;
    const square = (grow: number): Shape => ({
        kind: "box",
        x0: inset + grow,
        y0: inset + grow,
        x1: MARK_BOX - inset - grow,
        y1: MARK_BOX - inset - grow,
        radius: radius - grow,
    });
    return {
        box: MARK_BOX,
        layers: [
            { shape: square(0), colour: COLOURS.edge },
            { shape: square(edge), colour: COLOURS.surface },
            {
                shape: {
                    kind: "curve",
                    curve: scaled(DIRECT_CURVE, mark),
                    width: small ? 1.75 : DIRECT_WIDTH * mark,
                },
                colour: COLOURS.tertiary,
            },
            {
                shape: {
                    kind: "curve",
                    curve: scaled(TUNNEL_CURVE, mark),
                    width: small ? 2.6 : TUNNEL_WIDTH * mark,
                },
                colour: COLOURS.accent,
            },
        ],
    };
}

// The tray ------------------------------------------------------------------

/**
 * The things the tray can say. Each has a shape of its own as well as a
 * colour, for anyone who cannot tell the colours apart and because macOS
 * draws tray icons in one colour.
 */
export type TrayKind = "off" | "busy" | "on" | "attention" | "problem";

export const TRAY_KINDS: readonly TrayKind[] = ["off", "busy", "on", "attention", "problem"];

/** The colour of each part of the tray icon. */
export interface TrayPalette {
    /** The normal-connection line, and the tunnel while it is off. */
    ink: Rgb;
    busy: Rgb;
    on: Rgb;
    attention: Rgb;
    problem: Rgb;
    /**
     * A thin dark rim around every shape, or `null` for none. The icon cannot
     * know the colour of the taskbar it sits on, so it carries its own
     * contrast: light shapes for a dark bar, rimmed for a light one.
     */
    rim: Rgb | null;
}

/** One colour and no rim, for macOS, which tints template images itself. */
export const TEMPLATE_PALETTE: TrayPalette = {
    ink: [0, 0, 0],
    busy: [0, 0, 0],
    on: [0, 0, 0],
    attention: [0, 0, 0],
    problem: [0, 0, 0],
    rim: null,
};

/** For Windows and Linux. */
export const COLOUR_PALETTE: TrayPalette = {
    ink: COLOURS.secondary,
    busy: COLOURS.accent,
    on: COLOURS.positive,
    attention: COLOURS.attention,
    problem: COLOURS.danger,
    rim: COLOURS.bg,
};

/** How many pictures the working tray icon steps through, and how fast. */
export const BUSY_FRAMES = 3;
export const BUSY_FRAME_MS = 280;

/** Every picture the state icon can show: each state, and each working frame. */
export const STATE_PICTURES: readonly { kind: TrayKind; frame: number }[] = TRAY_KINDS.flatMap(
    (kind): { kind: TrayKind; frame: number }[] =>
        kind === "busy"
            ? Array.from({ length: BUSY_FRAMES }, (_, frame) => ({ kind, frame }))
            : [{ kind, frame: 0 }],
);

/**
 * The tunnel in two dashes, a third of a step further along in each frame.
 * The round caps reach into the gaps, so the gaps are long enough to stay
 * open at 16 pixels.
 */
const DASH = { on: 0.14, off: 0.36 };

/** Where the badge sits: over the end of the lower line. */
const BADGE = { cx: 12, cy: 12, gap: 4.4 };

const TRIANGLE = [
    [12, 8],
    [15.6, 14.6],
    [8.4, 14.6],
] as const;

const DIAMOND = [
    [12, 8.4],
    [15.6, 12],
    [12, 15.6],
    [8.4, 12],
] as const;

/**
 * Off: both lines thin, the tunnel closed. Working: the tunnel wide and in
 * moving dashes. On: the tunnel wide and whole. Needs attention: off, with a
 * triangle over the end of the lower line. A problem: off, with a diamond
 * there instead.
 */
export function trayIcon(kind: TrayKind, palette: TrayPalette, frame = 0): Drawing {
    const open = kind === "busy" || kind === "on";
    const layers: Layer[] = [
        {
            shape: { kind: "curve", curve: DIRECT_CURVE, width: DIRECT_WIDTH + 0.1 },
            colour: palette.ink,
        },
        {
            shape: {
                kind: "curve",
                curve: TUNNEL_CURVE,
                width: open ? TUNNEL_WIDTH + 0.25 : DIRECT_WIDTH + 0.1,
                ...(kind === "busy" && {
                    dash: {
                        ...DASH,
                        phase: -((frame % BUSY_FRAMES) / BUSY_FRAMES) * (DASH.on + DASH.off),
                    },
                }),
            },
            colour: kind === "busy" ? palette.busy : kind === "on" ? palette.on : palette.ink,
        },
    ];
    if (kind === "attention" || kind === "problem") {
        // A clear gap keeps the badge apart from the lines in one colour.
        layers.push({
            shape: { kind: "disc", cx: BADGE.cx, cy: BADGE.cy, r: BADGE.gap },
            colour: null,
        });
        layers.push({
            shape: { kind: "polygon", points: kind === "attention" ? TRIANGLE : DIAMOND },
            colour: kind === "attention" ? palette.attention : palette.problem,
        });
    }
    return {
        box: MARK_BOX,
        layers,
        ...(palette.rim !== null && { rim: { colour: palette.rim, width: 1, alpha: 0.85 } }),
    };
}
