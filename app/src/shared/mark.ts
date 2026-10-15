// The app's mark: one line in, two lines out. The upper line is the tunnel to
// UBC, the lower one the normal connection, as in the connection screen's
// diagram. This is the one description of it: the title bar draws it as SVG,
// and the main process draws the app icon, the tray icon and the taskbar badge
// from the same numbers (`src/main/icon`).

/** A cubic Bézier curve: start, two control points, end. */
export type Curve = readonly [
    readonly [number, number],
    readonly [number, number],
    readonly [number, number],
    readonly [number, number],
];

/** The mark is drawn on a square this many units wide. */
export const MARK_BOX = 16;

/** The tunnel to UBC. */
export const TUNNEL_CURVE: Curve = [
    [2, 8],
    [7, 8],
    [7, 3.5],
    [14, 3.5],
];

/** The normal connection. */
export const DIRECT_CURVE: Curve = [
    [2, 8],
    [7, 8],
    [7, 12.5],
    [14, 12.5],
];

/** Stroke widths, in the mark's units: the tunnel is the wide lane. */
export const TUNNEL_WIDTH = 2.5;
export const DIRECT_WIDTH = 1.5;

/** A curve as an SVG path. */
export function curvePath([start, one, two, end]: Curve): string {
    return `M${start.join(" ")} C${one.join(" ")} ${two.join(" ")} ${end.join(" ")}`;
}
