// How the connection screen shows the subnets a tunnel carries. Display only:
// what is routed is always exactly the saved list, and the screen keeps that
// list one click away.
//
// A range is often saved in pieces. To route all of a campus network except
// one address (the VPN server's own, say), a route table needs the range cut
// into up to 32 subnets around the hole. Shown one per row, those pieces bury
// the subnets the user actually chose, so they are shown here as the range
// they came from, with what was left out.

/** One row on the screen: a saved subnet, or a range shown in place of several. */
export interface ShownSubnet {
    /** What the row shows. A saved subnet, or the range its `parts` make. */
    subnet: string;
    /** The saved subnets behind the row, in the order they were saved. */
    parts: readonly string[];
    /** The addresses inside `subnet` that no part covers: one address, or "first–last". */
    leftOut: readonly string[];
    /** How many addresses `leftOut` holds in all. */
    leftOutCount: number;
}

/** A range may leave out at most this share of itself, so it is never mostly holes. */
const MOST_LEFT_OUT = 1 / 64;
/** No route the service accepts is wider than this. */
const WIDEST = 8;

interface Block {
    /** Where it sits in the saved list. */
    index: number;
    text: string;
    first: number;
    /** The last address, inclusive. */
    last: number;
    prefix: number;
}

const size = (prefix: number) => 2 ** (32 - prefix);

function address(text: string): number | null {
    const parts = text.split(".");
    if (parts.length !== 4 || !parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part))) {
        return null;
    }
    const octets = parts.map(Number);
    if (octets.some((octet) => octet > 255)) {
        return null;
    }
    return octets.reduce((sum, octet) => sum * 256 + octet, 0);
}

/** A subnet written exactly as the network it names, or null. */
function block(text: string, index: number): Block | null {
    const match = /^([^/]+)\/(\d{1,2})$/.exec(text);
    if (match === null) {
        return null;
    }
    const first = address(match[1] ?? "");
    const prefix = Number(match[2]);
    if (first === null || prefix > 32 || first % size(prefix) !== 0) {
        return null;
    }
    return { index, text, first, last: first + size(prefix) - 1, prefix };
}

function dotted(value: number): string {
    return [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join(".");
}

/** The parts' gaps inside a range, or null when two parts overlap. */
function gaps(parts: readonly Block[], range: { first: number; last: number }) {
    const sorted = [...parts].sort((a, b) => a.first - b.first);
    const holes: [number, number][] = [];
    let next = range.first;
    for (const part of sorted) {
        if (part.first < next) {
            return null;
        }
        if (part.first > next) {
            holes.push([next, part.first - 1]);
        }
        next = part.last + 1;
    }
    if (next <= range.last) {
        holes.push([next, range.last]);
    }
    return holes;
}

/**
 * The rows to show for a tunnel's subnets. Saved subnets that together make
 * one range, leaving out at most a small share of it, become one row for that
 * range; everything else is shown as saved. A subnet that cannot be read, or
 * that overlaps another, is never combined.
 */
export function summariseSubnets(saved: readonly string[]): ShownSubnet[] {
    const blocks = saved.map(block).filter((found): found is Block => found !== null);

    // Every range a saved subnet sits in, widest first, is a candidate.
    const candidates = new Map<string, { first: number; prefix: number }>();
    for (const piece of blocks) {
        for (let prefix = piece.prefix - 1; prefix >= WIDEST; prefix--) {
            const first = piece.first - (piece.first % size(prefix));
            candidates.set(`${first}/${prefix}`, { first, prefix });
        }
    }
    const widestFirst = [...candidates.values()].sort(
        (a, b) => a.prefix - b.prefix || a.first - b.first,
    );

    const taken = new Set<number>();
    const rangeAt = new Map<number, ShownSubnet>();
    for (const { first, prefix } of widestFirst) {
        const range = { first, last: first + size(prefix) - 1 };
        const inside = blocks.filter(
            (piece) => piece.first >= range.first && piece.last <= range.last,
        );
        const across = blocks.some(
            (piece) =>
                piece.first <= range.last && piece.last >= range.first && !inside.includes(piece),
        );
        if (inside.length < 2 || across || inside.some((piece) => taken.has(piece.index))) {
            continue;
        }
        const holes = gaps(inside, range);
        if (holes === null) {
            continue;
        }
        const leftOutCount = holes.reduce((sum, [from, to]) => sum + to - from + 1, 0);
        if (leftOutCount > size(prefix) * MOST_LEFT_OUT) {
            continue;
        }
        const inOrder = [...inside].sort((a, b) => a.index - b.index);
        const shown: ShownSubnet = {
            subnet: `${dotted(first)}/${prefix}`,
            parts: inOrder.map((piece) => piece.text),
            leftOut: holes.map(([from, to]) =>
                from === to ? dotted(from) : `${dotted(from)}–${dotted(to)}`,
            ),
            leftOutCount,
        };
        for (const piece of inside) {
            taken.add(piece.index);
        }
        rangeAt.set(inOrder[0]?.index ?? 0, shown);
    }

    const rows: ShownSubnet[] = [];
    saved.forEach((text, index) => {
        const range = rangeAt.get(index);
        if (range !== undefined) {
            rows.push(range);
        } else if (!taken.has(index)) {
            rows.push({ subnet: text, parts: [text], leftOut: [], leftOutCount: 0 });
        }
    });
    return rows;
}
