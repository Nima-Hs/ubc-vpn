import type { Tone } from "@shared/copy";
import type { TunnelMode } from "@shared/protocol/TunnelMode";
import { motion } from "motion/react";
import { useRef } from "react";
import { cn } from "@/lib/cn";
import { duration, easeOut } from "@/lib/motion";
import { useClockLock, useLinger } from "@/lib/steady-loop";

// The app's one picture: this computer on the left, and the ways its
// traffic can go. The upper lane is the tunnel to UBC, which fills when the
// VPN is on. The lower lane is the normal connection.
//
// Split tunnel: the tunnel carries UBC's subnets, and the lower lane runs
// all the way to everything else. Full tunnel: the lower lane stops at the
// local network, and everything else is reached through UBC, down a lane
// from UBC to where the lower one used to end. Switching moves between the
// two: the lower lane draws back to the local network as the lane on from
// UBC fills, and back again.

const TUNNEL = "M 22 75 C 124 75 122 32 224 32 L 318 32";
/** The pulse's way in full tunnel: through the tunnel, then on from UBC. */
const THROUGH_UBC = `${TUNNEL} L 318 118`;
/** From the computer to the local network: the part of the lower lane full tunnel keeps. */
const LOCAL = "M 22 75 C 124 75 122 118 224 118";
/** The rest of the lower lane, to everything else: split tunnel only. */
const REST = "M 224 118 L 318 118";
/** From UBC on to everything else: full tunnel only. */
const ONWARD = "M 318 32 L 318 118";

const lane: Record<Tone, string> = {
    idle: "stroke-control",
    busy: "stroke-control",
    on: "stroke-positive-subtle",
    attention: "stroke-attention-subtle",
    problem: "stroke-danger-subtle",
};

const ubc: Record<Tone, string> = {
    idle: "fill-bg stroke-text-tertiary",
    busy: "fill-bg stroke-accent",
    on: "fill-positive stroke-positive",
    attention: "fill-bg stroke-attention",
    problem: "fill-bg stroke-danger",
};

/** Fades between the two modes' parts, at the state's own pace. */
const fade = "transition-opacity duration-(--dur-base) ease-out";

/** One mode's working pulse: shown, and moving, only while that mode is working. */
function Pulse({ d, mode, shown }: { d: string; mode: TunnelMode; shown: boolean }) {
    // The pulse keeps moving while it fades out, and runs on the page's
    // clock, so no change of state, mode or screen makes it jump.
    const pulsing = useLinger(shown, duration.base * 1000);
    const pulse = useRef<SVGPathElement>(null);
    useClockLock(pulse, pulsing);
    return (
        <g className={cn(fade, shown ? "opacity-100" : "opacity-0")}>
            <path
                ref={pulse}
                data-pulse={mode}
                d={d}
                pathLength={1}
                strokeWidth={7}
                strokeDasharray="0.16 0.84"
                strokeDashoffset={-0.42}
                className={cn("stroke-accent", pulsing && "motion-safe:animate-flow")}
            />
        </g>
    );
}

/** Decorative: the words beside it always say the same thing. */
export function TunnelDiagram({
    tone,
    mode = "split",
    held = false,
    className,
}: {
    tone: Tone;
    /** Split or full: which way everything else goes. */
    mode?: TunnelMode;
    /**
     * Switching mode while connected: the connection stays up, so the
     * tunnel stays filled under the working pulse.
     */
    held?: boolean;
    className?: string;
}) {
    const busy = tone === "busy";
    const on = tone === "on" || held;
    const full = mode === "full";
    // Connected: the tunnel fills from this computer towards UBC, and in
    // full tunnel the lane on from UBC follows it down. Leaving, the lane on
    // from UBC goes first.
    const fill = on
        ? { duration: duration.slow, ease: easeOut }
        : { duration: duration.fast, ease: easeOut };
    return (
        <svg
            viewBox="0 0 340 150"
            aria-hidden
            data-mode={mode}
            className={cn("w-full font-ui text-caption", className)}
            fill="none"
            strokeLinecap="round"
        >
            <path d={LOCAL} className="stroke-text-tertiary" strokeWidth={1.5} />
            {/* Split only: the lower lane carries on to everything else. It
                draws back to the local network as full tunnel takes over. */}
            <motion.path
                d={REST}
                className="stroke-text-tertiary"
                strokeWidth={1.5}
                initial={false}
                animate={{ pathLength: full ? 0 : 1, opacity: full ? 0 : 1 }}
                transition={{ duration: duration.slow, ease: easeOut }}
            />
            <path
                d={TUNNEL}
                strokeWidth={7}
                className={cn(
                    "transition-[stroke] duration-(--dur-base) ease-out",
                    lane[held ? "on" : tone],
                )}
            />
            {/* Full only: the lane on from UBC to everything else. */}
            <path
                d={ONWARD}
                strokeWidth={4}
                className={cn(
                    "transition-[stroke,opacity] duration-(--dur-base) ease-out",
                    lane[held ? "on" : tone],
                    full ? "opacity-100" : "opacity-0",
                )}
            />
            <motion.path
                d={TUNNEL}
                strokeWidth={7}
                className="stroke-positive"
                initial={false}
                animate={{ pathLength: on ? 1 : 0, opacity: on ? 1 : 0 }}
                transition={on ? fill : { ...fill, delay: full ? duration.fast : 0 }}
            />
            <motion.path
                d={ONWARD}
                strokeWidth={4}
                className="stroke-positive"
                initial={false}
                animate={{ pathLength: on && full ? 1 : 0, opacity: on && full ? 1 : 0 }}
                // After the tunnel when connecting; at once when switching.
                transition={{ ...fill, delay: on && full ? duration.fast : 0 }}
            />
            {/* Working: a pulse travels from this computer to UBC, and in
                full tunnel on to everything else, entering and leaving under
                the dots. It fades in and out with the state. Without motion it
                rests part of the way along. */}
            <Pulse d={TUNNEL} mode="split" shown={busy && !full} />
            <Pulse d={THROUGH_UBC} mode="full" shown={busy && full} />
            <circle cx={22} cy={75} r={8} className="fill-text" />
            <circle
                cx={318}
                cy={32}
                r={8}
                strokeWidth={2.5}
                className={cn("transition-[fill,stroke] duration-(--dur-base) ease-out", ubc[tone])}
            />
            <circle cx={318} cy={118} r={3.5} className="fill-text-tertiary" />
            {/* Full only: where the lower lane now ends. */}
            <circle
                cx={224}
                cy={118}
                r={3.5}
                className={cn("fill-text-tertiary", fade, full ? "opacity-100" : "opacity-0")}
            />
            <g className="fill-text-secondary" stroke="none">
                <text x={12} y={106}>
                    This computer
                </text>
                <g className={cn(fade, full ? "opacity-0" : "opacity-100")}>
                    <text x={300} y={16} textAnchor="end">
                        UBC subnets
                    </text>
                    <text x={300} y={140} textAnchor="end">
                        Everything else
                    </text>
                </g>
                <g className={cn(fade, full ? "opacity-100" : "opacity-0")}>
                    <text x={300} y={16} textAnchor="end">
                        UBC
                    </text>
                    <text x={300} y={140} textAnchor="end">
                        Everything else, through UBC
                    </text>
                    <text x={224} y={104} textAnchor="middle">
                        Local network
                    </text>
                </g>
            </g>
        </svg>
    );
}
