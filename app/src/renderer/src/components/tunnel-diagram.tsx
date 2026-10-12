import type { Tone } from "@shared/copy";
import { motion } from "motion/react";
import { cn } from "@/lib/cn";
import { duration, easeOut } from "@/lib/motion";

// The app's one picture: this computer on the left, and the two ways its
// traffic can go. The upper lane is the tunnel to UBC, which fills when the
// VPN is on. The lower lane is the normal connection, which is always there.
// That is split tunnelling, and it is what the user is switching on and off.

const TUNNEL = "M 22 75 C 124 75 122 32 224 32 L 318 32";
const DIRECT = "M 22 75 C 124 75 122 118 224 118 L 318 118";

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

/** Decorative: the words beside it always say the same thing. */
export function TunnelDiagram({ tone, className }: { tone: Tone; className?: string }) {
    return (
        <svg
            viewBox="0 0 340 150"
            aria-hidden
            className={cn("w-full font-ui text-caption", className)}
            fill="none"
            strokeLinecap="round"
        >
            <path d={DIRECT} className="stroke-text-tertiary" strokeWidth={1.5} />
            <path
                d={TUNNEL}
                strokeWidth={7}
                className={cn("transition-[stroke] duration-(--dur-base) ease-out", lane[tone])}
            />
            {/* Connected: the tunnel fills from this computer towards UBC. */}
            <motion.path
                d={TUNNEL}
                strokeWidth={7}
                className="stroke-positive"
                initial={false}
                animate={{ pathLength: tone === "on" ? 1 : 0, opacity: tone === "on" ? 1 : 0 }}
                transition={
                    tone === "on"
                        ? { duration: duration.slow, ease: easeOut }
                        : { duration: duration.fast, ease: easeOut }
                }
            />
            {/* Working: a pulse travels along the tunnel. Without motion it rests mid-way. */}
            {tone === "busy" && (
                <path
                    d={TUNNEL}
                    pathLength={1}
                    strokeWidth={7}
                    strokeDasharray="0.16 0.84"
                    strokeDashoffset={-0.42}
                    className="stroke-accent motion-safe:animate-flow"
                />
            )}
            <circle cx={22} cy={75} r={8} className="fill-text" />
            <circle
                cx={318}
                cy={32}
                r={8}
                strokeWidth={2.5}
                className={cn("transition-[fill,stroke] duration-(--dur-base) ease-out", ubc[tone])}
            />
            <circle cx={318} cy={118} r={3.5} className="fill-text-tertiary" />
            <g className="fill-text-secondary" stroke="none">
                <text x={12} y={106}>
                    This computer
                </text>
                <text x={300} y={16} textAnchor="end">
                    UBC subnets
                </text>
                <text x={300} y={140} textAnchor="end">
                    Everything else
                </text>
            </g>
        </svg>
    );
}
