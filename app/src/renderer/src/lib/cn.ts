import { type ClassValue, clsx } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

// tailwind-merge has to be told the design system's type sizes, or it takes
// `text-body` for a colour and drops a real colour class next to it.
const merge = extendTailwindMerge({
    extend: {
        classGroups: {
            "font-size": [{ text: ["caption", "label", "body", "title", "display"] }],
        },
    },
});

/** Joins class names, letting a later one override an earlier one. */
export function cn(...inputs: ClassValue[]): string {
    return merge(clsx(inputs));
}
