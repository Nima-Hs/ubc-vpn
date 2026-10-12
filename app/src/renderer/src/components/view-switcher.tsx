import type { ComponentType } from "react";
import { cn } from "@/lib/cn";
import { pressable } from "./ui/button";

/** A screen the app can show. Add one to the list in `App.tsx`. */
export interface View {
    id: string;
    label: string;
    /** `show` switches to another screen by its id. */
    Component: ComponentType<{ show(id: string): void }>;
}

/**
 * Switches between the app's screens: a row of its own under the title bar,
 * with every screen named. The screens share the row equally, and it is
 * sized so that four fit with the longest name ("Connection") whole. With a
 * single screen there is nothing to switch, so it draws nothing.
 */
export function ViewSwitcher({
    views,
    current,
    onChange,
}: {
    views: readonly View[];
    current: string;
    onChange(id: string): void;
}) {
    if (views.length < 2) {
        return null;
    }
    return (
        <nav aria-label="Screens" className="no-drag shrink-0 px-5 pb-2">
            <div className="flex gap-0.5 rounded-md bg-surface p-0.5">
                {views.map((view) => (
                    <button
                        key={view.id}
                        type="button"
                        aria-current={view.id === current ? "page" : undefined}
                        onClick={() => onChange(view.id)}
                        className={cn(
                            pressable,
                            "h-control-xs min-w-0 flex-1 truncate rounded-sm px-1 text-label text-text-secondary hover:text-text",
                            "aria-[current]:bg-control-hover aria-[current]:text-text aria-[current]:shadow-control",
                        )}
                    >
                        {view.label}
                    </button>
                ))}
            </div>
        </nav>
    );
}
