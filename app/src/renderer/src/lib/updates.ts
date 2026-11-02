// Where updates stand, as the main process says: read once, then kept as
// it tells the window after every change.

import type { UpdateView } from "@shared/updates";
import { useEffect, useState } from "react";
import { api } from "@/lib/store";

/** The update view, or `null` until the main process has answered. */
export function useUpdates(): UpdateView | null {
    const [view, setView] = useState<UpdateView | null>(null);
    useEffect(() => {
        let current = true;
        const stop = api.updates.onChange((next) => {
            if (current) {
                setView(next);
            }
        });
        void api.updates.get().then((first) => {
            if (current) {
                setView((before) => before ?? first);
            }
        });
        return () => {
            current = false;
            stop();
        };
    }, []);
    return view;
}
