import { MotionConfig } from "motion/react";
import { lazy, Suspense, useState } from "react";
import { TitleBar } from "@/components/title-bar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { type View, ViewSwitcher } from "@/components/view-switcher";
import { ConnectionView } from "@/views/connection-view";

// The app's screens. Routes, settings and the log will be added here; the
// switcher in the title bar appears once there is more than one.
const views: View[] = [
    { id: "connection", label: "Connection", Component: ConnectionView },
    // Demo builds only: a second screen showing every component.
    ...(__DEMO__
        ? [
              {
                  id: "components",
                  label: "Components",
                  Component: lazy(() => import("@/demo/gallery-view")),
              },
          ]
        : []),
];

export function App() {
    const [current, setCurrent] = useState("connection");
    const Current = (views.find((view) => view.id === current) ?? views[0])?.Component;

    return (
        // Movement is dropped, and fades kept, for anyone who asks for less motion.
        <MotionConfig reducedMotion="user">
            <TooltipProvider>
                <div className="flex h-full flex-col">
                    <TitleBar>
                        <ViewSwitcher views={views} current={current} onChange={setCurrent} />
                    </TitleBar>
                    <Suspense>{Current !== undefined && <Current show={setCurrent} />}</Suspense>
                </div>
            </TooltipProvider>
        </MotionConfig>
    );
}
