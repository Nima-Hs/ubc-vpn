import { MotionConfig } from "motion/react";
import { lazy, Suspense } from "react";
import { DevelopmentMark } from "@/components/development-mark";
import { TitleBar } from "@/components/title-bar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { type View, ViewSwitcher } from "@/components/view-switcher";
import { show, useNavigation } from "@/lib/navigation";
import { ConnectionView } from "@/views/connection-view";
import { RoutesView } from "@/views/routes-view";

// The app's screens, in the order the switcher in the title bar shows them.
// Settings and the log will be added here.
const views: View[] = [
    { id: "connection", label: "Connection", Component: ConnectionView },
    { id: "routes", label: "Routes", Component: RoutesView },
    // Demo builds only: a screen showing every component.
    ...(__DEMO__
        ? [
              {
                  id: "components",
                  label: "Parts",
                  Component: lazy(() => import("@/demo/gallery-view")),
              },
          ]
        : []),
];

export function App() {
    const current = useNavigation((navigation) => navigation.current);
    const Current = (views.find((view) => view.id === current) ?? views[0])?.Component;

    return (
        // Movement is dropped, and fades kept, for anyone who asks for less motion.
        <MotionConfig reducedMotion="user">
            <TooltipProvider>
                <div className="flex h-full flex-col">
                    <TitleBar crowded={views.length > 2}>
                        <ViewSwitcher views={views} current={current} onChange={show} />
                    </TitleBar>
                    <DevelopmentMark />
                    <Suspense>{Current !== undefined && <Current show={show} />}</Suspense>
                </div>
            </TooltipProvider>
        </MotionConfig>
    );
}
