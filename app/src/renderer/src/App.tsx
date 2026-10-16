import { MotionConfig } from "motion/react";
import { lazy, Suspense } from "react";
import { DevelopmentMark } from "@/components/development-mark";
import { TitleBar } from "@/components/title-bar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { type View, ViewSwitcher } from "@/components/view-switcher";
import { show, useNavigation } from "@/lib/navigation";
import { ConnectionView } from "@/views/connection-view";
import { RoutesView } from "@/views/routes-view";

// The app's screens, in the order the switcher shows them. The switcher's
// row has room for four, and four is what there are.
const views: View[] = [
    { id: "connection", label: "Connection", Component: ConnectionView },
    { id: "routes", label: "Routes", Component: RoutesView },
    // The service's log. Not in a production build yet: see `__LOGS__`.
    ...(__LOGS__
        ? [{ id: "logs", label: "Logs", Component: lazy(() => import("@/views/logs-view")) }]
        : []),
    // How the app starts, and the saved password. See `__SETTINGS__`.
    ...(__SETTINGS__
        ? [
              {
                  id: "settings",
                  label: "Settings",
                  Component: lazy(() => import("@/views/settings-view")),
              },
          ]
        : []),
];

// Demo builds only: a screen showing every component. Not a fifth tab, which
// the row has no room for: a button in the title bar opens it.
const gallery: View | null = __DEMO__
    ? { id: "components", label: "Parts", Component: lazy(() => import("@/demo/gallery-view")) }
    : null;

export function App() {
    const current = useNavigation((navigation) => navigation.current);
    const Current = (
        [...views, ...(gallery === null ? [] : [gallery])].find((view) => view.id === current) ??
        views[0]
    )?.Component;

    return (
        // Movement is dropped, and fades kept, for anyone who asks for less motion.
        <MotionConfig reducedMotion="user">
            <TooltipProvider>
                <div className="flex h-full flex-col">
                    <TitleBar {...(gallery !== null && { onGallery: () => show(gallery.id) })} />
                    {/* Directly under the title bar, above everything else. */}
                    <DevelopmentMark />
                    <ViewSwitcher views={views} current={current} onChange={show} />
                    <Suspense>{Current !== undefined && <Current show={show} />}</Suspense>
                </div>
            </TooltipProvider>
        </MotionConfig>
    );
}
