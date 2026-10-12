import { DEVELOPMENT_MODE } from "@shared/copy";
import { FlaskConical } from "lucide-react";
import { useSnapshot } from "@/lib/store";

/**
 * Says, on every screen and for as long as it is so, that the app is talking
 * to a dev-mode service and not the real VPN. Nothing can dismiss it.
 */
export function DevelopmentMark() {
    const development = useSnapshot((snapshot) => snapshot.development);
    if (!development) {
        return null;
    }
    return (
        <p className="flex shrink-0 items-center justify-center gap-1.5 bg-attention-subtle px-4 py-1 text-caption text-text">
            <FlaskConical aria-hidden className="size-3 shrink-0 text-attention" />
            {DEVELOPMENT_MODE}
        </p>
    );
}
