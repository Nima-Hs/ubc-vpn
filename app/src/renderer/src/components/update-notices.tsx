import { describeAfterUpdate } from "@shared/settings-copy";
import type { UpdateView } from "@shared/updates";
import { Panel } from "@/components/ui/panel";
import { Text } from "@/components/ui/text";

/**
 * What the app has to say after an update it started, such as that it did not
 * finish, or why it did not reconnect. Shown on the first screen, where the user
 * looks for the connection, and in Settings.
 */
export function UpdateNotices({ view }: { view: UpdateView | null }) {
    if (view === null || view.after.length === 0) {
        return null;
    }
    return (
        <div role="status" className="shrink-0">
            <Panel tone="attention">
                {view.after.map((notice) => (
                    <Text key={notice}>{describeAfterUpdate(notice)}</Text>
                ))}
            </Panel>
        </div>
    );
}
