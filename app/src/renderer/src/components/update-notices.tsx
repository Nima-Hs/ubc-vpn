import { describeAfterUpdate, UPDATES } from "@shared/settings-copy";
import type { UpdateView } from "@shared/updates";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { Text } from "@/components/ui/text";
import { api } from "@/lib/store";

/**
 * What the app has to say after an update it started, such as that it did not
 * finish, or why it did not reconnect. Shown on the first screen, where the user
 * looks for the connection, and in Settings, until it is dismissed or a
 * connection is made.
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
                <div className="mt-2 flex">
                    <Button size="sm" onClick={() => void api.updates.dismiss()}>
                        {UPDATES.dismiss}
                    </Button>
                </div>
            </Panel>
        </div>
    );
}
