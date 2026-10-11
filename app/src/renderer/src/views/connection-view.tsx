import { type ActionKind, describe, describeActionError } from "@shared/copy";
import type { TunnelInfo } from "@shared/protocol/TunnelInfo";
import { TunnelDiagram } from "@/components/tunnel-diagram";
import { Button } from "@/components/ui/button";
import { List, ListRow } from "@/components/ui/list-row";
import { Panel } from "@/components/ui/panel";
import { StatusIndicator } from "@/components/ui/status-indicator";
import { Heading, Text } from "@/components/ui/text";
import { api, useSnapshot } from "@/lib/store";

const run: Record<ActionKind, () => Promise<void>> = {
    connect: () => api.connect(),
    disconnect: () => api.disconnect(),
    retry: () => api.retry(),
};

function Entries({ items }: { items: readonly string[] }) {
    if (items.length === 0) {
        return "None";
    }
    return (
        <ul className="grid grid-cols-2 gap-x-4 gap-y-1">
            {items.map((item) => (
                <li key={item}>{item}</li>
            ))}
        </ul>
    );
}

function TunnelDetails({ tunnel }: { tunnel: TunnelInfo }) {
    return (
        <Panel className="flex max-h-full flex-col overflow-hidden">
            <List className="scroll-region">
                <ListRow label="Your VPN address" data>
                    {tunnel.address}
                </ListRow>
                <ListRow label="Subnets through the VPN" stacked data>
                    <Entries items={tunnel.subnets} />
                </ListRow>
                <ListRow label="Domains looked up through the VPN" stacked data>
                    <Entries items={tunnel.dns_domains} />
                </ListRow>
            </List>
        </Panel>
    );
}

/** The app's first screen: where the connection stands, and one thing to do about it. */
export function ConnectionView() {
    const { state, notice } = useSnapshot();
    const copy = describe(state);
    const { action } = copy;
    const tunnel =
        state.link === "ready" && state.conn.state === "connected" ? state.conn.tunnel : null;
    const noticeText = notice === null ? null : describeActionError(notice);

    return (
        <main className="flex min-h-0 flex-1 flex-col gap-5 px-5 pt-2 pb-5">
            <TunnelDiagram tone={copy.tone} className="shrink-0" />

            {/* The words change the instant the state does; only their arrival is animated. */}
            <section key={copy.title} className="flex shrink-0 animate-arrive flex-col gap-2">
                <div className="flex items-center gap-3">
                    <StatusIndicator tone={copy.tone} size="lg" />
                    <Heading>{copy.title}</Heading>
                </div>
                <Text tone="secondary">{copy.body}</Text>
            </section>

            {/* Read out, politely, whenever the state or the notice changes. */}
            <p role="status" className="sr-only">
                {copy.title}. {copy.body} {noticeText}
            </p>

            <div className="flex min-h-0 flex-1 flex-col">
                {tunnel !== null && <TunnelDetails tunnel={tunnel} />}
                {copy.detail !== undefined && (
                    <Panel
                        tone="problem"
                        className="scroll-region flex max-h-full flex-col gap-1 px-4 py-3"
                    >
                        <Text size="label" tone="secondary">
                            The VPN service reported
                        </Text>
                        <Text selectable>{copy.detail}</Text>
                    </Panel>
                )}
            </div>

            {noticeText !== null && (
                <Panel tone="attention" className="shrink-0 px-4 py-3">
                    <Text>{noticeText}</Text>
                </Panel>
            )}

            {action !== null && (
                <Button
                    block
                    size="lg"
                    // Connect is the one filled button. Everything else is neutral.
                    variant={action.kind === "connect" ? "primary" : "secondary"}
                    loading={copy.working}
                    onClick={() => void run[action.kind]()}
                    className="shrink-0"
                >
                    {action.label}
                </Button>
            )}
        </main>
    );
}
