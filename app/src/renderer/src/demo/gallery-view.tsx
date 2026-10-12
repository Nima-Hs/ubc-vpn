// DEMO ONLY. Shows every shared component in every state, and lets the fake
// service be put into any state. Loaded only behind `__DEMO__`, so it is not
// part of a production build.

import { Plus, Settings, Trash2 } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { List, ListRow } from "@/components/ui/list-row";
import { Panel } from "@/components/ui/panel";
import { StatusIndicator } from "@/components/ui/status-indicator";
import { Subheading, Text } from "@/components/ui/text";
import { TextField } from "@/components/ui/text-field";
import { api } from "@/lib/store";

const variants = ["primary", "secondary", "quiet", "destructive"] as const;

function Section({ title, children }: { title: string; children: ReactNode }) {
    return (
        <section className="flex flex-col gap-3">
            <Subheading>{title}</Subheading>
            {children}
        </section>
    );
}

export default function GalleryView({ show }: { show(id: string): void }) {
    const [scenarios, setScenarios] = useState<string[]>([]);
    useEffect(() => {
        void api.demo?.listScenarios().then(setScenarios);
    }, []);

    return (
        <main className="scroll-region flex min-h-0 flex-1 flex-col gap-7 px-5 pb-5">
            <Section title="Show a state">
                <div className="flex flex-wrap gap-1.5">
                    {scenarios.map((name) => (
                        <Button
                            key={name}
                            size="sm"
                            onClick={() => {
                                void api.demo?.setScenario(name);
                                show("connection");
                            }}
                        >
                            {name}
                        </Button>
                    ))}
                </div>
            </Section>

            <Section title="Buttons">
                {variants.map((variant) => (
                    <div key={variant} className="flex flex-wrap items-center gap-2">
                        <Button variant={variant}>
                            {variant === "destructive" ? "Delete route" : "Connect"}
                        </Button>
                        <Button variant={variant} loading>
                            Working
                        </Button>
                        <Button variant={variant} disabled>
                            Unavailable
                        </Button>
                    </div>
                ))}
                <div className="flex items-center gap-2">
                    <Button size="sm" icon={<Plus aria-hidden className="size-4" />}>
                        Add subnet
                    </Button>
                    <Button size="md">Medium</Button>
                    <Button size="lg" variant="primary">
                        Large
                    </Button>
                </div>
                <div className="flex items-center gap-1">
                    <IconButton label="Open settings" tooltipSide="top">
                        <Settings />
                    </IconButton>
                    <IconButton label="Delete route" tone="danger" tooltipSide="top">
                        <Trash2 />
                    </IconButton>
                </div>
            </Section>

            <Section title="Status">
                <div className="flex flex-wrap gap-x-5 gap-y-2">
                    <StatusIndicator tone="idle" label="Not connected" />
                    <StatusIndicator tone="busy" label="Connecting" />
                    <StatusIndicator tone="on" label="Connected" />
                    <StatusIndicator tone="attention" label="Log in again" />
                    <StatusIndicator tone="problem" label="Tunnel failed" />
                </div>
            </Section>

            <Section title="Text fields">
                <TextField
                    label="Subnet"
                    placeholder="203.0.113.0/24"
                    hint="An IPv4 subnet, no wider than /8."
                />
                <TextField
                    label="Subnet"
                    defaultValue="203.0.113.0/4"
                    error="Use a prefix of /8 or longer, such as 203.0.0.0/8."
                />
                <TextField label="Subnet" defaultValue="203.0.113.0/24" disabled />
            </Section>

            <Section title="Panels and rows">
                <Panel>
                    <List>
                        <ListRow label="Your VPN address" data>
                            198.51.100.42
                        </ListRow>
                        <ListRow label="Subnets through the VPN" stacked data>
                            203.0.113.0/24
                        </ListRow>
                    </List>
                </Panel>
                <Panel tone="attention">
                    <Text>A message the user should not miss.</Text>
                </Panel>
                <Panel tone="problem">
                    <Text>A problem, with what to do about it.</Text>
                </Panel>
            </Section>

            <Section title="Type">
                <Text>Body: traffic to 2 UBC subnets goes through the VPN.</Text>
                <Text size="label" tone="secondary">
                    Label: subnets through the VPN
                </Text>
                <Text size="caption" tone="tertiary">
                    Caption: an IPv4 subnet, no wider than /8.
                </Text>
                <Text data size="label">
                    Data: 203.0.113.0/24 0123456789
                </Text>
            </Section>
        </main>
    );
}
