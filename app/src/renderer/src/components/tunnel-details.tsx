import { DETAILS, describeLeftOut } from "@shared/copy";
import type { TunnelInfo } from "@shared/protocol/TunnelInfo";
import { type ReactNode, useId, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { List, ListRow } from "@/components/ui/list-row";
import { Panel } from "@/components/ui/panel";
import { type ShownSubnet, summariseSubnets } from "@/lib/route-summary";

/** A labelled group of entries, one per row, with how many there are. */
function Group({
    title,
    count,
    footer,
    listId,
    children,
}: {
    title: string;
    count: string;
    footer?: ReactNode;
    listId?: string;
    children: ReactNode;
}) {
    const id = useId();
    return (
        <section aria-labelledby={id} className="border-t border-border">
            {/* Stays in view while its rows scroll under it, so a long list keeps its name. */}
            <div className="sticky top-0 flex items-baseline justify-between gap-4 border-b border-border bg-surface px-4 pt-3 pb-2">
                <h2 id={id} className="text-label text-text-secondary">
                    {title}
                </h2>
                <span className="shrink-0 text-caption text-text-tertiary tabular-nums">
                    {count}
                </span>
            </div>
            <ul
                id={listId}
                // An address is not a word: translation tools must leave it alone.
                translate="no"
                className="select-text divide-y divide-border font-data text-label text-text"
            >
                {children}
            </ul>
            {footer}
        </section>
    );
}

function Entry({ children }: { children: ReactNode }) {
    return <li className="px-4 py-2 wrap-anywhere">{children}</li>;
}

function NoEntries() {
    return (
        <Entry>
            <span className="font-ui text-text-tertiary">{DETAILS.none}</span>
        </Entry>
    );
}

/** A subnet: the address in full strength, the prefix after it quieter. */
function Subnet({ subnet }: { subnet: string }) {
    const slash = subnet.lastIndexOf("/");
    if (slash < 0) {
        return <span>{subnet}</span>;
    }
    return (
        <>
            <span>{subnet.slice(0, slash)}</span>
            <span className="text-text-tertiary">{subnet.slice(slash)}</span>
        </>
    );
}

function SubnetEntry({ entry }: { entry: ShownSubnet }) {
    return (
        <Entry>
            <Subnet subnet={entry.subnet} />
            {entry.parts.length > 1 && (
                <span className="block pt-0.5 font-ui text-caption text-text-tertiary">
                    {describeLeftOut(entry.parts.length, entry.leftOut, entry.leftOutCount)}
                </span>
            )}
        </Entry>
    );
}

/**
 * What a connected tunnel carries: the address it was given, the subnets
 * routed through it and the domains looked up through it. Each in a group of
 * its own, one entry per row. A range saved in pieces is shown whole, with the
 * saved subnets one press away.
 */
export function TunnelDetails({ tunnel }: { tunnel: TunnelInfo }) {
    const { subnets, dns_domains: domains } = tunnel;
    const full = tunnel.mode === "full";
    const combined = useMemo(() => summariseSubnets(subnets), [subnets]);
    const canCombine = combined.length < subnets.length;
    const [showEach, setShowEach] = useState(false);
    const listId = useId();
    const shown: ShownSubnet[] =
        canCombine && !showEach
            ? combined
            : subnets.map((subnet) => ({ subnet, parts: [subnet], leftOut: [], leftOutCount: 0 }));

    return (
        <Panel scrollLabel={DETAILS.label}>
            <List>
                <ListRow label={DETAILS.address} data compact>
                    {tunnel.address}
                </ListRow>
                {/* Full tunnel: everything goes through, not only the lists below. */}
                {full && (
                    <ListRow label={DETAILS.traffic} compact>
                        {DETAILS.allTraffic}
                    </ListRow>
                )}
            </List>
            <Group
                title={full ? DETAILS.subnetsFull : DETAILS.subnets}
                count={DETAILS.subnetCount(subnets.length)}
                listId={listId}
                footer={
                    canCombine && (
                        <div className="border-t border-border px-2 py-1.5">
                            <Button
                                variant="quiet"
                                size="sm"
                                aria-controls={listId}
                                onClick={() => setShowEach((each) => !each)}
                            >
                                {showEach ? DETAILS.showCombined : DETAILS.showEach(subnets.length)}
                            </Button>
                        </div>
                    )
                }
            >
                {subnets.length === 0 ? (
                    <NoEntries />
                ) : (
                    shown.map((entry, index) => (
                        // A subnet may be saved twice; its place tells the two apart.
                        <SubnetEntry key={`${index}-${entry.subnet}`} entry={entry} />
                    ))
                )}
            </Group>
            <Group
                title={full ? DETAILS.domainsFull : DETAILS.domains}
                count={DETAILS.domainCount(domains.length)}
            >
                {domains.length === 0 ? (
                    <NoEntries />
                ) : (
                    domains.map((domain, index) => (
                        <Entry key={`${index}-${domain}`}>{domain}</Entry>
                    ))
                )}
            </Group>
        </Panel>
    );
}
