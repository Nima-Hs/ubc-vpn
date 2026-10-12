import { LOGS } from "@shared/copy";
import { type LogView, MAX_LOG_LINES, type ReportResult, type ShownLine } from "@shared/logs";
import { useEffect, useState } from "react";
import { LogList } from "@/components/log-list";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { Heading, Text } from "@/components/ui/text";
import { api } from "@/lib/store";

type Held = { state: "loading" } | ({ state: "ready" } & LogView);

/** Adds new lines to those held: each number once, in order, and no more than the limit. */
function add(held: readonly ShownLine[], lines: readonly ShownLine[]): ShownLine[] {
    const last = held.at(-1)?.seq ?? -1;
    return [...held, ...lines.filter((line) => line.seq > last)].slice(-MAX_LOG_LINES);
}

/** The Logs screen: what the service has done, and a report to copy for whoever is helping. */
export default function LogsView() {
    const [held, setHeld] = useState<Held>({ state: "loading" });
    const [attempt, setAttempt] = useState(0);
    // The report: not asked for, being asked about, or what copying came to.
    const [report, setReport] = useState<"idle" | "asking" | "copying" | ReportResult>("idle");

    useEffect(() => {
        const logs = api.logs;
        if (logs === undefined) {
            return;
        }
        let current = true;
        const stop = logs.onUpdate((update) => {
            setHeld((before) =>
                before.state !== "ready"
                    ? before
                    : {
                          state: "ready",
                          available: update.available,
                          dropped: update.dropped,
                          lines: add(update.reset ? [] : before.lines, update.lines),
                      },
            );
        });
        void logs.open().then((view) => {
            if (current) {
                setHeld({ state: "ready", ...view, lines: view.lines.slice(-MAX_LOG_LINES) });
            }
        });
        return () => {
            current = false;
            stop();
            void logs.close();
        };
    }, [attempt]);

    const copy = async () => {
        setReport("copying");
        setReport((await api.logs?.copyReport()) ?? { ok: false });
    };

    const lines = held.state === "ready" ? held.lines : [];
    return (
        <main className="flex min-h-0 flex-1 flex-col gap-4 px-5 pt-2 pb-5">
            <section className="flex shrink-0 flex-col gap-2">
                <Heading>{LOGS.title}</Heading>
                <Text tone="secondary">{LOGS.body}</Text>
            </section>

            {held.state === "loading" && (
                <div role="status" className="flex min-h-0 flex-1 flex-col">
                    <Text tone="tertiary">{LOGS.loading}</Text>
                </div>
            )}
            {held.state === "ready" && !held.available && lines.length === 0 && (
                <div className="flex min-h-0 flex-1 flex-col gap-3">
                    <Panel tone="problem" className="shrink-0">
                        <Text>{LOGS.unavailable}</Text>
                    </Panel>
                    <div className="flex">
                        <Button size="sm" onClick={() => setAttempt((before) => before + 1)}>
                            Try again
                        </Button>
                    </div>
                </div>
            )}
            {held.state === "ready" && held.available && lines.length === 0 && (
                <div className="flex min-h-0 flex-1 flex-col">
                    <Text tone="tertiary">{LOGS.empty}</Text>
                </div>
            )}
            {lines.length > 0 && (
                <>
                    {held.state === "ready" && held.dropped && (
                        <Text size="label" tone="tertiary" className="shrink-0">
                            {LOGS.dropped}
                        </Text>
                    )}
                    <LogList lines={lines} className="flex-1" />
                </>
            )}

            <div className="flex shrink-0 flex-col gap-3">
                {report === "asking" && (
                    // Read out as it appears: what the report holds comes
                    // before the button that copies it.
                    <div role="alert">
                        <Panel tone="attention">
                            <Text>{LOGS.reportHolds}</Text>
                            <div className="flex gap-2 pt-1">
                                {/* The question takes the keyboard, so it cannot be missed. */}
                                <Button
                                    size="sm"
                                    ref={(button) => button?.focus()}
                                    onClick={() => void copy()}
                                >
                                    {LOGS.copyNow}
                                </Button>
                                <Button size="sm" variant="quiet" onClick={() => setReport("idle")}>
                                    Cancel
                                </Button>
                            </div>
                        </Panel>
                    </div>
                )}
                {typeof report === "object" && !report.ok && (
                    <Panel tone="problem">
                        <Text>{LOGS.reportFailed}</Text>
                    </Panel>
                )}
                <Button
                    block
                    size="lg"
                    loading={report === "copying"}
                    disabled={report === "asking"}
                    onClick={() => setReport("asking")}
                >
                    {LOGS.copyReport}
                </Button>
                {/* Said, and shown: what copying came to. The line is always there. */}
                <div role="status" className="flex min-h-5 justify-center">
                    <Text size="label" tone="tertiary">
                        {typeof report === "object" && report.ok
                            ? LOGS.reportCopied(report.lines)
                            : null}
                    </Text>
                </div>
            </div>
        </main>
    );
}
