import {
    type ActionKind,
    describe,
    describeActionError,
    loginAnnouncement,
    loginHasScreen,
} from "@shared/copy";
import { useEffect, useRef } from "react";
import { ProfileSwitcher } from "@/components/profile-switcher";
import { TunnelOutcome, TunnelSwitch, useTunnelOutcomeText } from "@/components/tunnel-choice";
import { TunnelDetails } from "@/components/tunnel-details";
import { TunnelDiagram } from "@/components/tunnel-diagram";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { StatusIndicator } from "@/components/ui/status-indicator";
import { Heading, Text } from "@/components/ui/text";
import { cn } from "@/lib/cn";
import { api, useSnapshot } from "@/lib/store";
import { LoginView } from "./login-view";

const run: Record<ActionKind, () => Promise<void>> = {
    connect: () => api.connect(),
    disconnect: () => api.disconnect(),
    retry: () => api.retry(),
};

/** The app's first screen: where the connection stands, and one thing to do about it. */
export function ConnectionView() {
    const { state, notice, login, tunnel: tunnelStatus } = useSnapshot();
    const copy = describe(state, tunnelStatus);
    const outcomeText = useTunnelOutcomeText();
    const { action } = copy;
    const tunnel =
        state.link === "ready" && state.conn.state === "connected" ? state.conn.tunnel : null;
    const noticeCopy = notice === null ? null : describeActionError(notice);
    const loggingIn = loginHasScreen(state, login);

    // When a login ends, the keyboard goes back to the one button, so the
    // next key press does something and focus is never left on nothing.
    const actionButton = useRef<HTMLButtonElement>(null);
    const wasLoggingIn = useRef(false);
    useEffect(() => {
        if (wasLoggingIn.current && !loggingIn) {
            actionButton.current?.focus();
        }
        wasLoggingIn.current = loggingIn;
    }, [loggingIn]);

    if (loggingIn && login.phase !== "idle") {
        return (
            <main className="scroll-region flex min-h-0 flex-1 flex-col gap-5 px-5 pt-2 pb-5">
                <TunnelDiagram
                    tone={login.phase === "failed" ? "problem" : "busy"}
                    mode={copy.mode}
                    className="shrink-0"
                />
                <LoginView login={login} />
                {/* Read out, politely, as the login moves on. */}
                <p role="status" className="sr-only">
                    {loginAnnouncement(login)}
                </p>
            </main>
        );
    }

    return (
        <main className="scroll-region flex min-h-0 flex-1 flex-col gap-5 px-5 pt-2 pb-5">
            <TunnelDiagram
                tone={copy.tone}
                mode={copy.mode}
                held={tunnel !== null && tunnelStatus.switching !== null}
                className="shrink-0"
            />

            {/* The words change the instant the state does; only their arrival is animated. */}
            <section key={copy.title} className="flex shrink-0 animate-arrive flex-col gap-2">
                <div className="flex items-center gap-3">
                    <StatusIndicator tone={copy.tone} size="lg" />
                    <Heading>{copy.title}</Heading>
                </div>
                <Text tone="secondary">{copy.body}</Text>
            </section>

            {/* Split or full, for every profile: switched in place while connected. */}
            <TunnelSwitch />
            {/* What came of the last switch, right under it, when it did not go as asked. */}
            <TunnelOutcome />

            {/* Which profile Connect uses, when there is more than one. */}
            <ProfileSwitcher />

            {/* Read out, politely, whenever the state, the notice or a switch's outcome changes. */}
            <p role="status" className="sr-only">
                {copy.title}. {copy.body} {noticeCopy?.text} {outcomeText}
            </p>

            {/* With something in it, keeps a minimum height, so when the text is
                zoomed past what the window can hold, the screen scrolls and the
                button stays reachable. Empty, it takes only the room left over. */}
            <div
                className={cn(
                    "flex flex-1 flex-col",
                    (tunnel !== null || copy.detail !== undefined) && "min-h-24",
                )}
            >
                {tunnel !== null && <TunnelDetails tunnel={tunnel} />}
                {copy.detail !== undefined && (
                    <Panel tone="problem" scrollLabel="What the VPN service reported">
                        <Text size="label" tone="secondary">
                            The VPN service reported
                        </Text>
                        <Text selectable>{copy.detail}</Text>
                    </Panel>
                )}
            </div>

            {noticeCopy !== null && (
                <Panel tone="attention" className="shrink-0">
                    <Text>{noticeCopy.text}</Text>
                    {noticeCopy.detail !== undefined && (
                        <Text size="label" tone="secondary" selectable>
                            {noticeCopy.detail}
                        </Text>
                    )}
                </Panel>
            )}

            {action !== null && (
                <Button
                    ref={actionButton}
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
