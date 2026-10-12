import type { connectCommand } from "./channel/cli";
import { ConnectRunner } from "./channel/connect";
import type { LoginFactory } from "./controller";
import type { ServiceLink } from "./link";

/**
 * Asks the service to disconnect, for a login the user gave up after the
 * service had taken it. If the service cannot be reached just now, the
 * request is sent once more, when the bridge is next ready: once, and not
 * in a loop. The promise ends when the request has been sent, so until then
 * the login is not shown as given up.
 */
export async function disconnectForCancel(
    link: Pick<ServiceLink, "disconnect" | "getState" | "subscribe">,
): Promise<void> {
    const first = await link.disconnect();
    if (first.ok || first.error.kind !== "service_unavailable") {
        return;
    }
    await new Promise<void>((resolve) => {
        if (link.getState().link === "ready") {
            resolve();
            return;
        }
        const stop = link.subscribe((state) => {
            if (state.link === "ready") {
                stop();
                resolve();
            }
        });
    });
    await link.disconnect();
}

/**
 * How the installed app logs in: the command-line client, with the link to
 * the service to undo a login that was given up too late.
 */
export function clientLogin(
    link: Pick<ServiceLink, "disconnect" | "getState" | "subscribe">,
    command: ReturnType<typeof connectCommand>,
    limits: { exitGraceMs?: number; minStartGapMs?: number } = {},
): LoginFactory {
    return (onState) =>
        new ConnectRunner({
            ...command,
            ...limits,
            onState,
            disconnect: () => disconnectForCancel(link),
        });
}
