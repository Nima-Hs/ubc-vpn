import type { connectCommand } from "./channel/cli";
import { ConnectRunner } from "./channel/connect";
import type { LoginFactory } from "./controller";
import type { ServiceLink } from "./link";

/**
 * How long after the user gave a login up the app may still send the
 * disconnect that undoes it. Past this, a disconnect would no longer be about
 * that login: it could take down a connection the user made since, by
 * another way, such as the command-line client.
 */
export const LATE_DISCONNECT_MS = 30_000;

/**
 * Asks the service to disconnect, for a login the user gave up after the
 * service had taken it. If the service cannot be reached just now, the
 * request is sent once more, when the bridge is next ready: once, not in a
 * loop, and only within {@link LATE_DISCONNECT_MS} of the cancel. After that
 * it is dropped. The promise ends when the request has been sent or dropped,
 * and until then the login is not shown as given up.
 */
export async function disconnectForCancel(
    link: Pick<ServiceLink, "disconnect" | "getState" | "subscribe">,
    cancelledAt: number,
    limitMs = LATE_DISCONNECT_MS,
): Promise<void> {
    const first = await link.disconnect();
    if (first.ok || first.error.kind !== "service_unavailable") {
        return;
    }
    const inTime = await new Promise<boolean>((resolve) => {
        const left = cancelledAt + limitMs - Date.now();
        if (left <= 0) {
            resolve(false);
            return;
        }
        if (link.getState().link === "ready") {
            resolve(true);
            return;
        }
        const timer = setTimeout(() => {
            stop();
            resolve(false);
        }, left);
        const stop = link.subscribe((state) => {
            if (state.link === "ready") {
                clearTimeout(timer);
                stop();
                resolve(true);
            }
        });
    });
    if (inTime) {
        await link.disconnect();
    }
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
            disconnect: (cancelledAt) => disconnectForCancel(link, cancelledAt),
        });
}
