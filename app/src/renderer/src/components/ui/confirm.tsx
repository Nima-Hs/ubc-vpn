import { type ReactNode, useEffect, useId, useRef } from "react";
import { Button } from "./button";
import { Panel } from "./panel";
import { Text } from "./text";

/**
 * A question before something that cannot be undone, shown in place. It is
 * an alert dialog named by the question. When it opens, the keyboard goes
 * once to the safe answer, so a second Enter pressed out of habit keeps what
 * is there; Escape keeps it too. Only a deliberate move to the other button
 * does the thing.
 */
export function Confirm({
    question,
    confirm,
    cancel,
    busy = false,
    onConfirm,
    onCancel,
    children,
}: {
    question: string;
    /** The button that does it, named for what it does. */
    confirm: string;
    /** The safe answer. */
    cancel: string;
    busy?: boolean;
    onConfirm(): void;
    onCancel(): void;
    /** Said under the question, for example why the last try failed. */
    children?: ReactNode;
}) {
    const questionId = useId();
    const safe = useRef<HTMLButtonElement>(null);
    // Once, when it opens: never again on a re-render.
    useEffect(() => {
        safe.current?.focus();
    }, []);

    return (
        <div
            role="alertdialog"
            aria-labelledby={questionId}
            onKeyDown={(event) => {
                if (event.key === "Escape") {
                    event.stopPropagation();
                    onCancel();
                }
            }}
        >
            <Panel tone="attention">
                <Text>
                    <span id={questionId}>{question}</span>
                </Text>
                {children}
                <div className="flex gap-2 pt-1">
                    <Button size="sm" variant="destructive" loading={busy} onClick={onConfirm}>
                        {confirm}
                    </Button>
                    <Button ref={safe} size="sm" variant="quiet" disabled={busy} onClick={onCancel}>
                        {cancel}
                    </Button>
                </div>
            </Panel>
        </div>
    );
}
