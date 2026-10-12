import type { LoginPrompt, LoginState } from "@shared/api";
import {
    describeLoginFailure,
    describePrompt,
    LOGIN_CANCELLING,
    LOGIN_WORKING,
} from "@shared/copy";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
import { StatusIndicator } from "@/components/ui/status-indicator";
import { Heading, Text } from "@/components/ui/text";
import { TextField } from "@/components/ui/text-field";
import { api } from "@/lib/store";

type Active = Exclude<LoginState, { phase: "idle" }>;

/**
 * One question from the gateway. What the user types stays in the field: it
 * is read once when they press Continue, handed to the main process, and
 * wiped. It is never put in React state or anywhere else it could be read.
 */
function Prompt({ prompt }: { prompt: LoginPrompt }) {
    const copy = describePrompt(prompt);
    const field = useRef<HTMLInputElement>(null);
    // Only whether there is anything to send, never what it is.
    const [empty, setEmpty] = useState(true);
    const hidden = prompt.kind === "password" || prompt.kind === "code";

    // A new question takes the keyboard, so the user can simply type.
    useEffect(() => {
        field.current?.focus();
    }, []);

    const submit = (event: FormEvent) => {
        event.preventDefault();
        const input = field.current;
        if (input === null || input.value === "") {
            return;
        }
        const value = input.value;
        input.value = "";
        setEmpty(true);
        void api.answerPrompt(prompt.id, value);
    };

    return (
        <form className="flex min-h-0 flex-1 flex-col gap-5" onSubmit={submit} noValidate>
            <section className="flex shrink-0 animate-arrive flex-col gap-2">
                <div className="flex items-center gap-3">
                    <StatusIndicator tone="busy" size="lg" />
                    <Heading>{copy.title}</Heading>
                </div>
                <Text tone="secondary">{copy.body}</Text>
            </section>

            <div className="flex min-h-24 flex-1 flex-col gap-4">
                {prompt.message !== undefined && (
                    // The gateway's own words: shown as plain text, in a
                    // region that scrolls if there is a lot of it.
                    <Panel tone="attention" scrollLabel="Message from UBC" className="shrink">
                        <Text selectable>{prompt.message}</Text>
                    </Panel>
                )}
                <TextField
                    ref={field}
                    label={prompt.label}
                    name={`login-${prompt.kind}`}
                    type={hidden ? "password" : "text"}
                    inputMode={prompt.kind === "code" ? "numeric" : "text"}
                    autoCapitalize="none"
                    autoCorrect="off"
                    onInput={(event) => setEmpty(event.currentTarget.value === "")}
                    className="shrink-0"
                />
            </div>

            <div className="flex shrink-0 flex-col gap-2">
                <Button type="submit" block size="lg" variant="primary" disabled={empty}>
                    {copy.submit}
                </Button>
                <Button block variant="quiet" onClick={() => void api.cancelLogin()}>
                    Cancel
                </Button>
            </div>
        </form>
    );
}

/** A login under way: a question, a wait, or what went wrong. */
export function LoginView({ login }: { login: Active }) {
    // Escape gives the login up from anywhere on the screen.
    useEffect(() => {
        const onKey = (event: KeyboardEvent) => {
            if (event.key === "Escape") {
                void api.cancelLogin();
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, []);

    if (login.phase === "prompt") {
        // Keyed by the question, so each one starts with an empty field.
        return <Prompt key={login.prompt.id} prompt={login.prompt} />;
    }

    if (login.phase === "cancelling") {
        // Nothing to press: it ends by itself, in a moment.
        return (
            <>
                <section className="flex shrink-0 animate-arrive flex-col gap-2">
                    <div className="flex items-center gap-3">
                        <StatusIndicator tone="busy" size="lg" />
                        <Heading>{LOGIN_CANCELLING.title}</Heading>
                    </div>
                    <Text tone="secondary">{LOGIN_CANCELLING.body}</Text>
                </section>
                <div className="flex min-h-24 flex-1 flex-col" />
            </>
        );
    }

    if (login.phase === "working") {
        return (
            <>
                <section className="flex shrink-0 animate-arrive flex-col gap-2">
                    <div className="flex items-center gap-3">
                        <StatusIndicator tone="busy" size="lg" />
                        <Heading>{LOGIN_WORKING.title}</Heading>
                    </div>
                    <Text tone="secondary">{LOGIN_WORKING.body}</Text>
                </section>
                <div className="flex min-h-24 flex-1 flex-col" />
                <Button block size="lg" className="shrink-0" onClick={() => void api.cancelLogin()}>
                    Cancel
                </Button>
            </>
        );
    }

    const copy = describeLoginFailure(login.code, login.message);
    return (
        <>
            <section className="flex shrink-0 animate-arrive flex-col gap-2">
                <div className="flex items-center gap-3">
                    <StatusIndicator tone="problem" size="lg" />
                    <Heading>{copy.title}</Heading>
                </div>
                <Text tone="secondary">{copy.body}</Text>
            </section>
            <div className="flex min-h-24 flex-1 flex-col">
                {copy.detail !== undefined && (
                    <Panel tone="problem" scrollLabel="What the login reported">
                        <Text size="label" tone="secondary">
                            The login reported
                        </Text>
                        <Text selectable>{copy.detail}</Text>
                    </Panel>
                )}
            </div>
            <div className="flex shrink-0 flex-col gap-2">
                {copy.retry && (
                    <Button
                        block
                        size="lg"
                        variant="primary"
                        // Starting again replaces the failure: one press, one login.
                        onClick={() => void api.cancelLogin().then(() => api.connect())}
                    >
                        Try again
                    </Button>
                )}
                {/* With nothing to try again, going back is the one thing to do. */}
                <Button
                    block
                    {...(copy.retry ? { variant: "quiet" as const } : { size: "lg" as const })}
                    onClick={() => void api.cancelLogin()}
                >
                    Back
                </Button>
            </div>
        </>
    );
}
