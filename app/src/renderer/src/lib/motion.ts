// The motion tokens, for animations driven from script. The values live in
// `tokens.css`; a test fails if these stop matching them.

/** Seconds, as Motion expects. */
export const duration = {
    fast: 0.16,
    base: 0.24,
    slow: 0.42,
} as const;

export const easeOut = [0.23, 1, 0.32, 1] as const;
