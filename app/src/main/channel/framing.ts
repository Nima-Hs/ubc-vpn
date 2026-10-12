/** The longest line either side accepts, newline included. */
export const MAX_LINE_BYTES = 64 * 1024;

const NEWLINE = 0x0a;

/** A line was longer than {@link MAX_LINE_BYTES}. */
export class LineTooLongError extends Error {
    constructor() {
        // The line itself is never part of the message: it may hold a secret.
        super(`line is longer than ${MAX_LINE_BYTES} bytes`);
        this.name = "LineTooLongError";
    }
}

/**
 * Splits a byte stream into lines without ever holding more than one
 * maximum-length line of unfinished input.
 */
export class LineDecoder {
    private pending: Buffer = Buffer.alloc(0);

    /**
     * Adds bytes and returns every complete line they finish, without the
     * newline. Throws {@link LineTooLongError} as soon as a line is too long,
     * whether or not its newline has arrived.
     */
    push(chunk: Buffer): string[] {
        const lines: string[] = [];
        let data = this.pending.length > 0 ? Buffer.concat([this.pending, chunk]) : chunk;
        for (;;) {
            const end = data.indexOf(NEWLINE);
            if (end === -1) {
                break;
            }
            if (end + 1 > MAX_LINE_BYTES) {
                throw new LineTooLongError();
            }
            lines.push(data.toString("utf8", 0, end));
            data = data.subarray(end + 1);
        }
        // A newline would make the unfinished line one byte longer.
        if (data.length + 1 > MAX_LINE_BYTES) {
            throw new LineTooLongError();
        }
        this.pending = Buffer.from(data);
        return lines;
    }

    /** Whether bytes have arrived that do not yet end in a newline. */
    hasPartial(): boolean {
        return this.pending.length > 0;
    }
}

/** Turns a message into one line, newline included. */
export function encodeLine(message: unknown): Buffer {
    const line = Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
    if (line.length > MAX_LINE_BYTES) {
        throw new LineTooLongError();
    }
    return line;
}
