// Motion and size: the title bar's mark, zoom, the working animations and
// reduced motion.

import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { action, app, heading, page, scenario, screenshotDir, shoot, tab, useApp } from "./fixture";

useApp();

test("the mark in the title bar takes the colour of each state, and moves to it smoothly", async () => {
    const mark = page.locator("header svg[data-tone]");
    const tunnel = mark.locator("path").first();
    const colours = new Map<string, string>();
    for (const [name, tone] of [
        ["disconnected", "idle"],
        ["connecting", "busy"],
        ["connected", "on"],
        ["login-needed", "attention"],
        ["failed-engine-failed", "problem"],
    ] as const) {
        await scenario(name);
        await expect(mark).toHaveAttribute("data-tone", tone);
        // Once the change has run its course.
        await page.waitForTimeout(400);
        colours.set(tone, await tunnel.evaluate((path) => getComputedStyle(path).stroke));
        await page
            .locator("header")
            .screenshot({ path: join(screenshotDir, `title-bar-${tone}.png`) });
    }
    // Each state its own colour.
    expect(new Set(colours.values()).size).toBe(5);
    // A change of colour is a transition, which carries on from the colour
    // it is at, never a jump.
    const transition = await tunnel.evaluate((path) => {
        const style = getComputedStyle(path);
        return { property: style.transitionProperty, duration: style.transitionDuration };
    });
    expect(transition.property).toBe("stroke");
    expect(Number.parseFloat(transition.duration)).toBeGreaterThan(0);
    await scenario("disconnected");
});

test("the keyboard enlarges, shrinks and resets the interface", async () => {
    const view = () =>
        app.evaluate(({ BrowserWindow }) => {
            const window = BrowserWindow.getAllWindows()[0];
            return {
                zoom: window?.webContents.getZoomFactor(),
                width: window?.getContentSize()[0],
            };
        });
    // Sent through the app, as a real key press is: the shortcut is handled
    // before the page sees the key.
    const chord = (key: string) =>
        app.evaluate(({ BrowserWindow }, keyCode) => {
            BrowserWindow.getAllWindows()[0]?.webContents.sendInputEvent({
                type: "keyDown",
                keyCode,
                modifiers: [process.platform === "darwin" ? "meta" : "control"],
            });
        }, key);
    await scenario("disconnected");
    const start = await view();
    expect(start.zoom).toBe(1);

    await chord("=");
    await chord("=");
    await expect.poll(async () => (await view()).zoom).toBe(1.25);
    // The window grows with the text, so nothing is cut off.
    expect((await view()).width).toBeGreaterThan(start.width ?? 0);
    await expect(action()).toBeInViewport({ ratio: 1 });

    await chord("-");
    await expect.poll(async () => (await view()).zoom).toBe(1.1);
    await chord("0");
    await expect.poll(view).toEqual(start);
});

/** One frame of the "working" pulse, as the page drew it. */
type PulseFrame = {
    /** The page's clock, in milliseconds: the time the frame was drawn for. */
    time: number;
    /** How far along the tunnel the pulse is, from 0 to 1, or null when it is not on the page. */
    at: number | null;
    /** Whether the pulse is moving. */
    moving: boolean;
    opacity: number;
    /** Whether it is fading in or out. */
    fading: boolean;
    /** The endless animations on the page that do not run on the page's clock. */
    offClock: string[];
};

test("the working animations carry on through every change, never jumping", async () => {
    await scenario("connecting");
    await expect(heading()).toHaveText("Connecting");
    // Faded in: the page has drawn since it opened.
    await expect
        .poll(() =>
            page
                .locator('[data-pulse="split"]')
                .evaluate((pulse) =>
                    Number.parseFloat(getComputedStyle(pulse.parentElement ?? pulse).opacity),
                ),
        )
        .toBe(1);
    // How long one lap takes, in milliseconds.
    const lap = await page
        .locator('[data-pulse="split"]')
        .evaluate((pulse) =>
            Number(pulse.getAnimations()[0]?.effect?.getComputedTiming().duration),
        );
    expect(lap).toBeGreaterThan(0);
    // Every frame from here on is recorded, while the state and the screen change under it.
    await page.evaluate(() => {
        const frames: PulseFrame[] = [];
        const record = { frames, stop: false };
        (window as unknown as { pulseRecord: typeof record }).pulseRecord = record;
        const tick = () => {
            const pulse = document.querySelector<SVGPathElement>('[data-pulse="split"]');
            frames.push({
                time: Number(document.timeline.currentTime),
                at:
                    pulse === null
                        ? null
                        : ((-Number.parseFloat(getComputedStyle(pulse).strokeDashoffset) % 1) + 1) %
                          1,
                moving: pulse !== null && pulse.getAnimations().length > 0,
                opacity:
                    pulse?.parentElement === null || pulse === null
                        ? 0
                        : Number.parseFloat(getComputedStyle(pulse.parentElement).opacity),
                fading:
                    pulse?.parentElement
                        ?.getAnimations()
                        .some(
                            (animation) =>
                                animation instanceof CSSTransition &&
                                animation.transitionProperty === "opacity",
                        ) ?? false,
                offClock: document
                    .getAnimations()
                    .filter(
                        (animation) =>
                            animation instanceof CSSAnimation &&
                            animation.effect?.getTiming().iterations === Number.POSITIVE_INFINITY &&
                            animation.startTime !== 0,
                    )
                    .map((animation) => (animation as CSSAnimation).animationName),
            });
            if (!record.stop) {
                setTimeout(tick, 15);
            }
        };
        // A timer, not animation frames: a window kept off the screen draws
        // none, and its animations still run on the page's clock.
        tick();
    });
    const marks: { label: string; time: number }[] = [];
    const step = async (label: string, change: () => Promise<unknown>) => {
        marks.push({
            label,
            time: await page.evaluate(() => Number(document.timeline.currentTime)),
        });
        await change();
        await page.waitForTimeout(500);
    };
    await page.waitForTimeout(500);
    // A login starts, asks a question, and gives way to the connection.
    await step("login working", () => scenario("login-working"));
    await step("login question", () => scenario("login-password"));
    await step("connecting again", () => scenario("connecting"));
    // Another screen and back: the diagram is made afresh.
    await step("another screen", () => tab("Routes").click());
    await step("back", () => tab("Connection").click());
    // Connected: the pulse fades out where it is going.
    await step("connected", () => scenario("connected"));
    await expect(heading()).toHaveText("Connected");
    await page.waitForTimeout(500);
    const frames = await page.evaluate(() => {
        const record = (
            window as unknown as { pulseRecord: { frames: PulseFrame[]; stop: boolean } }
        ).pulseRecord;
        record.stop = true;
        return record.frames;
    });
    const connectedAt = marks.at(-1)?.time ?? 0;

    expect(frames.length, "frames recorded").toBeGreaterThan(100);
    // Wherever the pulse is moving, it is exactly where the page's clock puts
    // it: it never starts a lap again, falls back or skips ahead, whatever
    // happened just before.
    const around = (a: number, b: number) => Math.min(Math.abs(a - b), 1 - Math.abs(a - b));
    const misplaced = frames
        .filter(
            (frame) =>
                frame.moving &&
                frame.at !== null &&
                around(frame.at, (frame.time % lap) / lap) > 0.02,
        )
        .map(
            (frame) =>
                `at ${frame.time.toFixed(0)} ms: ${frame.at?.toFixed(3)}, expected ${((frame.time % lap) / lap).toFixed(3)}`,
        );
    expect(misplaced, `frames where the pulse jumped (marks: ${JSON.stringify(marks)})`).toEqual(
        [],
    );
    // Every frame of the working states had it moving.
    const workingFrames = frames.filter((frame) => frame.time < connectedAt && frame.at !== null);
    expect(workingFrames.length).toBeGreaterThan(60);
    expect(workingFrames.filter((frame) => !frame.moving || frame.opacity < 0.99)).toEqual([]);
    // Nothing that loops, the status mark's breath and the spinner included,
    // runs on a clock of its own.
    expect(frames.flatMap((frame) => frame.offClock)).toEqual([]);
    // Once connected it fades out, still moving, instead of vanishing; then it stops.
    const after = frames.filter((frame) => frame.time >= connectedAt);
    expect(after.some((frame) => frame.moving && frame.fading)).toBe(true);
    expect(after.at(-1)?.moving).toBe(false);
    await shoot("connected-after-connecting");
});

test("with reduced motion the working pulse rests and nothing loops", async () => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    try {
        await scenario("connecting");
        await expect(heading()).toHaveText("Connecting");
        const looping = await page.evaluate(() =>
            document
                .getAnimations()
                .filter(
                    (animation) =>
                        animation.effect?.getTiming().iterations === Number.POSITIVE_INFINITY,
                )
                .map((animation) => (animation as CSSAnimation).animationName),
        );
        expect(looping).toEqual([]);
        // It rests mid-way, so the state can still be seen.
        const offset = await page
            .locator('[data-pulse="split"]')
            .evaluate((pulse) => Number.parseFloat(getComputedStyle(pulse).strokeDashoffset));
        expect(offset).toBeCloseTo(-0.42);
        await shoot("connecting-reduced-motion");
    } finally {
        await page.emulateMedia({ reducedMotion: null });
        await scenario("disconnected");
    }
});
