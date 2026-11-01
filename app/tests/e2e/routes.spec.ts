// The Routes screen.

import { expect, type Locator, test } from "@playwright/test";
import { app, heading, page, said, scenario, shoot, tab, useApp } from "./fixture";

useApp();

type Side = "top" | "right" | "bottom" | "left";

/**
 * How much of each side of a focused field's ring is really drawn, from 0 to
 * 1. The field is photographed with the keyboard on it and again without,
 * and the two are compared along each edge, so it is the pixels on screen
 * that count and not what the styles say. A ring that something clips shows
 * up as a side near 0.
 */
async function ringDrawn(field: Locator): Promise<Record<Side, number>> {
    await expect(field).toBeFocused();
    const box = await field.boundingBox();
    if (box === null) {
        throw new Error("the field is not on screen");
    }
    const view = await page.evaluate(() => ({ width: innerWidth, height: innerHeight }));
    // From a little outside the field to a little inside it, on every side.
    const OUT = 6;
    const IN = 3;
    const x = Math.max(0, Math.floor(box.x) - OUT);
    const y = Math.max(0, Math.floor(box.y) - OUT);
    const clip = {
        x,
        y,
        width: Math.min(view.width, Math.ceil(box.x + box.width) + OUT) - x,
        height: Math.min(view.height, Math.ceil(box.y + box.height) + OUT) - y,
    };
    const focused = await page.screenshot({ clip });
    await field.evaluate((element) => (element as HTMLElement).blur());
    const plain = await page.screenshot({ clip });
    await field.focus();
    const { width, height, a, b } = await app.evaluate(
        ({ nativeImage }, [first, second]) => {
            const one = nativeImage.createFromBuffer(Buffer.from(first as string, "base64"));
            const two = nativeImage.createFromBuffer(Buffer.from(second as string, "base64"));
            return {
                ...one.getSize(),
                a: one.toBitmap().toString("base64"),
                b: two.toBitmap().toString("base64"),
            };
        },
        [focused.toString("base64"), plain.toString("base64")],
    );
    const one = Buffer.from(a, "base64");
    const two = Buffer.from(b, "base64");
    const scale = width / clip.width;
    const differs = (px: number, py: number) => {
        if (px < 0 || py < 0 || px >= width || py >= height) {
            return false;
        }
        const at = (py * width + px) * 4;
        let sum = 0;
        for (let channel = 0; channel < 3; channel++) {
            sum += Math.abs((one[at + channel] ?? 0) - (two[at + channel] ?? 0));
        }
        return sum > 40;
    };
    const left = (box.x - clip.x) * scale;
    const top = (box.y - clip.y) * scale;
    const right = left + box.width * scale;
    const bottom = top + box.height * scale;
    // Along each edge, leaving the rounded corners out: is anything drawn
    // across the edge at this point?
    const CORNER = 10 * scale;
    const along = (from: number, to: number, hit: (at: number, across: number) => boolean) => {
        let drawn = 0;
        let total = 0;
        for (let at = Math.ceil(from + CORNER); at < to - CORNER; at++) {
            total += 1;
            for (let across = -OUT * scale; across <= IN * scale; across++) {
                if (hit(at, across)) {
                    drawn += 1;
                    break;
                }
            }
        }
        return total === 0 ? 0 : drawn / total;
    };
    return {
        top: along(left, right, (at, across) => differs(at, Math.round(top + across))),
        bottom: along(left, right, (at, across) => differs(at, Math.round(bottom - 1 - across))),
        left: along(top, bottom, (at, across) => differs(Math.round(left + across), at)),
        right: along(top, bottom, (at, across) => differs(Math.round(right - 1 - across), at)),
    };
}

test("routes: a problem is marked on its own row, and only checked routes can be saved", async () => {
    await scenario("routes");
    await tab("Connection").click();
    await tab("Routes").click();
    const save = page.getByRole("button", { name: "Save routes" });
    await expect(page.getByLabel("Subnet 1", { exact: true })).toHaveValue("203.0.113.0/24");
    // Nothing has changed, so there is nothing to save.
    await expect(save).toHaveAttribute("aria-disabled", "true");
    // The limits are said before anything is typed.
    await expect(page.getByText("A subnet can be no larger than /8")).toBeVisible();
    await expect(page.getByText("203.0.113.0/24, 198.51.100.0/24")).toBeVisible();

    // A new row takes the keyboard. What is typed is checked a moment later.
    await page.getByRole("button", { name: "Add subnet" }).click();
    const added = page.getByLabel("Subnet 3", { exact: true });
    await expect(added).toBeFocused();
    await page.keyboard.type("not a subnet");
    // While the check runs, the reason Save is not available is on screen.
    // (The other "Checking…" on the page is the one read out, which is not shown.)
    await expect(
        page.locator('main [aria-hidden="true"] p', { hasText: "Checking…" }),
    ).toBeInViewport({ ratio: 1 });
    await expect(added).toHaveAttribute("aria-invalid", "true");
    await expect(said("Write a network as address/length")).toHaveCount(1);
    // The rows that were fine are left alone.
    await expect(page.getByLabel("Subnet 1", { exact: true })).not.toHaveAttribute("aria-invalid");
    await expect(save).toHaveAttribute("aria-disabled", "true");

    // Put right, it can be saved; once saved there is again nothing to save.
    await added.fill("203.0.113.128/25");
    await expect(added).not.toHaveAttribute("aria-invalid");
    await expect(save).not.toHaveAttribute("aria-disabled");
    await save.click();
    await expect(page.getByRole("status")).toContainText("Saved.");
    await expect(save).toHaveAttribute("aria-disabled", "true");

    // Removing every subnet is a problem with the whole list, said once.
    for (const name of ["Remove subnet 3", "Remove subnet 2", "Remove subnet 1"]) {
        await page.getByRole("button", { name }).click();
    }
    await expect(said("Add at least one subnet.")).toHaveCount(1);
    await expect(page.getByText("No subnets yet.")).toBeVisible();
    await expect(save).toHaveAttribute("aria-disabled", "true");
    await shoot("routes-no-subnets");
    // Leave it as it was found: those changes are thrown away.
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();
    await expect(heading()).not.toHaveText("Routes");
});

test("routes: stored routes are checked on opening, before anything is typed", async () => {
    await scenario("routes-problems");
    await tab("Connection").click();
    await tab("Routes").click();
    // Each stored entry the client refuses is marked on its own row.
    await expect(page.getByLabel("Subnet 2", { exact: true })).toHaveAttribute(
        "aria-invalid",
        "true",
    );
    await expect(said("This subnet is too large. Use /8 or a larger number")).toHaveCount(1);
    await expect(said("This range is reserved for special uses")).toHaveCount(1);
    await expect(page.getByLabel("Subnet 1", { exact: true })).not.toHaveAttribute("aria-invalid");
    // Nothing was changed, so nothing can be saved, and leaving asks nothing.
    await expect(page.getByRole("button", { name: "Save routes" })).toHaveAttribute(
        "aria-disabled",
        "true",
    );
    await tab("Connection").click();
    await expect(heading()).not.toHaveText("Routes");
    await scenario("routes");
});

test("routes: unsaved changes are not lost by leaving the screen", async () => {
    await scenario("routes");
    await tab("Connection").click();
    await tab("Routes").click();
    await page.getByLabel("Domain 1", { exact: true }).fill("lab.campus.example");

    // Asked to leave, the screen stays and asks first.
    await tab("Connection").click();
    await expect(heading()).toHaveText("Routes");
    await expect(page.getByText("You have changes that are not saved.")).toBeVisible();
    const keep = page.getByRole("button", { name: "Keep editing" });
    await expect(keep).toBeFocused();
    await shoot("routes-unsaved");
    await keep.click();
    await expect(page.getByLabel("Domain 1", { exact: true })).toHaveValue("lab.campus.example");

    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();
    await expect(heading()).not.toHaveText("Routes");
    // Coming back shows what is saved, not what was thrown away.
    await tab("Routes").click();
    await expect(page.getByLabel("Domain 1", { exact: true })).toHaveValue("campus.example");
});

test("routes: what the user needs to know is said on the form", async () => {
    // While connected, a change waits for the next connection.
    await scenario("connected");
    await tab("Connection").click();
    await tab("Routes").click();
    await page.getByLabel("Domain 1", { exact: true }).fill("lab.campus.example");
    await expect(page.getByText("Changes apply the next time you connect.")).toBeVisible();
    await shoot("routes-while-connected");
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();

    // A save can be refused for routes the check accepted: said once, on the form.
    await scenario("routes-too-long-to-save");
    await tab("Routes").click();
    await page.getByLabel("Domain 1", { exact: true }).fill("lab.campus.example");
    const save = page.getByRole("button", { name: "Save routes" });
    await expect(save).not.toHaveAttribute("aria-disabled");
    await save.click();
    await expect(said("These routes are too long to save.")).toHaveCount(1);
    await expect(page.getByLabel("Domain 1", { exact: true })).not.toHaveAttribute("aria-invalid");
    await shoot("routes-too-long-to-save-refused");
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();

    // Settings that cannot be read: said plainly, with a way to try again.
    await scenario("routes-unreadable");
    await tab("Routes").click();
    await expect(page.getByText("Your settings file is damaged")).toBeInViewport({ ratio: 1 });
    await scenario("routes");
    await page.getByRole("button", { name: "Try again" }).click();
    await expect(page.getByLabel("Subnet 1", { exact: true })).toBeVisible();

    // A missing policy is said up front.
    await scenario("routes-no-policy");
    await tab("Connection").click();
    await tab("Routes").click();
    // In view and whole, not merely there: a panel squeezed flat is "visible".
    const warning = page.getByText("The VPN’s policy file is missing or damaged");
    await expect(warning).toBeInViewport({ ratio: 1 });
    const squeezed = await warning.evaluate((text) => {
        const panel = text.closest(".scroll-region")?.parentElement;
        return panel === null || panel === undefined
            ? true
            : panel.getBoundingClientRect().height < text.getBoundingClientRect().height;
    });
    expect(squeezed).toBe(false);
    await scenario("disconnected");
    await tab("Connection").click();
});

test("routes: a list of 256 rows stays usable", async () => {
    await scenario("routes-crowded");
    await tab("Connection").click();
    await tab("Routes").click();
    await expect(page.getByLabel("Subnet 256", { exact: true })).toHaveValue("203.0.113.255/32");
    // Typing in the middle of it answers at once, and the check still comes back.
    const middle = page.getByLabel("Subnet 128", { exact: true });
    const started = Date.now();
    await middle.fill("not a subnet");
    await expect(middle).toHaveValue("not a subnet");
    expect(Date.now() - started).toBeLessThan(2000);
    await expect(said("Write a network as address/length")).toHaveCount(1);

    // The keyboard reaches everything without scrolling by hand. Tab from the
    // last subnet lands on its remove button, then on Add, and each comes
    // into view as it takes focus.
    const add = page.getByRole("button", { name: "Add subnet" });
    await expect(add).not.toBeInViewport();
    await page.getByLabel("Subnet 256", { exact: true }).focus();
    await expect(page.getByLabel("Subnet 256", { exact: true })).toBeInViewport();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await expect(add).toBeFocused();
    await expect(add).toBeInViewport({ ratio: 1 });
    // Too many rows is a problem with the whole list. It is said above Save,
    // which does not scroll, so it is on screen wherever the list is.
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Subnet 257", { exact: true })).toBeFocused();
    await page.keyboard.type("203.0.112.0/24");
    await expect(said("There are more than 256 subnets")).toBeInViewport({ ratio: 1 });
    await expect(page.getByRole("button", { name: "Save routes" })).toBeInViewport({ ratio: 1 });
    await shoot("routes-too-many");
    await tab("Connection").click();
    await page.getByRole("button", { name: "Discard changes" }).click();
    await scenario("disconnected");
});

test("routes: the focus ring is drawn whole around a field, wherever its row is", async () => {
    await scenario("routes-crowded");
    await tab("Connection").click();
    await tab("Routes").click();
    const subnet = (row: number) => page.getByLabel(`Subnet ${row}`, { exact: true });
    await expect(subnet(256)).toHaveValue("203.0.113.255/32");
    const whole = { top: 1, right: 1, bottom: 1, left: 1 };

    // The first row.
    await subnet(1).focus();
    expect(await ringDrawn(subnet(1)), "the first row").toEqual(whole);
    await shoot("routes-focus-first-row");

    // A row in the middle, reached by Tab from the rows before it, so it is
    // scrolled only as far as it must be and sits against the area's edge.
    for (let row = 1; row < 12; row++) {
        await page.keyboard.press("Tab");
        await page.keyboard.press("Tab");
    }
    await expect(subnet(12)).toBeFocused();
    expect(await ringDrawn(subnet(12)), "a middle row").toEqual(whole);
    await shoot("routes-focus-middle-row");

    // The last row, come to from above in the same way.
    await subnet(255).focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await expect(subnet(256)).toBeFocused();
    expect(await ringDrawn(subnet(256)), "the last row").toEqual(whole);
    await shoot("routes-focus-last-row");
    await tab("Connection").click();
    await scenario("disconnected");
});
