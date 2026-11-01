// The connection details on the main screen.

import { expect, type Locator, test } from "@playwright/test";
import { action, page, scenario, shoot, useApp } from "./fixture";

useApp();

/**
 * How the rows of a list in the connection details sit: each row's box and
 * text, whether a line divides it from the row above, and whether anything in
 * it is cut off or reaches past the details.
 */
async function rowsOf(list: Locator) {
    return list.evaluate((section) => {
        const details = section.closest('[role="group"]')?.getBoundingClientRect();
        return [...section.querySelectorAll("li")].map((row) => {
            const box = row.getBoundingClientRect();
            const entry = row.querySelector("span")?.getBoundingClientRect();
            return {
                text: row.textContent ?? "",
                top: box.top,
                bottom: box.bottom,
                lineAbove: Number.parseFloat(getComputedStyle(row).borderTopWidth) > 0,
                lineBelow: Number.parseFloat(getComputedStyle(row).borderBottomWidth) > 0,
                cut: row.scrollWidth > row.clientWidth,
                outside:
                    details === undefined ||
                    box.left < details.left ||
                    box.right > details.right + 0.5,
                startsAt: entry?.left ?? null,
            };
        });
    });
}

test("connection details: one entry per row, grouped, aligned, and nothing spills", async () => {
    await scenario("connected-pieces");
    const details = page.getByRole("group", { name: "Connection details" });
    const subnets = details.getByRole("region", { name: "Subnets through the VPN" });
    const domains = details.getByRole("region", { name: "Domains looked up through the VPN" });
    await expect(subnets).toBeVisible();
    // Counted, where the group is named.
    await expect(subnets).toContainText("21 subnets");
    await expect(domains).toContainText("1 domain");
    await expect(domains.getByRole("listitem")).toHaveText(["campus.example"]);

    // The range saved in 16 pieces is shown as one row, saying so.
    await expect(subnets.getByRole("listitem")).toHaveText([
        "198.51.100.0/24",
        "10.20.0.0/16Saved as 16 subnets, leaving out 10.20.255.254",
        "10.30.0.0/16",
        "10.40.8.0/22",
        "192.0.2.0/24",
        "203.0.113.128/25",
    ]);
    const check = async (expected: number) => {
        const rows = await rowsOf(subnets);
        expect(rows).toHaveLength(expected);
        rows.forEach((row, index) => {
            expect(row.cut, `${row.text} is cut off`).toBe(false);
            expect(row.outside, `${row.text} reaches past the details`).toBe(false);
            if (index > 0) {
                // Its own row, under the last, with a line between.
                expect(row.top).toBeGreaterThanOrEqual((rows[index - 1]?.bottom ?? 0) - 0.5);
                const divided = row.lineAbove || rows[index - 1]?.lineBelow;
                expect(divided, `${row.text} has no line above it`).toBe(true);
            }
        });
        // Every address starts on one edge, the group name's.
        const heading = await subnets.getByRole("heading").boundingBox();
        const edges = new Set(rows.map((row) => Math.round(row.startsAt ?? -1)));
        expect([...edges]).toEqual([Math.round(heading?.x ?? 0)]);
    };
    await check(6);
    await shoot("details-combined");

    // The saved list is one press away, and back.
    await details.getByRole("button", { name: "Show all 21 saved subnets" }).click();
    await check(21);
    await expect(subnets.getByRole("listitem").nth(1)).toHaveText("10.20.0.0/17");
    // Scrolled, the group keeps its name in view.
    await details.evaluate((region) => {
        region.scrollTop = 240;
    });
    await expect(subnets.getByRole("heading")).toBeInViewport({ ratio: 1 });
    await shoot("details-each");
    await details.evaluate((region) => {
        region.scrollTop = 0;
    });
    await details.getByRole("button", { name: "Show combined ranges" }).click();
    await check(6);

    // The details scroll inside the window; the button below stays in view.
    const overflow = await page.evaluate(
        () =>
            document.documentElement.scrollWidth > document.documentElement.clientWidth ||
            document.documentElement.scrollHeight > document.documentElement.clientHeight,
    );
    expect(overflow).toBe(false);
    await expect(action()).toBeInViewport({ ratio: 1 });

    // The longest list allowed, and a domain with nowhere to break.
    await scenario("connected-crowded");
    await expect(subnets).toContainText("256 subnets");
    await details.getByRole("button", { name: "Show all 256 saved subnets" }).click();
    await check(256);
    const domainRows = await rowsOf(domains);
    expect(domainRows).toHaveLength(41);
    for (const row of domainRows) {
        expect(row.cut, `${row.text} is cut off`).toBe(false);
        expect(row.outside, `${row.text} reaches past the details`).toBe(false);
    }
    await expect(action()).toBeInViewport({ ratio: 1 });
    await scenario("disconnected");
});

test("keyboard focus on the scrolling details is visible", async () => {
    await scenario("connected-crowded");
    const details = page.getByRole("group", { name: "Connection details" });
    await expect(details).toBeVisible();
    // Reach it the way a keyboard user does: Tab through the title bar,
    // whose controls differ by OS, and the tunnel choice, until focus lands on it.
    await page.locator("body").click({ position: { x: 1, y: 1 } });
    for (let presses = 0; presses < 12; presses++) {
        await page.keyboard.press("Tab");
        if (await details.evaluate((region) => region === document.activeElement)) {
            break;
        }
    }
    await expect(details).toBeFocused();
    const ring = await details.evaluate((region) => {
        const style = getComputedStyle(region);
        return {
            keyboard: region.matches(":focus-visible"),
            style: style.outlineStyle,
            width: Number.parseFloat(style.outlineWidth),
            offset: Number.parseFloat(style.outlineOffset),
        };
    });
    // Drawn inside the region, where the panel's rounded edge cannot clip it.
    expect(ring.keyboard).toBe(true);
    expect(ring.style).toBe("solid");
    expect(ring.width).toBeGreaterThanOrEqual(2);
    expect(ring.offset).toBe(-ring.width);
    await shoot("keyboard-focus-details");
    await page.keyboard.press("ArrowDown");
    await expect.poll(() => details.evaluate((region) => region.scrollTop)).toBeGreaterThan(0);
    await scenario("disconnected");
});
