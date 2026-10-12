// Fails if anything shipped inside the app has a licence that is not on the
// list in `allowed-licenses.json`.
//
// "Shipped" means every package under `dependencies`, with everything they
// pull in, plus the few dev dependencies named in that file. Build tools are
// not checked: they run on the build machine and are not redistributed.

import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const config = JSON.parse(
    readFileSync(new URL("../allowed-licenses.json", import.meta.url), "utf8"),
);
const allowed = new Set(config.allowed);
const fontLicences = new Set(config.fonts.licences);
const fontPackages = new Set(config.fonts.packages);
const shippedDev = new Set(config.shippedDevDependencies.packages);

/** Runs `pnpm licenses list` and returns `{ licence: [package, ...] }`. */
function list(scope) {
    // `scope` is one of the two fixed strings below, never outside input.
    const output = execSync(`pnpm licenses list ${scope} --json`, {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(output);
}

/**
 * Whether an SPDX expression is satisfied by a set of licences: one side of
 * an OR is enough, both sides of an AND are needed. Anything else is refused.
 */
function satisfies(expression, licences) {
    const text = expression.replace(/^\((.*)\)$/, "$1").trim();
    if (text.includes(" OR ")) {
        return text.split(" OR ").some((part) => satisfies(part, licences));
    }
    if (text.includes(" AND ")) {
        return text.split(" AND ").every((part) => satisfies(part, licences));
    }
    return licences.has(text);
}

/** A font licence is good for the named font packages and for nothing else. */
function isAllowed({ licence, pkg }) {
    return (
        satisfies(licence, allowed) ||
        (fontPackages.has(pkg.name) && satisfies(licence, fontLicences))
    );
}

const shipped = [];
for (const [licence, packages] of Object.entries(list("--prod"))) {
    shipped.push(...packages.map((pkg) => ({ licence, pkg })));
}
for (const [licence, packages] of Object.entries(list("--dev"))) {
    shipped.push(
        ...packages.filter((pkg) => shippedDev.has(pkg.name)).map((pkg) => ({ licence, pkg })),
    );
}

const found = new Map(shipped.map(({ pkg }) => [pkg.name, pkg]));
const problems = [];

for (const entry of shipped.filter((candidate) => !isAllowed(candidate))) {
    const { licence, pkg } = entry;
    problems.push(`not allowed: ${pkg.name}@${pkg.versions.join(", ")} is licensed ${licence}`);
}
for (const name of [...shippedDev, ...fontPackages].filter((wanted) => !found.has(wanted))) {
    problems.push(`not found: ${name} is named in allowed-licenses.json but is not installed`);
}
// A font's licence requires its text to travel with the font. Packaging will
// copy it from here, so it has to be here.
for (const name of fontPackages) {
    const pkg = found.get(name);
    if (pkg !== undefined && !pkg.paths.some((path) => existsSync(join(path, "LICENSE")))) {
        problems.push(`no licence text: ${name} has no LICENSE file to ship with the font`);
    }
}
if (shipped.length === 0) {
    problems.push("no packages found: the check did not run");
}

if (problems.length > 0) {
    console.error(problems.join("\n"));
    process.exit(1);
}
console.log(`${shipped.length} shipped packages, all under an allowed licence`);
