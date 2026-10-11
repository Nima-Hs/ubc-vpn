// Fails if anything shipped inside the app has a licence that is not on the
// list in `allowed-licenses.json`.
//
// "Shipped" means every package under `dependencies`, with everything they
// pull in, plus the few dev dependencies named in that file. Build tools are
// not checked: they run on the build machine and are not redistributed.

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const config = JSON.parse(
    readFileSync(new URL("../allowed-licenses.json", import.meta.url), "utf8"),
);
const allowed = new Set(config.allowed);
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
 * Whether an SPDX expression is satisfied by the allowed list: one side of an
 * OR is enough, both sides of an AND are needed. Anything else is refused.
 */
function isAllowed(expression) {
    const text = expression.replace(/^\((.*)\)$/, "$1").trim();
    if (text.includes(" OR ")) {
        return text.split(" OR ").some(isAllowed);
    }
    if (text.includes(" AND ")) {
        return text.split(" AND ").every(isAllowed);
    }
    return allowed.has(text);
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

const found = new Set(shipped.map(({ pkg }) => pkg.name));
const missing = [...shippedDev].filter((name) => !found.has(name));
const refused = shipped.filter(({ licence }) => !isAllowed(licence));

for (const { licence, pkg } of refused) {
    console.error(`not allowed: ${pkg.name}@${pkg.versions.join(", ")} is licensed ${licence}`);
}
for (const name of missing) {
    console.error(`not found: ${name} is named in allowed-licenses.json but is not installed`);
}
if (shipped.length === 0) {
    console.error("no packages found: the check did not run");
}
if (refused.length > 0 || missing.length > 0 || shipped.length === 0) {
    process.exit(1);
}
console.log(`${shipped.length} shipped packages, all under an allowed licence`);
