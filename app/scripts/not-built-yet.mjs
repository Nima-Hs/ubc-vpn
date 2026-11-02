// Stands in for `pnpm package:mac` until that package is built
// (electron-builder.mac.yml).
//
//   node scripts/not-built-yet.mjs <system name>

const [system] = process.argv.slice(2);
console.error(`The ${system ?? "requested"} package is not built yet.`);
process.exit(1);
