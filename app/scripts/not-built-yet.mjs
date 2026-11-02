// Stands in for `pnpm package:mac` and `pnpm package:linux` until those
// packages are built (electron-builder.mac.yml, electron-builder.linux.yml).
//
//   node scripts/not-built-yet.mjs <system name>

const [system] = process.argv.slice(2);
console.error(`The ${system ?? "requested"} package is not built yet.`);
process.exit(1);
