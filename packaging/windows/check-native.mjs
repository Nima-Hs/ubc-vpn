// Checks an unpacked libopenconnect-windows-x64 artifact against its own
// manifest.json before packaging/windows/stage.sh stages anything from it:
//
//   node packaging/windows/check-native.mjs <native-folder>
//
// Every library in bin/ and every source archive in source/ must be listed
// in the manifest, and must have the SHA-256 it records there. The manifest
// is what SOURCES.txt and the sources tarball describe, so this is what ties
// each shipped library to the source published for it.
//
// It stops with exit code 1 at a file whose checksum differs, a listed file
// that is missing, or a file in bin/ or source/ the manifest does not list.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

if (process.argv.length !== 3) {
  console.error('usage: node check-native.mjs <native-folder>');
  process.exit(2);
}
const native = process.argv[2];
const manifest = JSON.parse(readFileSync(join(native, 'manifest.json'), 'utf8'));

// Every file the manifest gives a checksum for, by its path in the artifact.
const listed = new Map();
function list(name, sha256) {
  if (typeof name !== 'string' || !/^[0-9a-f]{64}$/.test(sha256 ?? '')) {
    throw new Error(`manifest.json: a file without a name or a SHA-256: ${JSON.stringify({ name, sha256 })}`);
  }
  if (listed.has(name) && listed.get(name) !== sha256) {
    throw new Error(`manifest.json lists ${name} twice, with different checksums`);
  }
  listed.set(name, sha256);
}
for (const component of manifest.components ?? []) {
  for (const file of component.files ?? []) list(file.name, file.sha256);
  const source = component.source;
  // A source recorded but not shipped (the static runtime's) has no file.
  if (source && source.shipped !== false) list(source.archive ?? source.file, source.sha256);
}

const problems = [];
// The files that ship or stand for the shipped ones' source: everything in
// bin/, and the archives at the top of source/ (source/recipe/ is ours).
const present = [
  ...readdirSync(join(native, 'bin')).map((f) => `bin/${f}`),
  ...readdirSync(join(native, 'source'))
    .filter((f) => !statSync(join(native, 'source', f)).isDirectory())
    .map((f) => `source/${f}`),
];
for (const name of present) {
  if (!listed.has(name)) problems.push(`${name} is not listed in manifest.json`);
}
for (const [name, sha256] of listed) {
  let actual;
  try {
    actual = createHash('sha256')
      .update(readFileSync(join(native, name)))
      .digest('hex');
  } catch {
    problems.push(`${name} is listed in manifest.json but missing`);
    continue;
  }
  if (actual !== sha256) problems.push(`${name}: SHA-256 ${actual}, but manifest.json says ${sha256}`);
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  process.exit(1);
}
console.log(`${listed.size} files match manifest.json`);
