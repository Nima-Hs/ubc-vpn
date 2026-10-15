// Checks an unpacked libopenconnect-windows-x64 artifact against its own
// manifest.json, and its recipe against this repository, before
// packaging/windows/stage.sh stages anything from it:
//
//   node packaging/windows/check-native.mjs <native-folder> <recipe-folder>
//
// Every library in bin/ and every source archive in source/ must be listed
// in the manifest, and must have the SHA-256 it records there. The manifest
// is what SOURCES.txt and the sources tarball describe, so this is what ties
// each shipped library to the source published for it.
//
// The only folder in source/ is recipe/, the build scripts and patches,
// which ship as the scripts that control the build. It must hold exactly
// the files of <recipe-folder>, byte for byte: native/windows as it is at
// the commit the manifest names (recipe.commit), which the workflow checks
// out.
//
// It stops with exit code 1 at a file whose checksum or contents differ, a
// listed file that is missing, or a file or folder the manifest or the
// recipe does not account for.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

if (process.argv.length !== 4) {
  console.error('usage: node check-native.mjs <native-folder> <recipe-folder>');
  process.exit(2);
}
const [native, recipe] = process.argv.slice(2);
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
// bin/, and everything at the top of source/ but the recipe.
const present = readdirSync(join(native, 'bin')).map((f) => `bin/${f}`);
for (const name of readdirSync(join(native, 'source'))) {
  if (name === 'recipe' && statSync(join(native, 'source', name)).isDirectory()) continue;
  present.push(`source/${name}`);
}
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

// Every file under `dir`, by its path from there with forward slashes.
function files(dir, prefix = '') {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = `${prefix}${entry.name}`;
    if (entry.isDirectory()) found.push(...files(join(dir, entry.name), `${path}/`));
    else found.push(path);
  }
  return found;
}
const shipped = join(native, 'source', 'recipe');
let inArtifact = [];
try {
  inArtifact = files(shipped);
} catch {
  problems.push('source/recipe/ is missing');
}
const inRepository = new Set(files(recipe));
for (const name of inArtifact) {
  if (!inRepository.has(name)) {
    problems.push(`source/recipe/${name} is not in native/windows at the recipe's commit`);
  } else if (!readFileSync(join(shipped, name)).equals(readFileSync(join(recipe, name)))) {
    problems.push(`source/recipe/${name} differs from native/windows at the recipe's commit`);
  }
  inRepository.delete(name);
}
for (const name of inRepository) {
  problems.push(`source/recipe/${name} is missing: native/windows has it at the recipe's commit`);
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  process.exit(1);
}
console.log(`${listed.size} files match manifest.json, and ${inArtifact.length} the recipe`);
