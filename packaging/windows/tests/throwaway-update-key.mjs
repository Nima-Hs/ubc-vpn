// For the "update end to end" job only: makes a throwaway Ed25519 key, puts its
// public half in app/src/main/update/keys.ts on the runner, and keeps nothing of
// the private half, so no list can ever be signed for it. A build with the
// placeholder never reads a note, so the job needs a real-looking key. Neither the
// edit nor those builds leave the runner: nothing from that job is uploaded.

import { generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

if (process.env.GITHUB_ACTIONS !== 'true') {
  console.error('throwaway-update-key.mjs: this changes the source, and is for CI runners only');
  process.exit(2);
}
const path = process.argv[2];
const { publicKey } = generateKeyPairSync('ed25519');
const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('base64');
const before = readFileSync(path, 'utf8');
const after = before.replace('publicKey: PLACEHOLDER_KEY }', `publicKey: "${raw}" }`);
if (after === before) {
  console.error('throwaway-update-key.mjs: the placeholder was not found');
  process.exit(1);
}
writeFileSync(path, after);
console.log('a throwaway update key is in place, on this runner only');
