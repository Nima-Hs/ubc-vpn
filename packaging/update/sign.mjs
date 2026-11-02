// Writes the signed update list for a release, for the release workflow:
//
//   node packaging/update/sign.mjs --version <version> \
//     --file <platform>=<installer> [--file <platform>=<installer> ...] \
//     [--key-fd <fd>] [--out <list.json>] < private-key.pem
//
// The list says which installers belong to the version, by file name, size
// and SHA-256, which this script works out from the files themselves. The
// app trusts an installer only if it matches a list signed with a key it
// carries. The format is in docs/architecture.md, "Updates"; the app's
// reader is app/src/main/update/list.ts, and app/tests/update-sign.test.ts
// checks that the two agree.
//
// The private key is an Ed25519 key in PKCS#8 PEM. It is read from standard
// input, or from the open file descriptor --key-fd names, never from an
// argument or a file name, so it never appears in a command line or a
// process list. Nothing this script prints holds it, or any part of it: it
// prints the list's contents and the public key's id, which are public.
//
// It checks what it writes with the app's own limits, so it never writes a
// list the app would refuse. It stops with exit code 1 on a problem with
// the files or the key, and 2 on a wrong command line. Messages name the
// platform and file name of an installer, but never repeat the key, an
// option or a value it does not take, so a key pasted into the wrong place
// is not echoed.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { closeSync, fstatSync, openSync, readFileSync, readSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';

// Must match app/src/main/update/list.ts.
const APP_ID = 'io.github.nima-hs.ubc-vpn';
const LIST_FORMAT = 1;
const SIGNING_CONTEXT = 'ubc-vpn update list v1\n';
const MAX_INSTALLER_BYTES = 512 * 1024 * 1024;
const MAX_FILES = 16;
const MAX_PLATFORM_LENGTH = 32;
const MAX_VERSION_LENGTH = 64;
const PLATFORM = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const FILE_NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const NUMBER = '0|[1-9]\\d*';
const PRE_ID = `(?:${NUMBER}|\\d*[a-zA-Z-][0-9a-zA-Z-]*)`;
const VERSION = new RegExp(
  `^(?:${NUMBER})\\.(?:${NUMBER})\\.(?:${NUMBER})(?:-${PRE_ID}(?:\\.${PRE_ID})*)?` +
    '(?:\\+[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*)?$',
);

function usage(problem) {
  console.error(`sign.mjs: ${problem}`);
  console.error(
    'usage: node sign.mjs --version <version> --file <platform>=<installer> ... ' +
      '[--key-fd <fd>] [--out <list.json>] < private-key.pem',
  );
  process.exit(2);
}

function fail(problem) {
  console.error(`sign.mjs: ${problem}`);
  process.exit(1);
}

let version = null;
let keyFd = 0;
let out = null;
const files = [];
const args = process.argv.slice(2);
for (let at = 0; at < args.length; at += 2) {
  const [option, value] = [args[at], args[at + 1]];
  if (value === undefined) {
    usage('every option takes a value');
  }
  if (option === '--version') {
    version = value;
  } else if (option === '--file') {
    const split = value.indexOf('=');
    if (split < 1) {
      usage('--file takes <platform>=<installer>');
    }
    files.push({ platform: value.slice(0, split), path: value.slice(split + 1) });
  } else if (option === '--key-fd') {
    if (!/^\d{1,4}$/.test(value)) {
      usage('--key-fd takes a file descriptor number');
    }
    keyFd = Number(value);
  } else if (option === '--out') {
    out = value;
  } else {
    // The option is not named: it could be a key pasted in by mistake.
    usage('an option is not one this script takes');
  }
}
if (version === null || version.length > MAX_VERSION_LENGTH || !VERSION.test(version)) {
  usage('--version takes a version such as 1.2.3');
}
if (files.length === 0 || files.length > MAX_FILES) {
  usage(`name from 1 to ${MAX_FILES} installers with --file`);
}

let key;
try {
  if (keyFd === 0 && process.stdin.isTTY) {
    fail('the private key is read from standard input; pipe it in');
  }
  key = createPrivateKey(readFileSync(keyFd));
} catch {
  fail('could not read an Ed25519 private key in PEM from the key input');
}
if (key.asymmetricKeyType !== 'ed25519') {
  fail('the key is not an Ed25519 private key');
}
const raw = Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x, 'base64url');
const keyId = createHash('sha256').update(raw).digest('hex').slice(0, 16);

// The size and the SHA-256 from one read of one open file, so they are of
// the same bytes. Stops past the largest size the app accepts.
function measure(path, name) {
  let fd;
  try {
    fd = openSync(path, 'r');
  } catch {
    fail(`${name} cannot be opened`);
  }
  try {
    if (!fstatSync(fd).isFile()) {
      fail(`${name} is not a file`);
    }
    const hash = createHash('sha256');
    const chunk = Buffer.alloc(1024 * 1024);
    let size = 0;
    for (;;) {
      const read = readSync(fd, chunk, 0, chunk.length, size);
      if (read === 0) {
        break;
      }
      hash.update(chunk.subarray(0, read));
      size += read;
      if (size > MAX_INSTALLER_BYTES) {
        fail(`${name} is larger than the app accepts`);
      }
    }
    if (size < 1) {
      fail(`${name} is empty`);
    }
    return { size, sha256: hash.digest('hex') };
  } finally {
    closeSync(fd);
  }
}

const entries = [];
const platforms = new Set();
for (const { platform, path } of files) {
  const name = basename(path);
  if (!PLATFORM.test(platform) || platform.length > MAX_PLATFORM_LENGTH) {
    fail(`"${platform}" is not a platform name such as windows-x64`);
  }
  if (platforms.has(platform)) {
    fail(`${platform} is named twice`);
  }
  platforms.add(platform);
  if (!FILE_NAME.test(name)) {
    fail(`"${name}" is not a file name the app accepts`);
  }
  entries.push({ platform, name, ...measure(path, name) });
}

const list = Buffer.from(
  `${JSON.stringify({ format: LIST_FORMAT, app: APP_ID, version, files: entries }, null, 2)}\n`,
  'utf8',
);
const signature = sign(null, Buffer.concat([Buffer.from(SIGNING_CONTEXT, 'utf8'), list]), key);
const envelope = `${JSON.stringify(
  {
    format: LIST_FORMAT,
    key: keyId,
    list: list.toString('base64'),
    signature: signature.toString('base64'),
  },
  null,
  2,
)}\n`;

if (out === null) {
  process.stdout.write(envelope);
} else {
  writeFileSync(out, envelope);
}
console.error(`signed the list for ${version} with key ${keyId}:`);
for (const entry of entries) {
  console.error(`  ${entry.platform}  ${entry.name}  ${entry.size} bytes  sha256 ${entry.sha256}`);
}
