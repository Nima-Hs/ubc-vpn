// Fails while the app trusts no real update key: the placeholder in
// src/main/update/keys.ts, a malformed key, or none. A build that ships
// with the placeholder can never install an update, so the release
// workflow runs this (`pnpm check:release`) before it builds anything.
// Test and development builds keep the placeholder and do not run it.
//
// keys.ts imports nothing, so Node loads it as it is, stripping its types.

import { releaseKeyProblems, TRUSTED_KEYS } from "../src/main/update/keys.ts";

const problems = releaseKeyProblems(TRUSTED_KEYS);
if (problems.length > 0) {
    console.error(
        `not a release build: ${problems.join("; ")}. Add the release public key to src/main/update/keys.ts.`,
    );
    process.exit(1);
}
console.log(`${TRUSTED_KEYS.length} update key(s), ready to release`);
