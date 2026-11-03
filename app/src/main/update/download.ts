// Where a downloaded installer is kept, and how it gets there: into a
// folder of the app's own that only the user can write, stopping at the
// size the signed list gives, and kept only once its size and SHA-256 match
// the list. This and `security.ts` are the only app code that touches the
// file system; neither goes near the settings file.

import { lstat, mkdir, open, readdir, rename, rm } from "node:fs/promises";
import { join, posix, win32 } from "node:path";
import { eachChunk } from "./github";
import { checkInstaller, type UpdateFile, UpdateRefused } from "./list";

/**
 * The folder for downloaded installers, in the user's local (not roaming)
 * profile, or `null` where there is none to use.
 */
export function updatesFolder(
    platform: NodeJS.Platform,
    env: NodeJS.ProcessEnv,
    home: string,
): string | null {
    switch (platform) {
        case "win32": {
            const local = env.LOCALAPPDATA;
            return local !== undefined && win32.isAbsolute(local)
                ? win32.join(local, "UBC VPN", "updates")
                : null;
        }
        case "darwin":
            return posix.join(home, "Library", "Caches", "UBC VPN", "updates");
        default: {
            const cache = env.XDG_CACHE_HOME;
            const base =
                cache !== undefined && posix.isAbsolute(cache) ? cache : posix.join(home, ".cache");
            return posix.join(base, "ubc-vpn", "updates");
        }
    }
}

/**
 * Makes the folder, for the user alone, and empties it: nothing from an
 * earlier download is ever used. On macOS and Linux it must be a real
 * folder, the user's own, that no one else can write; on Windows the
 * user's local profile is the user's alone already.
 */
export async function prepareFolder(folder: string): Promise<void> {
    await mkdir(folder, { recursive: true, mode: 0o700 });
    const info = await lstat(folder);
    // Windows reports no owner and no mode bits that mean anything here.
    const mine =
        process.platform === "win32" ||
        (process.getuid !== undefined &&
            info.uid === process.getuid() &&
            (info.mode & 0o022) === 0);
    if (!info.isDirectory() || info.isSymbolicLink() || !mine) {
        throw new UpdateRefused("the updates folder is not the user's alone");
    }
    for (const name of await readdir(folder)) {
        await rm(join(folder, name), { recursive: true, force: true });
    }
}

/**
 * Writes the body of `response` to `<folder>/<name>.part`, stopping as soon
 * as it passes the size the list gives, then checks the whole file against
 * the list and only then names it `<folder>/<name>`. Returns that path.
 * The folder must have been prepared; a file already there is not reused.
 */
export async function saveInstaller(
    response: Response,
    entry: UpdateFile,
    folder: string,
    idleMs?: number,
): Promise<string> {
    const partial = join(folder, `${entry.name}.part`);
    const done = join(folder, entry.name);
    // Read and write, and never a file that is there already.
    const file = await open(partial, "wx+", 0o600);
    try {
        let received = 0;
        await eachChunk(
            response,
            async (chunk) => {
                received += chunk.length;
                if (received > entry.size) {
                    throw new UpdateRefused("the installer is larger than the list gives");
                }
                await file.write(chunk);
            },
            idleMs,
        );
        await file.sync();
        await checkInstaller(file, entry);
    } catch (error) {
        await file.close();
        await rm(partial, { force: true });
        throw error;
    }
    await file.close();
    await rename(partial, done);
    return done;
}
