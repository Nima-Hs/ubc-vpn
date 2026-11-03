// electron-builder's afterPack hook (electron-builder.yml).
//
// Packaging the Electron in node_modules (electronDist) copies its folder
// as it is, so Electron's own default app and its version file come along.
// electron-builder removes them only from an Electron it downloaded itself.
// Neither belongs in the app; scripts/check-package.mjs fails if either is
// there.
//
// On Linux and macOS that copy also keeps the modes the files had in
// node_modules, where some are writable by the group. The packages install
// every file with the mode it has here, owned by root, and nobody but root
// may change the app, so group and other write is taken off everything. A
// mode is not part of what a macOS signature covers. The installer workflows
// check the installed app.

const { chmod, lstat, readdir, rm } = require("node:fs/promises");
const { join } = require("node:path");

async function closeToOthers(path) {
    const found = await lstat(path);
    if (found.isSymbolicLink()) {
        return;
    }
    await chmod(path, found.mode & 0o7755);
    if (found.isDirectory()) {
        for (const name of await readdir(path)) {
            await closeToOthers(join(path, name));
        }
    }
}

exports.default = async function afterPack(context) {
    if (context.electronPlatformName === "darwin") {
        const app = join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
        await rm(join(app, "Contents", "Resources", "default_app.asar"), { force: true });
        await closeToOthers(app);
        return;
    }
    for (const leftover of [join("resources", "default_app.asar"), "version"]) {
        await rm(join(context.appOutDir, leftover), { force: true });
    }
    if (context.electronPlatformName === "linux") {
        await closeToOthers(context.appOutDir);
    }
};
