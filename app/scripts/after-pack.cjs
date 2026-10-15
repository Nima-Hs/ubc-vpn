// electron-builder's afterPack hook (electron-builder.yml).
//
// Packaging the Electron in node_modules (electronDist) copies its folder
// as it is, so Electron's own default app and its version file come along.
// electron-builder removes them only from an Electron it downloaded itself.
// Neither belongs in the app; scripts/check-package.mjs fails if either is
// there.

const { rm } = require("node:fs/promises");
const { join } = require("node:path");

exports.default = async function afterPack(context) {
    for (const leftover of [join("resources", "default_app.asar"), "version"]) {
        await rm(join(context.appOutDir, leftover), { force: true });
    }
};
