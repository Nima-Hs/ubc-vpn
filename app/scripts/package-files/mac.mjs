// What scripts/check-package.mjs requires of the packaged macOS app. It
// exports the same names as win.mjs once the .pkg installer is built
// (electron-builder.mac.yml); until then the check says so and fails.

export const NOT_BUILT_YET = "the macOS package is not built yet";
