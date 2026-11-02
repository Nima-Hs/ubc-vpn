// What scripts/check-package.mjs requires of the packaged Linux app. It
// exports the same names as win.mjs once the .deb and .rpm packages are
// built (electron-builder.linux.yml); until then the check says so and fails.

export const NOT_BUILT_YET = "the Linux package is not built yet";
