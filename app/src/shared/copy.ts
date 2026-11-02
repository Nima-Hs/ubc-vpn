// Every word the app shows about the connection, so the window and the tray
// always say the same thing. Each screen's words are in a file of their own
// in `copy/`; this file gathers them, so every import of `@shared/copy` reads
// from here. The Settings screen's words are apart, in `settings-copy.ts`,
// because only builds with that screen carry them.
//
// The rules: sentence case, plain words, no exclamation marks. A message about
// a problem says what happened, then what to do next.

export * from "./copy/connection";
export * from "./copy/login";
export * from "./copy/logs";
export * from "./copy/notices";
export * from "./copy/routes";
export * from "./copy/tray";
