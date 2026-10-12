/*
 * libopenconnect reports progress through a printf-style callback. Rust
 * cannot define a function that takes "...", so this one formats the line
 * and hands Rust a plain string. It is the engine's only C code.
 *
 * A line longer than the buffer is cut short, never overrun. The buffer may
 * hold a secret (the library logs the session cookie at debug level), so it
 * is wiped before returning.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void ubc_vpn_progress_line(void *privdata, int level, const char *line);

void ubc_vpn_progress(void *privdata, int level, const char *fmt, ...)
{
	char line[4096];
	volatile char *wipe = line;
	size_t i;
	va_list args;

	va_start(args, fmt);
	vsnprintf(line, sizeof line, fmt, args);
	va_end(args);
	line[sizeof line - 1] = '\0';
	ubc_vpn_progress_line(privdata, level, line);
	for (i = 0; i < sizeof line; i++)
		wipe[i] = 0;
}
