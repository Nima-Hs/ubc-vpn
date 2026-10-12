/*
 * libopenconnect reports progress through a printf-style callback. Rust
 * cannot define a function that takes "...", so this one formats the line
 * and hands Rust a plain string. It is the engine's only C code.
 *
 * A line longer than the buffer is cut short, never overrun, and Rust is
 * told that it was cut, or that it could not be formatted at all. The buffer
 * may hold a secret (the library logs the session cookie at debug level), so
 * it is wiped before returning. The pointer is volatile so that the compiler
 * keeps the wipe: without it an optimised build drops it.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* What ubc_vpn_progress_line is told about the line. */
#define UBC_VPN_LINE_WHOLE 0
#define UBC_VPN_LINE_CUT 1
#define UBC_VPN_LINE_FAILED 2

void ubc_vpn_progress_line(void *privdata, int level, const char *line, int state);

void ubc_vpn_progress(void *privdata, int level, const char *fmt, ...)
{
	char line[4096];
	volatile char *wipe = line;
	int written, state;
	size_t i;
	va_list args;

	/* So that a format that fails at once leaves an empty line. */
	line[0] = '\0';
	va_start(args, fmt);
	written = vsnprintf(line, sizeof line, fmt, args);
	va_end(args);
	line[sizeof line - 1] = '\0';
	if (written < 0)
		state = UBC_VPN_LINE_FAILED;
	else if ((size_t)written >= sizeof line)
		state = UBC_VPN_LINE_CUT;
	else
		state = UBC_VPN_LINE_WHOLE;
	ubc_vpn_progress_line(privdata, level, line, state);
	for (i = 0; i < sizeof line; i++)
		wipe[i] = 0;
}
