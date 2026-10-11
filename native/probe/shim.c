#include <stdarg.h>
#include <stdio.h>
void rust_progress(void *priv, int level, const char *msg);
/* libopenconnect's progress callback is printf-style variadic; format here, hand Rust a plain string. */
void oc_progress_shim(void *priv, int level, const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    rust_progress(priv, level, buf);
}
