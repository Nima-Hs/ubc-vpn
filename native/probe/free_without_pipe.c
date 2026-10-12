/*
 * Shows whether libopenconnect closes file descriptor 0 when it frees a
 * handle that never made a command pipe. libopenconnect 9.21 does; our
 * builds carry a patch that stops it (patches/openconnect in each native
 * folder). Exits 0 if descriptor 0 is still open afterwards, 1 if not.
 *
 * Run it with standard input open, for example from /dev/null:
 *
 *   cc free_without_pipe.c $(pkg-config --cflags --libs openconnect) -o free_without_pipe
 *   ./free_without_pipe </dev/null
 */
#include <fcntl.h>
#include <stdio.h>

#include <openconnect.h>

static int validate(void *privdata, const char *reason)
{
	(void)privdata;
	(void)reason;
	return 1;
}

static int form(void *privdata, struct oc_auth_form *auth_form)
{
	(void)privdata;
	(void)auth_form;
	return OC_FORM_RESULT_CANCELLED;
}

static void progress(void *privdata, int level, const char *fmt, ...)
{
	(void)privdata;
	(void)level;
	(void)fmt;
}

static int is_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

int main(void)
{
	struct openconnect_info *vpninfo;
	int open_after;

	if (!is_open(0)) {
		fprintf(stderr, "error: run this with standard input open\n");
		return 2;
	}
	if (openconnect_init_ssl()) {
		fprintf(stderr, "error: openconnect_init_ssl failed\n");
		return 2;
	}
	printf("library: %s\n", openconnect_get_version());
	printf("before: descriptor 0 is open\n");

	vpninfo = openconnect_vpninfo_new("free-without-pipe", validate, NULL, form, progress, NULL);
	if (!vpninfo) {
		fprintf(stderr, "error: openconnect_vpninfo_new failed\n");
		return 2;
	}
	/* No openconnect_setup_cmd_pipe() here. */
	openconnect_vpninfo_free(vpninfo);

	open_after = is_open(0);
	printf("after:  descriptor 0 is %s\n", open_after ? "open" : "closed");
	return open_after ? 0 : 1;
}
