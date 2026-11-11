/*
 * Exercises openconnect_set_hip_report_handler() against a fake
 * GlobalProtect gateway (njvack/gp-fake-gateway). Not part of make check;
 * run through tests/macos/hip-handler.sh.
 *
 *   hip-handler-client SERVER PIN [fail]
 *
 * Logs in as test/test, answers the challenge with "1", and sets up the
 * session (getconfig, HIP check, HIP report from the handler, tunnel).
 * With "fail", the handler fails instead. Exits 0 if session setup
 * succeeded and the handler was called.
 */
#define _GNU_SOURCE /* asprintf */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openconnect.h"

static struct openconnect_info *vpninfo;
static const char *pin;
static int fail_handler;
static int handler_calls;
static int forms_seen;

static int validate_peer_cert(void *privdata, const char *reason)
{
	return openconnect_check_peer_cert_hash(vpninfo, pin) ? -1 : 0;
}

static int process_auth_form(void *privdata, struct oc_auth_form *form)
{
	int challenge = form->auth_id && !strcmp(form->auth_id, "_challenge");
	struct oc_form_opt *opt;

	if (++forms_seen > 10)
		return OC_FORM_RESULT_ERR; /* don't loop forever on a bad login */
	for (opt = form->opts; opt; opt = opt->next) {
		if (opt->type == OC_FORM_OPT_TEXT && !strcmp(opt->name, "user"))
			openconnect_set_option_value(opt, "test");
		else if (opt->type == OC_FORM_OPT_PASSWORD || opt->type == OC_FORM_OPT_TEXT)
			/* "1" answers the push challenge */
			openconnect_set_option_value(opt, challenge ? "1" : "test");
	}
	return OC_FORM_RESULT_OK;
}

static void progress(void *privdata, int level, const char *fmt, ...)
{
	va_list args;

	if (level > PRG_INFO)
		return;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static int hip_report(void *privdata, const struct oc_hip_report_request *req, char **report)
{
	const char *cookie = openconnect_get_cookie(vpninfo);

	handler_calls++;
	fprintf(stderr, "handler: md5=%s client_ip=%s client_os=%s cookie=%s\n",
		req->md5, req->client_ip ? : "(none)", req->client_os,
		cookie ? "(set)" : "(none)");
	if (!req->md5 || !req->client_os || !cookie)
		return -EINVAL;
	if (fail_handler)
		return -EIO;
	if (asprintf(report,
		     "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		     "<hip-report name=\"hip-report\">\n"
		     "<md5-sum>%s</md5-sum>\n"
		     "<user-name>test</user-name>\n"
		     "<host-name>hip-handler-client</host-name>\n"
		     "<ip-address>%s</ip-address>\n"
		     "<hip-report-version>4</hip-report-version>\n"
		     "<categories/>\n"
		     "</hip-report>\n",
		     req->md5, req->client_ip ? : "") < 0)
		return -ENOMEM;
	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	if (argc < 3) {
		fprintf(stderr, "usage: %s SERVER PIN [fail]\n", argv[0]);
		return 2;
	}
	pin = argv[2];
	fail_handler = argc > 3 && !strcmp(argv[3], "fail");

	openconnect_init_ssl();
	vpninfo = openconnect_vpninfo_new("hip-handler-client", validate_peer_cert, NULL,
					  process_auth_form, progress, NULL);
	if (!vpninfo)
		return 1;
	if (openconnect_set_protocol(vpninfo, "gp") ||
	    openconnect_parse_url(vpninfo, argv[1]))
		return 1;
	openconnect_set_hip_report_handler(vpninfo, hip_report);

	ret = openconnect_obtain_cookie(vpninfo);
	if (ret) {
		fprintf(stderr, "obtain_cookie failed: %d\n", ret);
		return 1;
	}
	ret = openconnect_make_cstp_connection(vpninfo);
	fprintf(stderr, "make_cstp_connection: %d, handler calls: %d\n", ret, handler_calls);
	openconnect_vpninfo_free(vpninfo);
	return (ret == 0 && handler_calls > 0) ? 0 : 1;
}
