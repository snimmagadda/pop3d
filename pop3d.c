/*
 * Copyright (c) 2014 Sunil Nimmagadda <sunil@nimmagadda.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <bsd_auth.h>
#include <err.h>
#include <event.h>
#include <login_cap.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "imsgev.h"
#include "pop3d.h"

#define	MBOX_PATH	"/var/mail/%u"
#define MAILDIR_PATH	"~/Maildir"
#define	POP3D_USER	"_pop3d"

static void authenticate(struct imsgev *, struct imsg *);
static void pop3e_imsgev(struct imsgev *, int , struct imsg *);
static void needfd(struct imsgev *);
static void sig_handler(int, short, void *);
static enum m_type m_type(const char *);
static void usage(void);

static struct imsgev	iev_pop3e;
static pid_t		pop3e_pid;
static const char	*mpath = MBOX_PATH;
static int		mtype = M_MBOX;
static int		afamily = AF_UNSPEC;

int
main(int argc, char *argv[])
{
	struct passwd	*pw;
	struct event	ev_sigint, ev_sigterm, ev_sighup, ev_sigchld;
	const char	*mtype_str = "mbox";
	int		ch, d = 0, pair[2];

	while ((ch = getopt(argc, argv, "dp:t:46")) != -1) {
		switch (ch) {
		case '4':
			afamily = AF_INET;
			break;
		case '6':
			afamily = AF_INET6;
			break;
		case 'd':
			d = 1;
			break;
		case 'p':
			mpath = optarg;
			break;
		case 't':
			if ((mtype = m_type(optarg)) == -1)
				errx(1, "%s invalid argument", optarg);
			if (mtype == M_MAILDIR)
				mpath = MAILDIR_PATH;
			mtype_str = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || *argv)
		usage();

	log_init(d);
	if (geteuid())
		fatalx("need root privileges");

	if (!d && daemon(1, 0) == -1)
		fatal("failed to daemonize");

	if (socketpair(AF_UNIX, SOCK_STREAM, AF_UNSPEC, pair) == -1)
		fatal("socketpair");

	set_nonblocking(pair[0]);
	set_nonblocking(pair[1]);
	if ((pw = getpwnam(POP3D_USER)) == NULL)
		fatalx("main: getpwnam " POP3D_USER);

	pop3e_pid = pop3_main(pair, afamily, pw);
	close(pair[1]);
	setproctitle("[priv]");
	logit(LOG_INFO, "pop3d ready; type:%s, path:%s", mtype_str, mpath);
	event_init();
	signal_set(&ev_sigint, SIGINT, sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	imsgev_init(&iev_pop3e, pair[0], NULL, pop3e_imsgev, needfd);
	if (event_dispatch() < 0)
		fatal("event_dispatch");

	logit(LOG_INFO, "pop3d exiting");
	return (0);
}

static void
pop3e_imsgev(struct imsgev *iev, int code, struct imsg *imsg)
{
	switch (code) {
	case IMSGEV_IMSG:
		switch (imsg->hdr.type) {
		case IMSG_AUTH:
			authenticate(iev, imsg);
			break;
		default:
			logit(LOG_DEBUG, "%s: unexpected imsg %u",
			    __func__, imsg->hdr.type);
			break;
		}
		break;
	case IMSGEV_EREAD:
	case IMSGEV_EWRITE:
	case IMSGEV_EIMSG:
		fatal("pop3d: imsgev read/write error");
		break;
	case IMSGEV_DONE:
		event_loopexit(NULL);
		break;
	}
}

static void
authenticate(struct imsgev *iev, struct imsg *imsg)
{
	struct auth_req	*req = imsg->data;
	struct passwd	*pw;
	int		pair[2];

	if (auth_userokay(req->user, NULL, "auth-pop3", req->pass) == 0) {
		logit(LOG_INFO, "%u: auth [%s] failed",
		    imsg->hdr.peerid, req->user);
		pair[0] = -1;
		goto end;
	}

	logit(LOG_INFO, "%u: auth [%s] passed", imsg->hdr.peerid,
	    req->user);
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair) == -1)
		fatal("socketpair");

	set_nonblocking(pair[0]);
	set_nonblocking(pair[1]);
	if ((pw = getpwnam(req->user)) == NULL)
		fatalx("authenticate: getpwnam");

	if (maildrop_init(imsg->hdr.peerid, pair, pw, mtype, mpath) == -1) {
		logit(LOG_INFO, "%u: unable to fork maildrop process",
		    imsg->hdr.peerid);
		pair[0] = -1;
		goto end;
	}

	close(pair[1]);
end:
	imsgev_xcompose(iev, IMSG_AUTH, imsg->hdr.peerid, 0,
	    pair[0], NULL, 0, "authenticate");
}

static void
needfd(struct imsgev *iev)
{
	fatalx("pop3d should never need an fd");
}

static void
sig_handler(int sig, short event, void *arg)
{
	int status;

	switch (sig) {
	case SIGINT:
	case SIGHUP:
	case SIGTERM:
		imsgev_clear(&iev_pop3e);
		imsgev_close(&iev_pop3e);
		event_loopexit(NULL);
		break;
	case SIGCHLD:
		if (waitpid(pop3e_pid, &status, WNOHANG) > 0)
			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				logit(LOG_ERR, "Lost pop3 engine");
				event_loopexit(NULL);
			}
		break;
	}
}

static enum m_type
m_type(const char *str)
{
	if (strcasecmp(str, "mbox") == 0)
		return M_MBOX;

	if (strcasecmp(str, "maildir") == 0)
		return M_MAILDIR;

	return (-1);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-p path] [-t type]\n", __progname);
	exit(EXIT_FAILURE);
}

