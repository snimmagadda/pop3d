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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "imsgev.h"
#include "pop3d.h"
#include "ssl.h"

#define BACKLOG		5

static void auth_response(struct session *, int);
static void pop3_accept(int, short, void *);
static void pop3_listen(const char *);
static void pop3_pause(int, short, void *);
static void pop3d_imsgev(struct imsgev *, int, struct imsg *);
static void needfd(struct imsgev *);
static void sig_handler(int, short, void *);

struct imsgev		iev_pop3d;
void			*ssl_ctx;

pid_t
pop3_main(int pair[2], struct passwd *pw)
{
	extern struct session_tree	sessions;
	struct event			ev_sigint, ev_sigterm;
	pid_t				pid;

	pid = fork();
	if (pid < 0)
		fatal("pop3e: fork");

	if (pid > 0)
		return (pid);

	close(pair[0]);
	setproctitle("pop3 engine");
	SPLAY_INIT(&sessions);
	event_init();
	signal_set(&ev_sigint, SIGINT, sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	imsgev_init(&iev_pop3d, pair[1], NULL, pop3d_imsgev, needfd);
	pop3_listen("pop3");

	ssl_init();
	if ((ssl_ctx = ssl_setup()) == NULL)
		fatal("ssl_setup failed");
	pop3_listen("pop3s");

	if (chroot(pw->pw_dir) == -1 || chdir("/") == -1)
		fatal("chroot");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");

	if (event_dispatch() < 0)
		fatal("event_dispatch");

	logit(LOG_INFO, "pop3 engine exiting");
	_exit(0);
}

static void
pop3_listen(const char *port)
{
	struct listener	*l = NULL;
	struct addrinfo	hints, *res, *res0;
	int		error, opt, serrno, s;
	const char	*cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		opt = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		    &opt, sizeof(opt)) == -1)
			fatal("listener setsockopt(SO_REUSEADDR)");

		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			serrno = errno;
			cause = "bind";
			close(s);
			errno = serrno;
			continue;
		}

		set_nonblocking(s);
		if (listen(s, BACKLOG) == -1)
			fatal("listen");

		l = xcalloc(1, sizeof(*l), "pop3_listen");
		l->sock = s;
		if (strcmp(port, "pop3s") == 0)
			l->flags |= POP3S;

		event_set(&l->ev, s, EV_READ|EV_PERSIST, pop3_accept, l);
		event_add(&l->ev, NULL);
		evtimer_set(&l->pause, pop3_pause, l);
	}

	if (l == NULL)
		errx(1, "%s", cause);

	freeaddrinfo(res0);
}

static void
pop3_accept(int fd, short events, void *arg)
{
	struct sockaddr_storage ss;
	struct listener		*l = arg;
	struct timeval		timeout = {1, 0};
	socklen_t		len;
	int			s;

	len = sizeof(ss);
	s = accept(fd, (struct sockaddr *)&ss, &len);
	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&l->ev);
			evtimer_add(&l->pause, &timeout);
			return;
		default:
			fatalx("accept");
		}
	}

	set_nonblocking(s);
	l->ss = ss;
	session_init(l, s);
}

static void
pop3_pause(int fd, short events, void *arg)
{
	struct listener *l = arg;

	event_add(&l->ev, NULL);
}

static void
pop3d_imsgev(struct imsgev *iev, int code, struct imsg *imsg)
{
	extern struct session_tree	sessions;
	struct session			key, *r;

	switch (code) {
	case IMSGEV_IMSG:
		key.id = imsg->hdr.peerid;
		r = SPLAY_FIND(session_tree, &sessions, &key);
		if (r == NULL) {
			logit(LOG_INFO, "%u: session not found", key.id);
			fatalx("pop3e: session lost");
		}
		switch (imsg->hdr.type) {
		case IMSG_AUTH:
			auth_response(r, imsg->fd);
			break;
		default:
			logit(LOG_DEBUG, "%s: unexpected imsg %d",
			    __func__, imsg->hdr.type);
			break;
		}
		break;
	case IMSGEV_EREAD:
	case IMSGEV_EWRITE:
	case IMSGEV_EIMSG:
		fatal("pop3e: imsgev read/write error");
		break;
	case IMSGEV_DONE:
		event_loopexit(NULL);
		break;
	}
}

static void
auth_response(struct session *s, int fd)
{
	if (fd == -1) {
		session_reply(s, "%s", "-ERR auth failed");
		io_set_write(&s->io);
		session_close(s, 1);
		return;
	}

	session_imsgev_init(s, fd);
}

static void
needfd(struct imsgev *iev)
{
	/* XXX can anything be done to handle fd exhaustion? */
	fatalx("pop3e needs an fd");
}

static void
sig_handler(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		event_loopexit(NULL);
	}
}

