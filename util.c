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
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "pop3d.h"

int debug = 0;

void
set_nonblocking(int fd)
{
	int	 flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl F_GETFL");

	flags |= O_NONBLOCK;
	if ((flags = fcntl(fd, F_SETFL, flags)) == -1)
		fatal("fcntl F_SETFL");
}

void
log_init(int n_debug)
{
	extern char *__progname;

	debug = n_debug;
	if (!debug)
		openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	tzset();
}

void
fatal(const char *emsg)
{
	if (errno)
		logit(LOG_CRIT, "fatal: %s: %s\n", emsg, strerror(errno));
	else
		logit(LOG_CRIT, "fatal: %s\n", emsg);

	exit(EXIT_FAILURE);
}

void
fatalx(const char *emsg)
{
	errno = 0;
	fatal(emsg);
}

void
logit(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	char *nfmt;

	if (debug) {
		/* best effort in out of mem situations */
		if (asprintf(&nfmt, "%s\n", fmt) == -1) {
			vfprintf(stderr, fmt, ap);
			fprintf(stderr, "\n");
		} else {
			vfprintf(stderr, nfmt, ap);
			free(nfmt);
		}
		fflush(stderr);
	} else
		vsyslog(pri, fmt, ap);
}

void *
xcalloc(size_t nmemb, size_t size, const char *where)
{
	void	*r;

	if ((r = calloc(nmemb, size)) == NULL) {
		logit(LOG_CRIT, "%s: calloc(%zu, %zu)", where, nmemb, size);
		err(1, "exiting");
	}

	return (r);
}

int
imsgev_xcompose(struct imsgev *iev, u_int16_t type, u_int32_t peerid,
    uint32_t pid, int fd, void *data, u_int16_t datalen, const char *where)
{
	int	r;
	r = imsgev_compose(iev, type, peerid, pid, fd, data, datalen);
	if (r == -1) {
		logit(LOG_CRIT, "imsgev_xcompose: %s", where);
		errx(1, "maildrop exiting");
	}

	return (r);
}

void
iobuf_xfqueue(struct iobuf *io, const char *where, const char *fmt, ...)
{
	va_list	ap;
	int	len;

	va_start(ap, fmt);
	len = iobuf_vfqueue(io, fmt, ap);
	va_end(ap);

	if (len == -1)
		errx(1, "%s: iobuf_xfqueue(%p, %s, ...)", where, io, fmt);
}

void
iobuf_xqueue(struct iobuf *io, const char *where, const void *data, size_t len)
{
	if (iobuf_queue(io, data, len) == -1)
		errx(1, "%s: iobuf_xqueue(%p, data, %zu)", where, io, len);
}

int
get_index(struct session *s, const char *args, unsigned int *idx)
{
	const char	*errstr;

	*idx = strtonum(args, 1, UINT_MAX, &errstr);
	if (errstr || *idx < 1 || *idx > s->nmsgs) {
		logit(LOG_INFO, "%zu: Invalid index", s->id);
		session_reply(s, "%s", "-ERR invalid index");
		return (0);
	}

	*idx -= 1; /* make it zero based */
	return (1);
}

void
log_connect(uint32_t id, struct sockaddr_storage *s, socklen_t s_len)
{
	char	hbuf[NI_MAXHOST];
	int	e;

	e = getnameinfo((struct sockaddr *)s, s_len, hbuf, sizeof(hbuf),
	    NULL, 0, NI_NUMERICHOST);
	if (e) {
		logit(LOG_DEBUG, "getnameinfo: %s", gai_strerror(e));
		logit(LOG_INFO, "new session with id %u", id);
	} else
		logit(LOG_INFO, "new session with id %u from %s", id, hbuf);
}
