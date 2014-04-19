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
#include <sys/stat.h>

#include <event.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "imsgev.h"
#include "pop3d.h"

static void session_imsgev(struct imsgev *, int, struct imsg *);
static void update(struct imsgev *, struct imsg *, struct m_backend *);
static void retr(struct imsgev *, struct imsg *, struct m_backend *);
static void dele(struct imsgev *, struct imsg *, struct m_backend *);
static void rset(struct imsgev *, struct imsg *, struct m_backend *);
static void list(struct imsgev *, struct imsg *, struct m_backend *);
static void list_all(struct imsgev *, struct imsg *, struct m_backend *);
static void do_list(unsigned int, size_t *, char *, size_t);
static struct m_backend *m_backend_lookup(enum m_type);
static void sig_handler(int, short, void *);
static void needfd(struct imsgev *);
static size_t expand(char *, const char *, size_t, struct passwd *);

static struct mdrop m;

pid_t
maildrop_init(uint32_t session_id, int pair[2], struct passwd *pw,
    int type, const char *path)
{
	struct imsgev		iev_session;
	struct event		ev_sigint, ev_sigterm;
	struct stats		stats;
	struct m_backend	*mb;
	char			buf[MAXPATHLEN];
	pid_t			pid;
	mode_t			old_mask;
	int			fd, flags, res = -1;

	if ((pid = fork()) != 0)
		return (pid);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");

	close(pair[0]);
	setproctitle("maildrop");
	if ((mb = m_backend_lookup(type)) == NULL)
		fatalx("maildrop: invalid backend");

	if (expand(buf, path, sizeof(buf), pw) >= sizeof(buf))
		fatalx("maildrop: path truncation");

	flags = O_CREAT;
	if (type == M_MBOX)
		flags |= O_RDWR;
	else
		flags |= O_RDONLY;

	old_mask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if ((fd = open(buf, flags)) == -1)
		logit(LOG_CRIT, "%zu: failed to open %s", session_id , buf);

	if (fd != -1) {
		m.fd = fd;
		res = mb->init(&m, &stats.nmsgs, &stats.sz);
	}

	umask(old_mask);
	event_init();
	signal_set(&ev_sigint, SIGINT, sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	imsgev_init(&iev_session, pair[1], mb, session_imsgev, needfd);

	if (res == 0) {
		imsgev_xcompose(&iev_session, IMSG_MAILDROP_INIT, session_id,
		    0, -1, &stats, sizeof(struct stats), "maildrop_init");
	} else {
		logit(LOG_CRIT, "%zu: maildrop init failed %s",
		    session_id, buf);
		imsgev_xcompose(&iev_session, IMSG_MAILDROP_INIT, session_id,
		    0, -1, NULL, 0, "maildrop_init");
	}

	if (event_dispatch() < 0)
		fatal("event_dispatch");

	logit(LOG_INFO, "maildrop process exiting");
	_exit(0);
}

/*
 * Build dst by substituting '~' with user's home dir and '%u' with user name
 * in src. Return the length of string built. If return value >= dst_sz then
 * dst is truncated. 
 */
static size_t
expand(char *dst, const char *src, size_t dst_sz, struct passwd *pw)
{
	size_t	i = 0, r;
	int	c;

	memset(dst, 0, dst_sz);
	while ((c = *src++)) {
		if (i >= dst_sz)
			break;

		switch (c) {
		case '~':
			if ((r = strlcpy(&dst[i], pw->pw_dir,
			    (dst_sz - i))) >= (dst_sz - i)) {
				i += r;
				goto end;
			}
			i += r;
			break;
		case '%':
			if (*src == 'u') {
				if ((r = strlcpy(&dst[i], pw->pw_name,
				    (dst_sz - i))) >= (dst_sz - i)) {
					i += r;
					goto end;
				}
				i += r;
				src++;
			} else
				dst[i++] = c;
			break;
		default:
			dst[i++] = c;
			break;
		}
	}

end:
	if (c)
		while ((c = *src++))
			i++;

	dst[dst_sz - 1] = '\0';
	return (i);
}

static void
session_imsgev(struct imsgev *iev, int code, struct imsg *imsg)
{
	struct m_backend	*mb = iev->data;

	switch (code) {
	case IMSGEV_IMSG:
		switch (imsg->hdr.type) {
		case IMSG_MAILDROP_UPDATE:
			update(iev, imsg, mb);
			break;
		case IMSG_MAILDROP_RETR:
			retr(iev, imsg, mb);
			break;
		case IMSG_MAILDROP_DELE:
			dele(iev, imsg, mb);
			break;
		case IMSG_MAILDROP_RSET:
			rset(iev, imsg, mb);
			break;
		case IMSG_MAILDROP_LIST:
			list(iev, imsg, mb);
			break;
		case IMSG_MAILDROP_LISTALL:
			list_all(iev, imsg, mb);
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
		fatal("maildrop: imsgev read/write error");
		break;
	case IMSGEV_DONE:
		event_loopexit(NULL);
		break;
	}
}

static void
update(struct imsgev *iev, struct imsg *imsg, struct m_backend *mb)
{
	int		res;
	uint32_t	session_id = imsg->hdr.peerid;

	if ((res = mb->update(&m)) == 0)
		logit(LOG_INFO, "%zu: maildrop updated", session_id);
	else
		logit(LOG_CRIT, "%zu: maildrop updated failed", session_id);

	imsgev_xcompose(iev, IMSG_MAILDROP_UPDATE, session_id,  0,
	    -1, &res, sizeof(res), "maildrop_update");
}

static void
retr(struct imsgev *iev, struct imsg *imsg, struct m_backend *mb)
{
	struct retr_res	res;
	struct retr_req	*req = imsg->data;
	int		fd;

	fd = mb->retr(&m, req->idx, &res.nlines, &res.offset);
	/* pass on top arguments */
	res.top = req->top;
	res.ntop = req->ntop;
	imsgev_xcompose(iev, IMSG_MAILDROP_RETR, imsg->hdr.peerid, 0,
	    fd, &res, sizeof(res), "maildrop_retr");
}

static void
dele(struct imsgev *iev, struct imsg *imsg, struct m_backend *mb)
{
	unsigned int	*idx = imsg->data;
	int		res = 0;

	if (m.msgs_index[*idx]->flags & F_DELE) {
		res = -1;
		goto end;
	}

	m.msgs_index[*idx]->flags |= F_DELE;
end:
	imsgev_xcompose(iev, IMSG_MAILDROP_DELE, imsg->hdr.peerid, 0,
	    -1, &res, sizeof(res), "maildrop_dele");
}

static void
rset(struct imsgev *iev, struct imsg *imsg, struct m_backend *mb)
{
	size_t	i;

	for (i = 0; i < m.nmsgs; i++)
		m.msgs_index[i]->flags = 0;

	imsgev_xcompose(iev, IMSG_MAILDROP_RSET, imsg->hdr.peerid, 0,
	    -1, NULL, 0, "maildrop_rset");
}

static void
list(struct imsgev *iev, struct imsg *imsg, struct m_backend *mb)
{
	struct list_req	*req = imsg->data;
	struct list_res	res;
	char		hash[SHA1_DIGEST_STRING_LENGTH];
	size_t		sz;

	res.idx = req->idx;
	do_list(req->idx, &sz, hash, sizeof(hash));
	res.uidl = req->uidl;
	if (res.uidl)
		(void)strlcpy(res.u.hash, hash, sizeof(res.u.hash));
	else
		res.u.sz = sz;

	imsgev_xcompose(iev, IMSG_MAILDROP_LIST, imsg->hdr.peerid, 0,
	    -1, &res, sizeof(res), "maildrop_list");

}

static void
do_list(unsigned int idx, size_t *sz, char *hash, size_t hash_sz)
{
	if (m.msgs_index[idx]->flags & F_DELE) {
		*sz = 0;
		(void)strlcpy(hash, "", hash_sz);
		return;
	}

	*sz = m.msgs_index[idx]->sz;
	(void)strlcpy(hash, m.msgs_index[idx]->hash, hash_sz);
}

static void
list_all(struct imsgev *iev, struct imsg *imsg, struct m_backend *mb)
{
	struct list_res	res;
	size_t		i;
	int		*uidl = imsg->data;

	for (i = 0; i < m.nmsgs; i++) {
		if (m.msgs_index[i]->flags & F_DELE)
			continue;

		res.idx = i;
		res.uidl = *uidl;
		if (*uidl) {
			(void)strlcpy(res.u.hash, m.msgs_index[i]->hash,
			    sizeof(res.u.hash));
		} else
			res.u.sz = m.msgs_index[i]->sz;
		
		imsgev_xcompose(iev, IMSG_MAILDROP_LISTALL,
		    imsg->hdr.peerid, 0, -1, &res, sizeof(res),
		    "maildrop_list");
	}
	
	res.uidl = *uidl;
	/* terminal sentinel: hash = "" and sz = 0 */
	if (*uidl)
		(void)strlcpy(res.u.hash, "", sizeof(res.u.hash));
	else
		res.u.sz = 0;

	imsgev_xcompose(iev, IMSG_MAILDROP_LISTALL, imsg->hdr.peerid,
	    0, -1, &res, sizeof(res), "maildrop_list");
}

static void
needfd(struct imsgev *iev)
{
	fatalx("maildrop should never need an fd");
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

extern struct m_backend m_backend_mbox;
extern struct m_backend m_backend_maildir;

static struct m_backend *
m_backend_lookup(enum m_type type)
{
	switch (type) {
	case M_MBOX:
		return &m_backend_mbox;
		break;
	case M_MAILDIR:
		return &m_backend_maildir;
		break;
	default:
		fatalx("m_backend_lookup: invalid m_type");
	};

	return (NULL);
}

