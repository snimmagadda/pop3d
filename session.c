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

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "imsgev.h"
#include "pop3d.h"
#include "ssl.h"

#define MAXLINESIZE	2048
#define TIMEOUT		600000

enum pop_command {
	CMD_STLS = 0,
	CMD_CAPA,
	CMD_USER,
	CMD_PASS,
	CMD_QUIT,
	CMD_STAT,
	CMD_RETR,
	CMD_LIST,
	CMD_DELE,
	CMD_RSET,
	CMD_TOP,
	CMD_UIDL,
	CMD_NOOP
};

enum arg_constraint {
	OPTIONAL = 1,
	PROHIBITED,
	REQUIRED
};

static struct {int code; enum arg_constraint c; const char *cmd;} commands[] = {
	{CMD_STLS, PROHIBITED, "STLS"},
	{CMD_CAPA, PROHIBITED, "CAPA"},
	{CMD_USER, REQUIRED, "USER"},
	{CMD_PASS, REQUIRED, "PASS"},
	{CMD_QUIT, PROHIBITED, "QUIT"},
	{CMD_STAT, PROHIBITED, "STAT"},
	{CMD_RETR, REQUIRED, "RETR"},
	{CMD_LIST, OPTIONAL, "LIST"},
	{CMD_DELE, REQUIRED, "DELE"},
	{CMD_RSET, PROHIBITED, "RSET"},
	{CMD_TOP,  REQUIRED, "TOP"},
	{CMD_UIDL, OPTIONAL, "UIDL"},
	{CMD_NOOP, PROHIBITED, "NOOP"},
	{-1, OPTIONAL, NULL}
};

static void auth_request(struct session *);
static void capa(struct session *);
static void command(struct session *, int, char *);
static void session_io(struct io *, int);
static void parse(struct session *, char *);
static void auth_command(struct session *, int, char *);
static void trans_command(struct session *, int, char *);
static void get_list_all(struct session *, int);
static void get_list(struct session *, unsigned int, int);
static void maildrop_imsgev(struct imsgev *, int, struct imsg *);
static void handle_init(struct session *, struct imsg *);
static void handle_retr(struct session *, struct imsg *);
static void handle_dele(struct session *, struct imsg *);
static void handle_list(struct session *, struct imsg *);
static void handle_list_all(struct session *, struct imsg *);
static void handle_update(struct session *, struct imsg *);
static void needfd(struct imsgev *);
static void pop3_debug(char *, ...);
static void session_write(struct session *, const char *, size_t);
static const char *strstate(enum state);

struct session_tree	sessions;
static int		_pop3_debug = 0;

void
session_init(struct listener *l, int fd)
{
	struct session	*s;
	void		*ssl;
	extern void	*ssl_ctx;

	s = xcalloc(1, sizeof(*s), "session_init");
	s->l = l;
	if (iobuf_init(&s->iobuf, 0, 0) == -1)
		fatal("iobuf_init");

	io_init(&s->io, fd, s, session_io, &s->iobuf);
	io_set_timeout(&s->io, TIMEOUT);
	s->id = arc4random();
	s->state = AUTH;
	if (s->l->flags & POP3S) {
		s->flags |= POP3S;
		ssl = pop3s_init(ssl_ctx, fd);
		io_set_read(&s->io);
		io_start_tls(&s->io, ssl);
		return;
	}

	log_connect(s->id, &l->ss, l->ss.ss_len);
	SPLAY_INSERT(session_tree, &sessions, s);
	session_reply(s, "%s", "+OK pop3d ready");
	io_set_write(&s->io);
}

void
session_close(struct session *s, int flush)
{
	struct session *entry;

	entry = SPLAY_REMOVE(session_tree, &sessions,  s);
	if (entry == NULL) {
		/* STARTTLS session was in progress and got interrupted */
		logit(LOG_DEBUG, "%u: not in tree", s->id);
		entry = s;
	}

	if (flush) {
		if (entry->flags & POP3S)
			iobuf_flush_ssl(&entry->iobuf, entry->io.ssl);
		else
			iobuf_flush(&entry->iobuf, entry->io.sock);
	}

	io_clear(&entry->io);
	iobuf_clear(&entry->iobuf);
	imsgev_clear(entry->iev_maildrop);
	entry->iev_maildrop->terminate = 1;
	logit(LOG_INFO, "%u: session closed", entry->id);
	free(entry);
}

static void
session_io(struct io *io, int evt)
{
	struct session	*s = io->arg;
	char		*line;
	size_t		len;

	pop3_debug("%u: %s", s->id, io_strevent(evt));
	switch (evt) {
	case IO_DATAIN:
		line = iobuf_getline(&s->iobuf, &len);
		if (line == NULL) {
			iobuf_normalize(&s->iobuf);
			break;
		}
		if (strncasecmp(line, "PASS", 4) == 0)
			pop3_debug(">>> PASS");
		else
			pop3_debug(">>> %s", line);
		parse(s, line);
		break;
	case IO_LOWAT:
		if (iobuf_queued(&s->iobuf) == 0)
			io_set_read(io);
		break;
	case IO_TLSREADY:
		/* greet only for pop3s, STLS already greeted */
		if (s->flags & POP3S) {
			log_connect(s->id, &s->l->ss, s->l->ss.ss_len);
			session_reply(s, "%s", "+OK pop3 ready");
			io_set_write(&s->io);
		}
		SPLAY_INSERT(session_tree, &sessions, s);
		/* mark STLS session as secure */
		s->flags |= POP3S;
		logit(LOG_INFO, "%u: TLS ready", s->id);
		break;
	case IO_DISCONNECTED:
	case IO_TIMEOUT:
	case IO_ERROR:
		session_close(s, 0);
		break;
	default:
		logit(LOG_DEBUG, "unknown event %s", io_strevent(evt));
		break;
	}
}

static void
parse(struct session *s, char *line)
{
	enum arg_constraint	c = OPTIONAL;
	int			i, cmd = -1;
	char			*args;

	/* trim newline */
	line[strcspn(line, "\n")] = '\0';

	args = strchr(line, ' ');
	if (args) {
		*args++ = '\0';
		while (isspace((unsigned char)*args))
			args++;
	}

	for (i = 0; commands[i].code != -1; i++) {
		if (strcasecmp(line, commands[i].cmd) == 0) {
			cmd = commands[i].code;
			c = commands[i].c;
			break;
		}
	}

	if (cmd == -1) {
		logit(LOG_INFO, "%u: invalid command %s", s->id, line);
		session_reply(s, "%s", "-ERR invalid command");
		io_set_write(&s->io);
		return;
	}

	if (c == PROHIBITED && args) {
		session_reply(s, "%s", "-ERR no arguments allowed");
		io_set_write(&s->io);
		return;
	} else if ((c == REQUIRED) &&
	    (args == NULL || strlen(args) >= ARGLEN)) {
		session_reply(s, "%s", "-ERR args required or too long");
		io_set_write(&s->io);
		return;
	}

	command(s, cmd, args);
}

static void
command(struct session *s, int cmd, char *args)
{
	switch (s->state) {
	case AUTH:
		auth_command(s, cmd, args);
		break;
	case TRANSACTION:
		trans_command(s, cmd, args);
		break;
	case UPDATE:
		session_reply(s, "%s", "-ERR commands not allowed");
		io_set_write(&s->io);
		break;
	default:
		fatalx("Invalid state");
	}
}

static void
auth_command(struct session *s, int cmd, char *args)
{
	extern void	*ssl_ctx;
	void		*ssl;

	switch (cmd) {
	case CMD_STLS:
		if (s->flags & POP3S) {
			session_reply(s, "%s", "-ERR already secured");
			break;
		}
		session_reply(s, "%s", "+OK");
		io_set_write(&s->io);
		iobuf_flush(&s->iobuf, s->io.sock);
		/* add back when IO_TLSREADY. */
		SPLAY_REMOVE(session_tree, &sessions, s);
		ssl = pop3s_init(ssl_ctx, s->io.sock);
		io_set_read(&s->io);
		io_start_tls(&s->io, ssl);
		return;
	case CMD_CAPA:
		capa(s);
		break;
	case CMD_USER:
		(void)strlcpy(s->user, args, sizeof(s->user));
		session_reply(s, "%s", "+OK");
		break;
	case CMD_PASS:
		if (s->user[0] == '\0') {
			session_reply(s, "%s", "-ERR no USER specified");
			break;
		}
		(void)strlcpy(s->pass, args, sizeof(s->pass));
		auth_request(s);
		return;
	case CMD_QUIT:
		session_reply(s, "%s", "+OK");
		io_set_write(&s->io);
		session_close(s, 1);
		return;
	default:
		session_reply(s, "%s", "-ERR invalid command");
		break;
	}

	io_set_write(&s->io);
}

static void
auth_request(struct session *s)
{
	extern struct imsgev	iev_pop3d;
	struct auth_req		req;

	memset(&req, 0, sizeof(req));
	(void)strlcpy(req.user, s->user, sizeof(req.user));
	(void)strlcpy(req.pass, s->pass, sizeof(req.pass));
	imsgev_xcompose(&iev_pop3d, IMSG_AUTH, s->id, 0, -1,
	    &req, sizeof(req), "auth_request");
}

static void
capa(struct session *s)
{
	session_reply(s, "%s", "+OK");
	session_reply(s, "%s", "STLS");
	session_reply(s, "%s", "USER");
	session_reply(s, "%s", "TOP");
	session_reply(s, "%s", "UIDL");
	session_reply(s, "%s", "IMPLEMENTATION pop3d");
	session_reply(s, "%s", ".");
}

static void
trans_command(struct session *s, int cmd, char *args)
{
	struct retr_req	retr_req;
	unsigned int	idx, n;
	char		*c;
	const char	*errstr;
	int		uidl = 0;

	memset(&retr_req, 0, sizeof(retr_req));
	switch (cmd) {
	case CMD_CAPA:
		capa(s);
		break;
	case CMD_STAT:
		session_reply(s, "%s %zu %zu", "+OK", s->nmsgs, s->m_sz);
		break;
	case CMD_TOP:
		if ((c = strchr(args, ' ')) == NULL) {
			session_reply(s, "%s", "-ERR invalid arguments");
			break;
		}
		*c++ = '\0';
		n = strtonum(c, 0, UINT_MAX, &errstr);
		if (errstr) {
			session_reply(s, "%s", "-ERR invalid n");
			break;
		}
		retr_req.top = 1;
		retr_req.ntop = n;
		/* FALLTRHROUGH */
	case CMD_RETR:
		if (!get_index(s, args, &retr_req.idx))
			break;
		imsgev_xcompose(s->iev_maildrop, IMSG_MAILDROP_RETR,
		    s->id, 0, -1, &retr_req, sizeof(retr_req), "trans_command");
		return;
	case CMD_NOOP:
		session_reply(s, "%s", "+OK");
		break;
	case CMD_DELE:
		if (!get_index(s, args, &idx))
			break;
		imsgev_xcompose(s->iev_maildrop, IMSG_MAILDROP_DELE,
		    s->id, 0, -1, &idx, sizeof(idx), "trans_command");
		return;
	case CMD_RSET:
		imsgev_xcompose(s->iev_maildrop, IMSG_MAILDROP_RSET,
		    s->id, 0, -1, NULL, 0, "trans_command");
		return;
	case CMD_UIDL:
		uidl = 1;
		/* FALLTHROUGH */
	case CMD_LIST:
		if (args) {
			if (!get_index(s, args, &idx))
				break;
			get_list(s, idx, uidl);
		} else
			get_list_all(s, uidl);
		return;
	case CMD_QUIT:
		imsgev_xcompose(s->iev_maildrop, IMSG_MAILDROP_UPDATE,
		    s->id, 0, -1, NULL, 0, "trans_command");
		session_set_state(s, UPDATE);
		return;
	default:
		session_reply(s, "%s", "-ERR invalid command");
		break;
	}

	io_set_write(&s->io);
}

static void
get_list_all(struct session *s, int uidl)
{
	io_pause(&s->io, IO_PAUSE_IN);
	session_reply(s, "+OK");
	imsgev_xcompose(s->iev_maildrop, IMSG_MAILDROP_LISTALL,
	    s->id, 0, -1, &uidl, sizeof(uidl), "list_all");
}

static void
get_list(struct session *s, unsigned int i, int uidl)
{
	struct list_req	req;

	req.idx = i;
	req.uidl = uidl;
	imsgev_xcompose(s->iev_maildrop, IMSG_MAILDROP_LIST,
	    s->id, 0, -1, &req, sizeof(req), "list");
}

void
session_imsgev_init(struct session *s, int fd)
{
	s->iev_maildrop = xcalloc(1, sizeof(struct imsgev),
	    "session_imsgev_init");
	imsgev_init(s->iev_maildrop, fd, NULL, maildrop_imsgev, needfd);
}

static void
maildrop_imsgev(struct imsgev *iev, int code, struct imsg *imsg)
{
	struct session	key, *r;

	switch (code) {
	case IMSGEV_IMSG:
		key.id = imsg->hdr.peerid;
		r = SPLAY_FIND(session_tree, &sessions, &key);
		if (r == NULL) {
			logit(LOG_INFO, "%u: session not found", key.id);
			fatalx("session: session lost");
		}
		switch (imsg->hdr.type) {
		case IMSG_MAILDROP_INIT:
			handle_init(r, imsg);
			break;
		case IMSG_MAILDROP_RETR:
			handle_retr(r, imsg);
			break;
		case IMSG_MAILDROP_DELE:
			handle_dele(r, imsg);
			break;
		case IMSG_MAILDROP_RSET:
			session_reply(r, "%s", "+OK reset");
			io_set_write(&r->io);
			break;
		case IMSG_MAILDROP_LIST:
			handle_list(r, imsg);
			break;
		case IMSG_MAILDROP_LISTALL:
			handle_list_all(r, imsg);
			break;
		case IMSG_MAILDROP_UPDATE:
			handle_update(r, imsg);
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
		fatal("session: imsgev read/write error");
		break;
	case IMSGEV_DONE:
		free(iev);
		break;
	}
}

static void
handle_init(struct session *s, struct imsg *imsg)
{
	size_t		datalen;
	struct stats	*stats;

	datalen = imsg->hdr.len - sizeof(imsg->hdr);
	if (datalen) {
		stats = imsg->data;
		s->m_sz = stats->sz;
		s->nmsgs = stats->nmsgs;
		session_reply(s, "%s", "+OK maildrop ready");
		io_set_write(&s->io);
		session_set_state(s, TRANSACTION);
	} else {
		session_reply(s, "%s", "-ERR maildrop init failed");
		io_set_write(&s->io);
		session_close(s, 1);
	}
}

static void
handle_retr(struct session *s, struct imsg *imsg)
{
	struct retr_res	*r = imsg->data;
	FILE		*fp;
	char		*line;
	size_t		len;

	if (imsg->fd == -1) {
		session_reply(s, "%s", "-ERR marked for delete");
		io_set_write(&s->io);
		return;
	}

	if ((fp = fdopen(imsg->fd, "r")) == NULL) {
		logit(LOG_INFO, "%zu: retr failed", s->id);
		session_reply(s, "%s", "-ERR RETR failed");
		io_set_write(&s->io);
		session_close(s, 1);
		return;
	}

	if (fseek(fp, r->offset, SEEK_SET) == -1)
		fatal("fseek");

	session_reply(s, "%s", "+OK");
	/* Ignore "From " line when type is mbox; maildir doesn't have it */
	if ((line = fgetln(fp, &len)) && strncmp(line, "From ", 5))
		session_write(s, line, len);

	if (r->top) {
		/* print headers regardless of ntop */
		while ((line = fgetln(fp, &len))) {
			session_write(s, line, len);
			r->nlines -= 1;
			if (strncmp(line , "\n", 1) == 0)
				break;
		}

		/* print ntop lines of body */
		while ((r->ntop-- > 0) && r->nlines-- &&
		    (line = fgetln(fp, &len)))
			session_write(s, line, len);
	} else
		while (r->nlines-- && (line = fgetln(fp, &len)))
			session_write(s, line, len);

	session_reply(s, "%s", ".");
	io_set_write(&s->io);
	fclose(fp);
	close(imsg->fd);
}

static void
handle_dele(struct session *s, struct imsg *imsg)
{
	int	*res = imsg->data;

	if (*res == 0)
		session_reply(s, "%s", "+OK marked for delete");
	else
		session_reply(s, "%s", "+ERR msg already marked delete");

	io_set_write(&s->io);
}

/* DELEted msg's hash and sz will be zero, ignore them */
static void
handle_list(struct session *s, struct imsg *imsg)
{
	struct list_res	*res = imsg->data;

	res->idx += 1;	/* POP3 index is 1 based */
	if (res->uidl) {
		if (strlen(res->u.hash))
			session_reply(s, "+OK %zu %s", res->idx, res->u.hash);
		else
			session_reply(s, "-ERR marked for delete");
	} else {
		if (res->u.sz)
			session_reply(s, "+OK %zu %zu", res->idx, res->u.sz);
		else
			session_reply(s, "-ERR marked for delete");
	}

	io_set_write(&s->io);
}

/* List terminal is indicated by hash being empty string or sz = 0 */
static void
handle_list_all(struct session *s, struct imsg *imsg)
{
	struct list_res	*res = imsg->data;

	res->idx += 1;	/* POP3 index is 1 based */
	if (res->uidl)
		if (strlen(res->u.hash))
			session_reply(s, "%zu %s", res->idx, res->u.hash);
		else
			goto end;
	else
		if (res->u.sz)
			session_reply(s, "%zu %zu", res->idx, res->u.sz);
		else
			goto end;

	return;
end:
	session_reply(s, ".");
	io_set_write(&s->io);
	io_resume(&s->io, IO_PAUSE_IN);
}

static void
handle_update(struct session *s, struct imsg *imsg)
{
	int	*res = imsg->data;

	if (*res == 0)
		session_reply(s, "%s", "+OK maildrop updated");
	else
		session_reply(s, "%s", "-ERR maildrop update failed");

	io_set_write(&s->io);
	session_close(s, 1);
}

static void
needfd(struct imsgev *iev)
{
	/* XXX */
	fatalx("session needs an fd");
}

int
session_cmp(struct session *a, struct session *b)
{
	if (a->id < b->id)
		return (-1);

	if (a->id > b->id)
		return (1);

	return (0);
}

void
session_set_state(struct session *s, enum state newstate)
{
	pop3_debug("%u: %s -> %s", s->id, strstate(s->state),
	    strstate(newstate));
	s->state = newstate;
}

#define CASE(x) case x : return #x
static const char *
strstate(enum state state)
{
	static char buf[32];

	switch (state) {
	CASE(AUTH);
	CASE(TRANSACTION);
	CASE(UPDATE);
	default:
		(void)snprintf(buf, sizeof(buf), "%d ???", state);
		return (buf);
	}
}

void
session_reply(struct session *s, char *fmt, ...)
{
	va_list	ap;
	int	n;
	char	buf[MAXLINESIZE];

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n == -1 || n > MAXLINESIZE)
		fatalx("session_reply: response too long");

	if (buf[0] == '+')
		pop3_debug("<<< +OK");
	else if (buf[0] == '-')
		pop3_debug("<<< -ERR");

	iobuf_xfqueue(&s->iobuf, "session_reply", "%s\r\n", buf);
}

static void
session_write(struct session *s, const char *data, size_t len)
{
	/* remove terminating \n or \r\n if any */
	if (data[len - 1] == '\n')
		len -= 1;

	if (len && data[len - 1] == '\r')
		len -= 1;

	/* byte stuff "." if at beginning of line */
	if (data[0] == '.')
		iobuf_xfqueue(&s->iobuf, "session_write", ".");

	iobuf_xqueue(&s->iobuf, "session_write", data, len);
	/* explicitly terminate with CRLF */
	iobuf_xfqueue(&s->iobuf, "session_write", "\r\n");
}

static void
pop3_debug(char *fmt, ...)
{
	va_list		ap;
	char		buf[MAXLINESIZE];
	int		n;

	if (!_pop3_debug)
		return;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n == -1 || n > MAXLINESIZE)
		fatalx("pop3_debug: response too long");

	logit(LOG_DEBUG, "%s", buf);
}

SPLAY_GENERATE(session_tree, session, entry, session_cmp);

