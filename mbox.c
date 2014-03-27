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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "pop3d.h"

static int init(struct mdrop *, size_t *, size_t *);
static int retr(struct mdrop *, unsigned int, size_t *, size_t *);
static int update(struct mdrop *);

struct m_backend m_backend_mbox = {
	init,
	retr,
	update
};

/* 
 * Parse mbox calculating each message's offset, size and hash.
 * A message is identified by "From " at the start of a line.
 * Returns 0 on success with nmsgs and sz populated.
 */
int
init(struct mdrop *m, size_t *nmsgs, size_t *sz)
{
	SHA1_CTX	ctx;
	FILE		*fp;
	struct msg	*msg = NULL;
	size_t		i, len;
	long		offset;
	char		*line;

	*nmsgs = 0;
	*sz = 0;
	if (flock(m->fd, LOCK_EX|LOCK_NB) == -1) {
		switch (errno) {
		case EWOULDBLOCK:
			logit(LOG_INFO, "mbox: locked by other process");
			return (-1);
		default:
			fatal("flock(LOCK_EX)");
		}
	}

	if ((fp = fdopen(dup(m->fd), "r+")) == NULL) {
		logit(LOG_INFO, "mbox: fdopen failed");
		return (-1);
	}

	SIMPLEQ_INIT(&m->e.q_msgs);
	offset = ftell(fp);
	while ((line = fgetln(fp, &len))) {
		if ((len > 5) && strncmp("From ", line, 5) == 0) {
			if (msg)
				SHA1End(&ctx, msg->hash);

			msg = xcalloc(1, sizeof(*msg), "init");
			SHA1Init(&ctx);
			msg->u.offset = offset;
			m->nmsgs += 1;
			SIMPLEQ_INSERT_TAIL(&m->e.q_msgs, msg, e.q_entry);
		} else {
			if (msg == NULL)
				fatalx("mbox corrupted: no \"From \" line");

			msg->sz += len;
			msg->nlines += 1;
			SHA1Update(&ctx, (u_int8_t *)line, len);
			offset = ftell(fp);
		}
	}

	if (msg)
		SHA1End(&ctx, msg->hash);

	/* allocate space for nmsgs of struct msg pointers */
	m->msgs_index = xcalloc(m->nmsgs, sizeof(msg), "make_index");
	i = 0;
	SIMPLEQ_FOREACH(msg, &m->e.q_msgs, e.q_entry) {
		m->msgs_index[i++] = msg;
		/* calculate mbox size by counting newline as 2 (CRLF) */
		m->sz += msg->sz + msg->nlines;
	}

	*nmsgs = m->nmsgs;
	*sz = m->sz;
	fclose(fp);
	return (0);
}

static int
retr(struct mdrop *m, unsigned int idx, size_t *nlines, size_t *offset)
{
	if (m->msgs_index[idx]->flags & F_DELE)
		return (-1);

	*offset = m->msgs_index[idx]->u.offset;
	*nlines = m->msgs_index[idx]->nlines;
	return (dup(m->fd)); /* imsg closes sender's fd */
}

/* 
 * No resource management as this process is blown away
 * upon success or error.
 */
static int
update(struct mdrop *m)
{
	struct msg	*cur;
	size_t		i, j = 0, len, nlines;
	char		buf[MAXBSIZE], fn[22], *line;
	FILE		*tmp_fp, *m_fp;
	mode_t		old_mask;
	int		tmp_fd;

	for (i = 0; i < m->nmsgs; i++)
		if (m->msgs_index[i]->flags & F_DELE)
			j += 1;

	if ((m_fp = fdopen(dup(m->fd), "r+")) == NULL) {
		logit(LOG_INFO, "mbox: fdopen failed");
		return (-1);
	}

	if (j == 0)
		return (0);
	else if (j == m->nmsgs) {
		if (ftruncate(fileno(m_fp), 0) == -1) {
			logit(LOG_CRIT, "update: ftruncate failed");
			return (1);
		}

		return (0);
	}

	strlcpy(fn, "/tmp/pop3d.XXXXXXXXXX", sizeof(fn));
	old_mask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if ((tmp_fd = mkstemp(fn)) == -1 ||
	    (tmp_fp = fdopen(tmp_fd, "r+")) == NULL) {
		logit(LOG_CRIT, "mbox: mkstemp failed");
		return (1);
	}

	umask(old_mask);
	for (i = 0; i < m->nmsgs; i++) {
		cur = m->msgs_index[i];
		if (cur->flags & F_DELE)
			continue;

		if (fseek(m_fp, cur->u.offset, SEEK_SET) == -1) {
			logit(LOG_CRIT, "update: fseek failed");
			return (1);
		}
		/*
		 * "From " line isn't counted in nlines but offset starts
		 * there, adjust nlines here 
		 */
		nlines = m->msgs_index[i]->nlines + 1;
		while (nlines--) {
			if ((line = fgetln(m_fp, &len)))
				if (fwrite(line, len, 1, tmp_fp) != 1)
					fatalx("update: short write");
		}
	}

	fflush(tmp_fp);
	rewind(m_fp);
	rewind(tmp_fp);
	while (!feof(tmp_fp)) {
		fread(buf, sizeof(buf), 1, tmp_fp);
		if (fwrite(buf, sizeof(buf), 1, m_fp) != 1)
			fatalx("update: short write");
	}

	fflush(m_fp);
	if (ftruncate(fileno(m_fp), ftello(tmp_fp)) == -1)
		fatal("update: failed to truncate");

	fclose(m_fp);
	return (0);
}

