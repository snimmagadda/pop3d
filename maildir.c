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
#include <sys/tree.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "pop3d.h"

static int init(struct mdrop *, size_t *, size_t *);
static int retr(struct mdrop *, unsigned int, size_t *, long *);
static int update(struct mdrop *);
static int new_to_cur(struct mdrop *);
static int msgcmp(struct msg *, struct msg *);
RB_PROTOTYPE(msgtree, msg, e.t_entry, msgcmp);

struct m_backend m_backend_maildir = {
	init,
	retr,
	update
};

/*
 * No resource management on error path as the process is
 * killed if an error occurs.
 */
static int
init(struct mdrop *m, size_t *nmsgs, size_t *sz)
{
	SHA1_CTX	ctx;
	struct stat	sb;
	u_char		buf[MAXBSIZE];
	DIR		*dirp;
	struct dirent	*dp;
	struct msg	*msg;
	u_char		*C;
	size_t		i;
	ssize_t		len;
	int		cur_fd, msg_fd;

	*nmsgs = 0;
	*sz = 0;
	if (new_to_cur(m) == -1) {
		logit(LOG_WARNING, "maildir: move msgs from new to cur failed");
		return (-1);
	}

	if ((cur_fd = openat(m->fd, "cur", O_RDONLY)) == -1) {
		logit(LOG_CRIT, "maildir: unable to open \"cur\" dir");
		return (-1);
	}

	if ((dirp = fdopendir(cur_fd)) == NULL)
		return (-1);

	while ((dp = readdir(dirp))) {
		if (dp->d_type != DT_REG)
			continue;

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		msg = xcalloc(1, sizeof(*msg), "init");
		if ((msg->u.fname = strdup(dp->d_name)) == NULL)
			fatalx("init: strdup");

		if (fstatat(cur_fd, dp->d_name, &sb, 0) == -1) {
			logit(LOG_CRIT, "%s fstatat failed", dp->d_name);
			return (-1);
		}

		msg->sz = sb.st_size;
		if ((msg_fd = openat(cur_fd, dp->d_name, O_RDONLY)) == -1) {
			logit(LOG_CRIT, "%s openat failed", dp->d_name);
			return (-1);
		}

		SHA1Init(&ctx);
		while (( len = read(msg_fd, buf, sizeof(buf))) > 0) {
			SHA1Update(&ctx, (u_int8_t *)buf, len);
			for (C = buf; len--; ++C)
				if (*C == '\n')
					msg->nlines += 1;
		}

		SHA1End(&ctx, msg->hash);
		close(msg_fd);
		RB_INSERT(msgtree, &m->e.t_msgs, msg);
		m->nmsgs += 1;
	}

	/* allocate space for nmsgs of struct msg pointers */
	m->msgs_index = xcalloc(m->nmsgs, sizeof(msg), "init");
	*nmsgs = m->nmsgs;
	i = 0;
	*sz = 0;
	RB_FOREACH(msg, msgtree, &m->e.t_msgs) {
		m->msgs_index[i++] = msg;
		/* calculate maildir size by counting newline as 2 (CRLF) */
		*sz += msg->sz + msg->nlines;
	}

	closedir(dirp);
	close(cur_fd);
	return (0);
}

static int
new_to_cur(struct mdrop *m)
{
	DIR		*dirp;
	struct dirent	*dp;
	int		cur_fd, new_fd;


	if ((cur_fd = openat(m->fd, "cur", O_RDONLY)) == -1) {
		logit(LOG_CRIT, "maildir: unable to open \"cur\" dir");
		return (-1);
	}

	if ((new_fd = openat(m->fd, "new", O_RDONLY)) == -1) {
		logit(LOG_CRIT, "maildir: unable to open \"new\" dir");
		return (-1);
	}

	if ((dirp = fdopendir(new_fd)) == NULL)
		return (-1);

	while ((dp = readdir(dirp))) {
		if (dp->d_type != DT_REG)
			continue;

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		if (renameat(new_fd, dp->d_name, cur_fd, dp->d_name) == -1) {
			logit(LOG_CRIT, "maildir: renameat failed");
			return (-1);
		}
	}

	closedir(dirp);
	close(cur_fd);
	close(new_fd);
	return (0);
}

static int
retr(struct mdrop *m, unsigned int idx, size_t *nlines, long *offset)
{
	char	buf[MAXPATHLEN];
	int	fd, r;

	*offset = 0;
	*nlines = m->msgs_index[idx]->nlines;
	r = snprintf(buf, sizeof(buf), "cur/%s", m->msgs_index[idx]->u.fname);
	if ((u_int)r >= sizeof(buf)) {
		logit(LOG_WARNING, "path too long");
		return (-1);
	}

	fd = openat(m->fd, buf, O_RDONLY);
	return (fd);
}

static int
update(struct mdrop *m)
{
	char	buf[MAXPATHLEN];
	size_t	i, j = 0;
	int	r;

	for (i = 0; i < m->nmsgs; i++)
		if (m->msgs_index[i]->flags & F_DELE)
			j += 1;

	if (j == 0) /* nothing to update */
		return (0);

	for (i = 0; i < m->nmsgs; i++) {
		if (!(m->msgs_index[i]->flags & F_DELE))
			continue;

		r = snprintf(buf, sizeof(buf), "cur/%s",
		    m->msgs_index[i]->u.fname);
		if ((u_int)r >= sizeof(buf)) {
			logit(LOG_WARNING, "path too long");
			return (1);
		}

		if (unlinkat(m->fd, buf, 0) == -1) {
			logit(LOG_CRIT, "%s unlink failed", buf);
			return (1);
		}
	}

	return (0);
}

static int
msgcmp(struct msg *m1, struct msg *m2)
{
	return strcmp(m1->u.fname, m2->u.fname);
}

RB_GENERATE(msgtree, msg, e.t_entry, msgcmp);
