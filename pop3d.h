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

#include <sys/tree.h>

#include <sha1.h>

#include "imsgev.h"
#include "iobuf.h"
#include "ioev.h"

#define	ARGLEN		40
#define POP3S		0x01
#define	F_DELE		0x01

struct passwd;

enum imsg_type {
	IMSG_AUTH,
	IMSG_MAILDROP_INIT,
	IMSG_MAILDROP_RETR,
	IMSG_MAILDROP_DELE,
	IMSG_MAILDROP_RSET,
	IMSG_MAILDROP_LIST,
	IMSG_MAILDROP_LISTALL,
	IMSG_MAILDROP_UPDATE
};

enum m_type {
	M_MBOX,
	M_MAILDIR
};

struct msg {
	union {
		SIMPLEQ_ENTRY(msg)	q_entry;
		RB_ENTRY(msg)		t_entry;
	}				e;
	char				hash[SHA1_DIGEST_STRING_LENGTH];
	size_t				sz;
	size_t				nlines;
	union {
		long			offset;
		const char		*fname;
	}				u;
	int				flags;
};

struct mdrop {
	union {
		SIMPLEQ_HEAD(, msg)	q_msgs;
		RB_HEAD(msgtree, msg)	t_msgs;
	}				e;
	size_t				nmsgs;
	size_t				sz;
	struct msg			**msgs_index; /* random access msgs */
	int				fd;
};

struct stats {
	size_t	nmsgs;
	size_t	sz;
};

struct retr_req {
	unsigned int	idx;
	unsigned int	ntop;
	int		top;
};

struct retr_res {
	size_t		nlines;
	long		offset;
	unsigned int	ntop;
	int		top;
};

struct list_req {
	unsigned int	idx;
	int		uidl;
};

struct list_res {
	unsigned int	idx;
	union {
		size_t	sz;
		char	hash[SHA1_DIGEST_STRING_LENGTH];
	}		u;
	int		uidl;
};

struct m_backend {
	int (*init)(struct mdrop *, size_t *, size_t *);
	int (*retr)(struct mdrop *, unsigned int, size_t *, long *);
	int (*update)(struct mdrop *);
};

struct auth_req {
	char	user[ARGLEN];
	char	pass[ARGLEN];
};

struct listener {
	struct sockaddr_storage	ss;
	struct event		ev;
	struct event		pause;
	int			flags;
	int			sock;
};

enum state {
	AUTH,
	TRANSACTION,
	UPDATE
};

struct session {
	SPLAY_ENTRY(session)	entry;
	struct imsgev		iev_maildrop;
	struct iobuf		iobuf;
	struct io		io;
	char			user[ARGLEN];
	char			pass[ARGLEN];
	size_t			m_sz;
	size_t			nmsgs;
	struct listener		*l;
	uint32_t		id;
	int			flags;
	enum state		state;
};

/* pop3e.c */
void pop3_main(int [2], struct passwd *);

/* session.c */
void session_init(struct listener *, int);
void session_close(struct session *, int);
void session_reply(struct session *, char *, ...);
void session_set_state(struct session *, enum state);
void session_imsgev_init(struct session *, int);
SPLAY_HEAD(session_tree, session);
int session_cmp(struct session *, struct session *);
SPLAY_PROTOTYPE(session_tree, session, entry, session_cmp);

/* maildrop.c */
pid_t maildrop_setup(uint32_t, int [2], struct passwd *);

/* util.c */
void set_nonblocking(int);
void log_init(int);
void logit(int, const char *, ...);
void vlog(int, const char *, va_list);
void fatal(const char *);
void fatalx(const char *);
void *xcalloc(size_t, size_t, const char *);
void iobuf_xfqueue(struct iobuf *, const char *, const char *, ...);
void iobuf_xqueue(struct iobuf *, const char *, const void *, size_t);
int imsgev_xcompose(struct imsgev *, u_int16_t, u_int32_t,
    uint32_t, int, void *, u_int16_t, const char *);
int get_index(struct session *, const char *, unsigned int *);
void log_connect(uint32_t, struct sockaddr_storage *, socklen_t);
