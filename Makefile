PROG=		pop3d
MAN=		pop3d.8
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations -Wshadow -Wpointer-arith
CFLAGS+=	-Wcast-qual -Wsign-compare
CFLAGS+=	-DIO_SSL
DEBUG=		-g
SRCS=		pop3d.c pop3e.c session.c maildrop.c maildir.c mbox.c util.c
SRCS+=		imsgev.c iobuf.c ioev.c
SRCS+=		ssl.c ssl_privsep.c
LDADD+=		-levent -lssl -lcrypto -lutil
DPADD=		${LIBEVENT} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}

.include <bsd.prog.mk>
