/*
 * Copyright (c) 2013 Sunil Nimmagadda <sunil@nimmagadda.net>
 * Copyright (c) 2006 Pierre-Yves Ritschard <pyr@openbsd.org>
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
#include <sys/stat.h>

#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include "pop3d.h"
#include "ssl.h"

#define SSL_CIPHERS		"HIGH"
#define SSL_SESSION_TIMEOUT	300

static char *ssl_load_file(const char *, off_t *);

void
ssl_init(void)
{
	/* SSL init */
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* Init hardware cryto engines. */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
}

void *
ssl_setup(const char *certfile, const char *keyfile)
{
	SSL_CTX *ctx = NULL;
	char	*cert, *key;
	off_t	cert_len, key_len;

	/* SSL context creation */
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ssl_error("ssl_ctx_create");
		fatal("ssl_ctx_create: could not create SSL context");
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_timeout(ctx, SSL_SESSION_TIMEOUT);
	SSL_CTX_set_options(ctx,
	    SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_TICKET);
	SSL_CTX_set_options(ctx,
	    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

	/* SSL certificate, key loading */
	cert = ssl_load_file(certfile, &cert_len);
	if (cert == NULL)
		fatal("ssl_load_file: certificate");

	key = ssl_load_file(keyfile, &key_len);
	if (key == NULL)
		fatal("ssl_load_file: key");

	if (!SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS))
		goto err;

	if (!ssl_ctx_use_certificate_chain(ctx, cert, cert_len))
		goto err;

	else if (!ssl_ctx_use_private_key(ctx, key, key_len))
		goto err;

	else if (!SSL_CTX_check_private_key(ctx))
		goto err;

	return (ctx);

err:
	if (ctx != NULL)
		SSL_CTX_free(ctx);
	ssl_error("ssl_setup");
	fatal("ssl_setup: cannot set SSL up");
	return (NULL);
}

void *
pop3s_init(SSL_CTX *ctx, int fd)
{
	SSL *ssl;

	if ((ssl = SSL_new(ctx)) == NULL)
		fatal("SSL_new");

	if (SSL_set_fd(ssl, fd) == 0)
		fatal("SSL_set_fd");

	return (ssl);
}

static char *
ssl_load_file(const char *name, off_t *len)
{
	struct stat	st;
	off_t		size;
	char		*buf = NULL;
	int		fd;

	if ((fd = open(name, O_RDONLY)) == -1)
		return (NULL);

	if (fstat(fd, &st) != 0)
		goto fail;

	size = st.st_size;
	if ((buf = calloc(1, size + 1)) == NULL)
		goto fail;
	if (read(fd, buf, size) != size)
		goto fail;

	close(fd);

	*len = size;
	return (buf);

fail:
	if (buf != NULL)
		free(buf);

	close(fd);
	return (NULL);
}

void
ssl_error(const char *where)
{
	unsigned long	code;
	char		errbuf[128];
	extern int	debug;

	if (!debug)
		return;

	for (; (code = ERR_get_error()) != 0 ;) {
		ERR_error_string_n(code, errbuf, sizeof(errbuf));
		logit(LOG_DEBUG, "SSL library error: %s: %s", where, errbuf);
	}
}

