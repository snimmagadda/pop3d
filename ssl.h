#include <openssl/ssl.h>

/* ssl.c */
void ssl_init(void);
void *ssl_setup(const char *, const char *);
void *pop3s_init(SSL_CTX *, int);
void ssl_error(const char *);

/* ssl_privsep.c */
int ssl_ctx_use_private_key(SSL_CTX *, char *, off_t);
int ssl_ctx_use_certificate_chain(SSL_CTX *, char *, off_t);
