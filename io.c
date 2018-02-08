/*
 *  trapdoor2 - HTTPS trapdoor daemon
 *  Copyright (C) 2004  Andreas Krennmair <ak@synflood.at>
 *  Copyright (C) 2004  Clifford Wolf <clifford@clifford.at>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#if HAVE_LIBSSL
#  include <openssl/rsa.h>
#  include <openssl/crypto.h>
#  include <openssl/pem.h>
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#endif

#if HAVE_LIBGNUTLS
#  include <gnutls/gnutls.h>
#endif

#include "td2.h"

extern char *ssl_certfile, *ssl_keyfile;

#if HAVE_LIBSSL
static SSL_METHOD *meth;
static SSL_CTX *ctx;
static SSL * ssl_handle;
#endif

#if HAVE_LIBGNUTLS

#define DH_BITS 1024

static gnutls_certificate_credentials x509_cred;
static gnutls_session session;

static gnutls_session initialize_tls_session()
{
	gnutls_session session;

	gnutls_init(&session, GNUTLS_SERVER);

	/* avoid calling all the priority functions, since the defaults
	* are adequate.
	*/
	gnutls_set_default_priority( session);   

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	/* request client certificate if any.
	*/
	gnutls_certificate_server_set_request( session, GNUTLS_CERT_REQUEST);

	gnutls_dh_set_prime_bits( session, DH_BITS);

	return session;
}

static gnutls_dh_params dh_params;

static int generate_dh_params(void) 
{
	/* Generate Diffie Hellman parameters - for use with DHE
	 * kx algorithms. These should be discarded and regenerated
	 * once a day, once a week or once a month. Depending on the
	 * security requirements.
	 */
	gnutls_dh_params_init( &dh_params);
	gnutls_dh_params_generate2( dh_params, DH_BITS);
	
	return 0;
}

#endif

void close_ssl(void)
{
#if HAVE_LIBSSL
	SSL_free(ssl_handle);
	SSL_CTX_free(ctx);
#endif

#if HAVE_LIBGNUTLS
	gnutls_bye( session, GNUTLS_SHUT_WR);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();
#endif
}

void init_ssl(void)
{
#if HAVE_LIBSSL
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		limit_syslog(LOG_ERR, "SSL: failed to create new context");
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, ssl_keyfile, SSL_FILETYPE_PEM) <= 0) {
		limit_syslog(LOG_ERR, "SSL: failed to use key file %s", ssl_keyfile);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, ssl_certfile, SSL_FILETYPE_PEM) <= 0) {
		limit_syslog(LOG_ERR, "SSL: failed to use certificate file %s", ssl_certfile);
		exit(EXIT_FAILURE);
	}

	ssl_handle = SSL_new(ctx);
	if (ssl_handle == NULL) {
		limit_syslog(LOG_ERR, "SSL: failed to get new handle");
		exit(EXIT_FAILURE);
	}

#endif

#if HAVE_LIBGNUTLS

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&x509_cred);
	/* gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM); */

	/* gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM); */

	gnutls_certificate_set_x509_key_file(x509_cred, ssl_certfile, ssl_keyfile, GNUTLS_X509_FMT_PEM);

	generate_dh_params();
	
	gnutls_certificate_set_dh_params( x509_cred, dh_params);

	session = initialize_tls_session();

#endif
}

void init_ssl2(int fd) 
{
	int rc;
#if HAVE_LIBSSL
	SSL_set_fd(ssl_handle, fd);
	rc = SSL_accept(ssl_handle);
	if (rc == -1) {
		int errint;
		errint = SSL_get_error(ssl_handle, rc);
		if (errint == SSL_ERROR_SSL) {
			unsigned long e;
			char buf[120];
			e = ERR_get_error();
			ERR_error_string(e, buf);
			limit_syslog(LOG_ERR, "SSL: failed to accept connection: %s",
				     buf);
		} else {
			limit_syslog(LOG_ERR, "SSL: failed to accept connection; err=%d", errint);
		}
		exit(EXIT_FAILURE);
	}
#endif
#if HAVE_LIBGNUTLS
	gnutls_transport_set_ptr( session, (gnutls_transport_ptr)fd);
	rc = gnutls_handshake(session);

	if (rc < 0) {
		exit(EXIT_FAILURE);
	}
#endif
}

int ssl_read(char *x, int len)
{
#if HAVE_LIBSSL
	return SSL_read(ssl_handle, x, len);
#endif
#if HAVE_LIBGNUTLS
	return gnutls_record_recv(session,x,len);
#endif
}

static int ssl_write(char *x, int len)
{
#if HAVE_LIBSSL
	return SSL_write(ssl_handle, x, len);
#endif
#if HAVE_LIBGNUTLS
	return gnutls_record_send(session,x,len);
#endif
}

int ssl_writestr(char *x)
{
	return ssl_write(x, (int)strlen(x));
}

ssize_t ssl_readline(char *vptr, size_t maxlen)
{
	size_t n, rc;
	char c, *ptr;
	if (vptr == NULL)
		return 0;
	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
		if ((rc = (size_t)ssl_read(&c, (int)sizeof(c))) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;
		} else if (rc == 0) {
			if (n == 1) {
				*ptr = '\0';
				return 0;
			} else
				break;
		} else
			return -1;
	}
	*ptr = '\0';
	/* truncate lines that are too long */
	if (strlen(vptr) > 0 && vptr[strlen(vptr) - 1] != '\n') {
		rc = (size_t)ssl_read(&c, (int)sizeof(c));
		while (rc == sizeof(c) && c != '\n') {
			rc = (size_t)ssl_read(&c, (int)sizeof(c));
		}
	}
	return (ssize_t)n;
}

