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

#ifndef TD2__H
#define TD2__H

#define MAX_CONN_PER_SLOT_AND_8SECS 12
#define MAX_CONN_PRIME_SLOT_NUMBER 397

#define LISTENQ 1024

#if HAVE_DARWIN
#define socklen_t int
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

enum { OUTPUT_HTML = 1, OUTPUT_WML };

extern void process_config(char *f);
extern char *get_command(char *cookie);
extern char *get_response(char *cookie);
extern char *get_config(char *key, char **target);
extern void free_auth(void);
extern void free_config(void);

extern void handle_http_request(int fd, struct in_addr in);

extern void init_ssl(void);
extern void init_ssl2(int fd);
extern void close_ssl(void);

extern int ssl_read(char *x, int len);
extern ssize_t ssl_readline(char *vptr, size_t maxlen);
extern int ssl_writestr(char *x);

typedef void Sigfunc(int);

extern Sigfunc *Signal(int signo, Sigfunc * func);

extern int Tcp_listen(const char *host, const char *serv, socklen_t * addrlenp);

extern int apr_password_validate(const char *passwd, const char *hash);
extern int apr_md5_encode(const char *, const char *, char *, size_t);

extern unsigned int dohash(const char *data, unsigned int len, unsigned int mod);

extern void limit_syslog (int pri, const char *fmt, ...);

#ifndef CONFDIR
#  define CONFDIR "/etc/td2" /* fall back in case -DCONFDIR="$foo" failed somehow */
#  warning "Needed to enable fallback definition of CONFDIR - something's broken with the build process."
#endif

#endif
