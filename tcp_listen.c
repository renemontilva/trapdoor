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

#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "td2.h"

static void Setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	if (setsockopt(fd, level, optname, optval, optlen) < 0) {
		limit_syslog(LOG_WARNING, "setsockopt failed: %s", strerror(errno));
	}
}

static void Listen(int fd, int backlog)
{
	char *ptr;

	if ((ptr = getenv("LISTENQ")) != NULL) {
		backlog = atoi(ptr);
	}

	if (listen(fd, backlog) < 0) {
		limit_syslog(LOG_ERR, "listen failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static int tcp_listen(const char *host, const char *serv, socklen_t * addrlenp)
{
	int listenfd, n;
	const int on = 1;
	struct addrinfo hints, *res, *ressave;
	struct linger sl = { 1, 5 };

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
		limit_syslog(LOG_ERR, "getaddrinfo failed: %s, %s: %s",
				host ? host : "(any)", serv, strerror(errno));
		perror("getaddrinfo");
		exit(EXIT_FAILURE);
	}
	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (listenfd < 0)
			continue;
		Setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on));
		Setsockopt(listenfd, SOL_SOCKET, SO_LINGER, &sl, (socklen_t)sizeof(sl));
		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;
		close(listenfd);
	} while ((res = res->ai_next) != NULL);
	if (res == NULL) {
		limit_syslog(LOG_ERR, "failed to bind socket: %s, %s: %s",
				host ? host : "(any)", serv, strerror(errno));
		perror("tcp_listen");
		exit(EXIT_FAILURE);
	}
	Listen(listenfd, LISTENQ);
	if (addrlenp)
		*addrlenp = res->ai_addrlen;

	freeaddrinfo(ressave);
	return listenfd;
}

int Tcp_listen(const char *host, const char *serv, socklen_t * addrlenp)
{
	return tcp_listen(host, serv, addrlenp);
}
