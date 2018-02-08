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

#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <paths.h>
#include "td2.h"

#define MAX_CONN_PER_SLOT_AND_8SECS 12
#define MAX_CONN_PRIME_SLOT_NUMBER 397

static struct {
	time_t last;
	int counter;
} conn_counter[MAX_CONN_PRIME_SLOT_NUMBER];

static char *listenhost = "0.0.0.0";
static char *port = "443";

static char * output = NULL;

char *ssl_certfile = CONFDIR "/cert.pem";
char *ssl_keyfile = CONFDIR "/key.pem";

static char *chroot_user = "nobody";
static char *chroot_group = "nobody";
uid_t chroot_uid;
gid_t chroot_gid;

char *chroot_dir = "/var/empty";
static char *configfile = CONFDIR "/td2.conf";

int output_type;


/* daemonize copied from dietlibc
 * and modified by Andreas Krennmair <ak@synflood.at>
 */
static int daemonize(void)
{
	int fd;
	switch (fork()) {
	case -1: return (-1);
	case  0: break;
	default: _exit (0);
	}
	if (setsid () == -1) return (-1);
	if (chdir("/") == -1) return (-1);
	fd = open(_PATH_DEVNULL,O_RDWR,0);
	if (fd == -1) return (-1);
	dup2 (fd,STDIN_FILENO);
	dup2 (fd,STDOUT_FILENO);
	dup2 (fd,STDERR_FILENO);
	if (fd>2) close (fd);
	return (0);
}



static void sig_chld(int signo)
{
	pid_t pid;
	int status;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

static void sig_term(int signo)
{
	exit(EXIT_SUCCESS);
}

static void fetch_config_values(void)
{
	(void) get_config("listenhost", &listenhost);
	(void) get_config("listenport", &port);
	(void) get_config("certfile", &ssl_certfile);
	(void) get_config("keyfile", &ssl_keyfile);
	(void) get_config("user", &chroot_user);
	(void) get_config("group", &chroot_group);
	(void) get_config("chrootdir", &chroot_dir);
	(void) get_config("output", &output);
}

static void sig_hup(int signo)
{
	free_config();
	free_auth();
	process_config(configfile);
	fetch_config_values();
}

int main(int argc, char *argv[])
{
	int listenfd, connfd;
	pid_t childpid;
	socklen_t addrlen;
	char *progname;
	socklen_t clen;
	struct sockaddr_in client;
	int randomfd, modval = 0;
	time_t last = 0;

	progname = strrchr(argv[0], '/');
	if (progname) progname++;
	else progname = argv[0];

	openlog(progname, LOG_PID, LOG_USER);

	if (argc > 1)
		configfile = argv[1];

	process_config(configfile);
	fetch_config_values();

	if (output==NULL || strcasecmp(output,"html")==0) {
		output_type = OUTPUT_HTML;
	} else {
		output_type = OUTPUT_WML;
	}

	/* look up user and group */
	{
		struct passwd *u;
		struct group *g;
		u = getpwnam(chroot_user);
		if (!u) {
			fprintf(stderr, "Error: couldn't find user `%s'.\n", chroot_user);
			exit(EXIT_FAILURE);
		}
		chroot_uid = u->pw_uid;
		g = getgrnam(chroot_group);
		if (!g) {
			fprintf(stderr, "Error: couldn't find group `%s'.\n", chroot_group);
			exit(EXIT_FAILURE);
		}
		chroot_gid = g->gr_gid;
	}

	(void) Signal(SIGCHLD, sig_chld);
	(void) Signal(SIGTERM, sig_term);
	(void) Signal(SIGINT, sig_term);
	(void) Signal(SIGHUP, sig_hup);
	(void) Signal(SIGQUIT, sig_term);

	{
		char *daemon_option = "no";
		(void) get_config("daemon", &daemon_option);
		if (strcmp(daemon_option, "yes")==0) {
			int rc = daemonize();
			if (rc==-1) {
				limit_syslog(LOG_ERR, "daemonize failed: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
	}

	listenfd = Tcp_listen(listenhost, port, &addrlen);

	randomfd = open("/dev/urandom", O_RDONLY);
	if ( randomfd < 0 ) {
		limit_syslog(LOG_WARNING, "Can't open /dev/urandom: %s", strerror(errno));
		srandom(time(NULL) ^ getpid());
	} else {
		if ( read(randomfd, &modval, sizeof(modval)) == (ssize_t)sizeof(modval) ) srandom(modval);
		else srandom(time(NULL) ^ getpid());
	}

	for (;;) {
		clen = (socklen_t) sizeof(struct sockaddr *);

		if ((connfd = accept(listenfd, (struct sockaddr *) &client, &clen)) < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				limit_syslog(LOG_ERR, "failed to accept connection: %s", strerror(errno));
				continue;
			}
		}

		getpeername(connfd, (struct sockaddr *) &client, &clen);

		{
			char *addr_data = (void *) &client.sin_addr;
			time_t current = time(NULL) & ~7;
			unsigned int slot;

			if ( current != last ) {
				if ( randomfd < 0 || read(randomfd, &modval,
						sizeof(modval)) != (ssize_t)sizeof(modval) ) modval = random();
				last = current;
			}

			slot = dohash(addr_data, (unsigned int) sizeof(struct in_addr),
					(unsigned int) modval) % MAX_CONN_PRIME_SLOT_NUMBER;

			conn_counter[slot].counter =
			    conn_counter[slot].last == current ? conn_counter[slot].counter + 1 : 0;
			conn_counter[slot].last = current;

			if (conn_counter[slot].counter >= MAX_CONN_PER_SLOT_AND_8SECS) {
				close(connfd);
				continue;
			}

			limit_syslog(LOG_INFO, "Connection from %s:%u [mod=%08X, slot=%u, count=%u]",
					inet_ntoa(client.sin_addr), ntohs(client.sin_port),
					modval, slot, conn_counter[slot].counter);
		}

		if ((childpid = fork()) == 0) {
			close(listenfd);
			handle_http_request(connfd, client.sin_addr);
			exit(EXIT_SUCCESS);
		} else if (childpid == -1) {
			limit_syslog(LOG_ERR, "fork failed (aborting): %s", strerror(errno));
		}

		close(connfd);
	}

	/* NOTREACHED */
	return 0;
}
