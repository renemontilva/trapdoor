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
#include "td2.h"
#include <netinet/in.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

extern uid_t chroot_uid;
extern gid_t chroot_gid;
extern char *chroot_dir;
extern int output_type;

static char *client_ip;
static char forwarded_ip[10];

static void drop_privileges(void)
{
	struct rlimit rlim;

#if !HAVE_LIBGNUTLS
#ifdef RLIMIT_CPU
	rlim.rlim_cur=rlim.rlim_max=2;
	if (setrlimit(RLIMIT_CPU, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_CPU) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_CPU undefined and thus corresponding setrlimit disabled."
#endif
#endif
	
#ifdef RLIMIT_FSIZE
	rlim.rlim_cur=rlim.rlim_max=0;
	if (setrlimit(RLIMIT_FSIZE, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_FSIZE) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_FSIZE undefined and thus corresponding setrlimit disabled."
#endif
	
#ifdef RLIMIT_DATA
	rlim.rlim_cur=rlim.rlim_max=1024*512;
	if (setrlimit(RLIMIT_DATA, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_DATA) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_DATA undefined and thus corresponding setrlimit disabled."
#endif
	
#ifdef RLIMIT_STACK
	rlim.rlim_cur=rlim.rlim_max=1024*64;
	if (setrlimit(RLIMIT_STACK, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_STACK) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_STACK undefined and thus corresponding setrlimit disabled."
#endif

#ifdef RLIMIT_CORE
	rlim.rlim_cur=rlim.rlim_max=0;
	if (setrlimit(RLIMIT_CORE, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_CORE) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_CORE undefined and thus corresponding setrlimit disabled."
#endif
	
#ifdef RLIMIT_RSS
	rlim.rlim_cur=rlim.rlim_max=1024*512;
	if (setrlimit(RLIMIT_RSS, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_RSS) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_RSS undefined and thus corresponding setrlimit disabled."
#endif
	
#ifdef RLIMIT_NOFILE
	rlim.rlim_cur=rlim.rlim_max=16;
	if (setrlimit(RLIMIT_NOFILE, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_NOFILE) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_NOFILE undefined and thus corresponding setrlimit disabled."
#endif
	
#ifdef RLIMIT_AS
	rlim.rlim_cur=rlim.rlim_max=1024*1024*32;
	if (setrlimit(RLIMIT_AS, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_AS) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_AS undefined and thus corresponding setrlimit disabled."
#endif

#ifdef RLIMIT_MEMLOCK
	rlim.rlim_cur=rlim.rlim_max=0;
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_MEMLOCK undefined and thus corresponding setrlimit disabled."
#endif
	
#ifdef RLIMIT_LOCKS
	rlim.rlim_cur=rlim.rlim_max=0;
	if (setrlimit(RLIMIT_LOCKS, &rlim)) {
		limit_syslog(LOG_ERR, "setrlimit(RLIMIT_LOCKS) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
#  warning "RLIMIT_LOCKS undefined and thus corresponding setrlimit disabled."
#endif

	/* create chroot_dir if it's not there, e.g. for /var/run subdirs
	 * which are automatically removed at system reboot. */
	(void) mkdir(chroot_dir, 0755);

	if (chdir(chroot_dir)) {
		limit_syslog(LOG_ERR, "chdir(chroot_dir) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct stat st;
	(void) mkdir("dev", 0755);
	if (stat("/dev/urandom", &st) == 0) {
		(void) mknod("dev/urandom", st.st_mode & ~07333, st.st_rdev);
	}
	if (stat("/dev/random", &st) == 0) {
		(void) mknod("dev/random", st.st_mode & ~07333, st.st_rdev);
	}

	if (chroot(chroot_dir)) {
		limit_syslog(LOG_ERR, "chroot(chroot_dir) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if (setgid(chroot_gid)) {
		limit_syslog(LOG_ERR, "setgid(chroot_gid) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if (setuid(chroot_uid)) {
		limit_syslog(LOG_ERR, "setuid(chroot_uid) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (alarm(10)) {
		limit_syslog(LOG_ERR, "alarm(10) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/* cookie auth dialog on child process */
static int auth_cookie(char *c, int cl, int pipe_fds[])
{
	int ret = 1;

	if (cl >= 100) return 1;

	(void) write(pipe_fds[1], &cl, sizeof(cl));
	(void) write(pipe_fds[1], c, (size_t)cl);
	(void) read(pipe_fds[0], &ret, sizeof(ret));

	return ret;
}

static char wml_header[] = 
"HTTP/1.0 200 Authenticated\n"
"Server: trapdoor2\n"
"Content-Type: text/vnd.wap.wml\n\n"
"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
"<!DOCTYPE wml PUBLIC \"-//WAPFORUM//DTD WML 1.1//EN\" "
"\"http://www.wapforum.org/DTD/wml_1.1.xml\">"
"<wml><card title=\"trapdoor2\"><p align=\"center\">";

static char wml_footer[] = 
"</p><p align=\"center\">"
"<input name=\"cookie\" type=\"password\" maxlength=\"64\" format=\"*M\" />"
"<anchor title=\"Go\">Go<go href=\"/\" method=\"post\">"
"<postfield name=\"c\" value=\"$(cookie:e)\" /></go></anchor></p></card></wml>\n";

static char html_header[] =
"HTTP/1.0 200 Authenticated\n"
"Server: trapdoor2\n"
"Content-Type: text/html\n\n"
"<html><head><title>trapdoor2</title>"
"</head><body><h1 align=center>";

static char html_footer[] =
"</h1><center><form method=\"post\">"
"<input type=\"password\" name=\"c\">"
"<input type=submit value=\"Go\">"
"</form></center></body></html>\n";

static void write_success(void)
{
	ssl_writestr(output_type == OUTPUT_WML ? wml_header : html_header);
	ssl_writestr("Request Authenticated");
	ssl_writestr(output_type == OUTPUT_WML ? wml_footer : html_footer);
}

static void write_redir(char *resp)
{
	ssl_writestr("HTTP/1.0 302 Moved Temporarily\n");
	ssl_writestr("Location: ");
	ssl_writestr(resp);
	ssl_writestr("\n\n");
}

static void write_fail(void)
{
	ssl_writestr(output_type == OUTPUT_WML ? wml_header : html_header);
	ssl_writestr("Authentication failed");
	ssl_writestr(output_type == OUTPUT_WML ? wml_footer : html_footer);
}

static void write_none(void)
{
	ssl_writestr(output_type == OUTPUT_WML ? wml_header : html_header);
	ssl_writestr("Give me a cookie!");
	ssl_writestr(output_type == OUTPUT_WML ? wml_footer : html_footer);
}

static void run_command(char *cmd, char *ip)
{
	int pid;
	pid = fork();
	if (pid == 0) {
		char env_ip[20], env_cmd[strlen(cmd)+10];
		char *const envp[] = { env_ip, env_cmd, "PATH=/bin:/usr/bin", 0 };
		snprintf(env_cmd, sizeof(env_cmd), "CMD=%s", cmd);
		snprintf(env_ip, sizeof(env_ip), "IP=%s", ip);
		execle("/bin/sh", "/bin/sh", "-c", cmd, NULL, envp);
		limit_syslog(LOG_ERR, "execl of %s failed: %s", cmd, strerror(errno));
		exit(EXIT_FAILURE);
	} else if (pid == -1) {
		limit_syslog(LOG_ERR, "fork failed: %s", strerror(errno));
	} else {
		(void) waitpid(pid, NULL, 0);
	}
}

/* this is the cookie auth check on the daemon (parent) */
static void handle_client_request(int pipe_fds[])
{
	int size;
	int rc, ret = 1;
	char buf[100], *cmd, *resp;

	rc = (int)read(pipe_fds[0], &size, sizeof(size));
	if (rc < 0) {
		syslog(LOG_ERR|LOG_AUTHPRIV, "error on internal protocol: %s", strerror(errno));
		return;
	}
	if (rc == 0) {
		syslog(LOG_ERR|LOG_AUTHPRIV, "premature EOF on internal protocol");
		return;
	}
	if (rc < (int)sizeof(size)) {
		syslog(LOG_ERR|LOG_AUTHPRIV, "error in internal protocol: invalid length of size (%d instead of %zu)", rc, sizeof(size));
		return;
	}
	if (size <= 0 || size >= 100) {
		syslog(LOG_ERR|LOG_AUTHPRIV, "error in internal protocol: invalid length of buffer (%d not in 1:99)", size);
		return;
	}
	rc = (int)read(pipe_fds[0], buf, size);
	if (rc < size) {
		syslog(LOG_ERR|LOG_AUTHPRIV, "error in internal protocol: input truncated");
		return;
	}
	buf[size] = 0;

	/* try to find command for the cookie */
	if ( (cmd = get_command(buf)) ) {
		/* Don't log this thru the limiter ! */
		syslog(LOG_INFO | LOG_AUTHPRIV, "Running '%s' for %s.", cmd, client_ip);
		run_command(cmd, client_ip);
		ret = 0;
	}

	(void) write(pipe_fds[1], &ret, sizeof(ret));

	if ( ret == 0 ) {
		if ( (resp = get_response(buf)) ) {
			ret = strlen(resp);
			(void) write(pipe_fds[1], &ret, sizeof(ret));
			(void) write(pipe_fds[1], resp, strlen(resp));
		} else
			(void) write(pipe_fds[1], &ret, sizeof(ret));
	}
}

static char *nexttoken(char *line, int *pos, char *expect, char *delim)
{
	char *retval = line + *pos;
	size_t len1 = strcspn(retval, delim);
	size_t len2 = strspn(retval+len1, delim);

	if ( expect && (strlen(expect) != len1 || strncasecmp(retval, expect, len1)) )
		return 0;

	if (len2) line[*pos+len1] = 0;
	*pos += len1 + len2;

	return retval;
}

static void do_handle_http_request(int fd, int pipe_fds[])
{
	int i=0, ispost=0, auth_success=2, resp_len=0;
	char line[1024], *cookie=0;
	ssize_t rc;

	init_ssl();

	drop_privileges();

	init_ssl2(fd);

	if ( ssl_readline(line, sizeof(line)) <= 0 )
		goto http_error;

	if (!nexttoken(line, &i, "GET", " \t")) {
		if (nexttoken(line, &i, "POST", " \t")) ispost=1;
		else goto http_error;
	}

	if (nexttoken(line, &i, "/wml", " \t?")) output_type = OUTPUT_WML;
	else if (nexttoken(line, &i, "/html", " \t?")) output_type = OUTPUT_HTML;
	else if (!nexttoken(line, &i, 0, " \t?")) goto query_error;

	if (!ispost) {
		if (!nexttoken(line, &i, 0, "=")) goto query_error;
		if (!(cookie = nexttoken(line, &i, 0, " \t"))) goto query_error;
	}

	if (!nexttoken(line, &i, "HTTP", "/")) goto query_error;

	if (!ispost)
		auth_success = auth_cookie(cookie, (int)strlen(cookie), pipe_fds);

query_error:
	if (!ispost)
	{
		/* read over HTTP headers until we reach a blank line */
		do {
			rc = ssl_readline(line, sizeof(line));
			sscanf(line, "X-Forwarded-For: %s", &forwarded_ip);
			printf("printing %s\n", forwarded_ip);
		} while (rc > 0 && strcmp(line, "\r\n") != 0);
	}
	else
	{
		int request_len = 0;

		/* read over HTTP headers until we reach a blank line */
		do {
			rc = ssl_readline(line, sizeof(line));
			sscanf(line, "Content-Length: %d", &request_len);
		} while (rc > 0 && strcmp(line, "\r\n") != 0);

		if ( request_len > 0 && request_len < 100 )
			if ( ssl_read(line, request_len) == request_len ) {
				line[request_len] = 0;
				cookie = strchr(line, '=');
				if (cookie)
					auth_success = auth_cookie(cookie+1, (int)strlen(cookie+1), pipe_fds);
			}
	}

http_error:
	switch (auth_success) {
		case 0:
			(void) read(pipe_fds[0], &resp_len, sizeof(resp_len));
			if ( resp_len == 0 )
				write_success();
			else {
				char resp[resp_len+1];
				(void) read(pipe_fds[0], resp, resp_len);
				resp[resp_len]=0;
				write_redir(resp);
			}
			break;
		case 1:
			write_fail();
			break;
		case 2:
			write_none();
			break;
	}
	close_ssl();
}

void handle_http_request(int fd, struct in_addr in)
{
	int childpid, rc;
	int c2p_fds[2];
	int p2c_fds[2];
	int pipe_fds[2];

	client_ip = inet_ntoa(in);

	rc = pipe(c2p_fds);
	if (rc != 0) {
		limit_syslog(LOG_ERR, "pipe failed: %s", strerror(errno));
		return;
	}

	rc = pipe(p2c_fds);
	if (rc != 0) {
		limit_syslog(LOG_ERR, "pipe failed: %s", strerror(errno));
		return;
	}

	childpid = fork();

	if (childpid == 0) {
		close(c2p_fds[0]);	/* child to parent: write only */
		close(p2c_fds[1]);	/* parent to child: write only */
		pipe_fds[0] = p2c_fds[0];
		pipe_fds[1] = c2p_fds[1];
		do_handle_http_request(fd, pipe_fds);
		exit(EXIT_SUCCESS);
	} else if (childpid == -1) {
		limit_syslog(LOG_ERR, "fork failed: %s", strerror(errno));
	}

	close(fd);
	close(c2p_fds[1]);
	close(p2c_fds[0]);
	pipe_fds[0] = c2p_fds[0];
	pipe_fds[1] = p2c_fds[1];

	handle_client_request(pipe_fds);
}

