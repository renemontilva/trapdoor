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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include "td2.h"

/* read the cookie from the terminal */
static void read_cookie(char *c, size_t size)
{
	char p[size];

	snprintf(c, size, "%s", getpass("Please enter the cookie: "));
	snprintf(p, size, "%s", getpass("Please re-enter the cookie: "));

	if ( strcmp(c, p) ) {
		puts("cookies do not match!");
		exit(EXIT_FAILURE);
	}
}

static void generate_salt(char *tbl, char *s, size_t size)
{
	size_t i;
	struct timeval t;
	gettimeofday(&t, NULL);
	srand(getpid() ^ getppid() ^ (t.tv_sec + t.tv_usec));
	for (i = 0; i < size; ++i) {
		int idx = (int) (64.0 * rand() / (RAND_MAX + 1.0));
		s[i] = tbl[idx];
	}
}

static void usage(void)
{
	puts("usage: gencookie [cookie]\n\ngenerates MD5-hashed cookie for use in td2.conf\n"
		"if no cookie was specified on the command line, it is read from the terminal");
	exit(EXIT_FAILURE);
}

/*@ -redef @*/
int main(int argc, char *argv[])
{
	char cookie[120] = "";
	char result[120] = "";
	char salt[9] = "";
	char tbl[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	if (argc == 1) {
		read_cookie(cookie, sizeof(cookie) - 1);
	} else if (argc > 1) {
		if (strcmp(argv[1],"-h")==0)
			usage();
		strncat(cookie, argv[1], sizeof(cookie) - 1);
	}
	generate_salt(tbl, salt, sizeof(salt) - 1);
	apr_md5_encode(cookie, salt, result, sizeof(result));
	puts(result);
	return 0;
}

