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

#include <signal.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "td2.h"

static Sigfunc *my_signal(int signo, Sigfunc * func)
{
	struct sigaction act, oact;

	if (func == NULL)
		return NULL;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
		/* Linux header says "historical no-op." 
		 * BSD doesn't have it. So it can't be _that_
		 * important. */
		act.sa_flags |= SA_INTERRUPT;
#endif
	} else {
		act.sa_flags |= SA_RESTART;
	}
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
}

Sigfunc *Signal(int signo, Sigfunc * func)
{
	Sigfunc *sigfunc;

	if (func == NULL)
		return NULL;
	if ((sigfunc = my_signal(signo, func)) == SIG_ERR) {
		limit_syslog(LOG_ERR, "failed to set signal handler: %s", strerror(errno));
		perror("Signal error");
	}
	return sigfunc;
}
