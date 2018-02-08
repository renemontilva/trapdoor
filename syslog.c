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

#include "td2.h"
#include <syslog.h>
#include <stdarg.h>
#include <time.h>

#define MSG_PER_SECS 0.1
#define MAX_BURST_LEVEL 30
#define PENALTY_LIMIT 10

static float msg_counter = MAX_BURST_LEVEL;
static time_t last_message = 0;
static int penalty_mode = 0;

void limit_syslog (int pri, const char *fmt, ...)
{
	va_list ap;
	time_t now = time(0);

	if ( last_message ) {
		msg_counter += (now-last_message) * MSG_PER_SECS;
		if ( msg_counter > MAX_BURST_LEVEL ) msg_counter = MAX_BURST_LEVEL;
	}
	last_message = now;

	if ( msg_counter <= 0 ) {
		if ( ! penalty_mode ) {
			syslog(LOG_WARNING | LOG_AUTHPRIV, "Too many syslog messages (DOS Attack ?)");
			syslog(LOG_WARNING | LOG_AUTHPRIV, "... going to be silent for %d seconds.",
					(int)(PENALTY_LIMIT/MSG_PER_SECS));
		}
		penalty_mode = 1;
	}

	if ( msg_counter >= PENALTY_LIMIT ) penalty_mode = 0;
	if ( penalty_mode ) return;

	va_start(ap, fmt);
	vsyslog(pri | LOG_AUTHPRIV, fmt, ap);
	va_end(ap);

	msg_counter--;
}

