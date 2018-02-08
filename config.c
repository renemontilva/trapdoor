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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct config_entry {
	char *key, *value;
	struct config_entry *next;
};

struct auth_entry {
	char *cookie, *cmd, *response;
	struct auth_entry *next;
};

static struct config_entry *config_top;
static struct auth_entry *auth_top;


static char *my_strtok(char *string)
{
	char *s1, *s2, *separators = "\t\n ";
        static char *savestring;

        if (string == NULL) {
                string = savestring;
                if (string == NULL) return NULL;
        }

        s1 = string + strspn(string, separators);
        if (*s1 == '\0') {
                savestring = NULL;
                return NULL;
        }

	if (*s1 == '"') {
		separators = "\"\n";
		s1++;
	}

	if (*s1 == '\'') {
		separators = "'\n";
		s1++;
	}

        s2 = strpbrk(s1, separators);
        if (s2 != NULL)
                *s2++ = '\0';
        savestring = s2;
        return s1;
}

void process_config(char *fx)
{
	FILE *f = fopen(fx, "r");
	char linebuf[1024], *token[10];
	char *errstr = "unknown keyword or wrong argument count";
	int lineno, tcount, i;

	struct config_entry *ce;
	struct auth_entry *ae;

	struct {
		void *code_address;
		char *keyword;
		int tokens;
	} keywords[] = {
		{ &&do_config_var, "listenhost", 2 },
		{ &&do_config_var, "listenport", 2 },
		{ &&do_config_var, "user",       2 },
		{ &&do_config_var, "group",      2 },
		{ &&do_config_var, "chrootdir",  2 },
		{ &&do_config_var, "certfile",   2 },
		{ &&do_config_var, "keyfile",    2 },
		{ &&do_config_var, "output",     2 },
		{ &&do_config_var, "daemon",     2 },
		{ &&do_new_cookie, "cookie",     2 },
		{ &&do_set_hash,   "hash",       2 },
		{ &&do_set_cmd,    "command",    2 },
		{ &&do_set_resp,   "response",   2 },
		{ 0, 0, 0 }
	};

	if (!f) {
		fprintf(stderr, "Error: couldn't open configuration file `%s'.\n", fx);
		exit(EXIT_FAILURE);
	}

	for (lineno=1; fgets(linebuf, (int)sizeof(linebuf), f); lineno++)
	{
		for (tcount=0; tcount<10; tcount++) {
			token[tcount] = my_strtok(!tcount ? linebuf : 0);
			if ( !token[tcount] ) break;
		}

		if (!tcount || *token[0] == '#') continue;
		
		for (i=0; keywords[i].keyword; i++)
			if ( !strcmp(keywords[i].keyword, token[0]) &&
			     tcount == keywords[i].tokens) goto *keywords[i].code_address;
		goto syntax_error;

do_new_cookie:
		ae = malloc(sizeof(struct auth_entry));
		ae->cookie = "*";
		ae->cmd = "";
		ae->next = auth_top;
		auth_top = ae;
		continue;

do_set_hash:
		if ( !config_top ) {
			errstr = "hash definition before cookie keyword";
			goto syntax_error;
		}
		auth_top->cookie = strdup(token[1]);
		continue;

do_set_cmd:
		if ( !config_top ) {
			errstr = "command definition before cookie keyword";
			goto syntax_error;
		}
		auth_top->cmd = strdup(token[1]);
		continue;

do_set_resp:
		if ( !config_top ) {
			errstr = "response definition before cookie keyword";
			goto syntax_error;
		}
		auth_top->response = strdup(token[1]);
		continue;

do_config_var:
		if ( get_config(token[0], 0) ) {
			errstr = "config value defined twice";
			goto syntax_error;
		}
		ce = malloc(sizeof(struct config_entry));
		ce->key = strdup(token[0]);
		ce->value = strdup(token[1]);
		ce->next = config_top;
		config_top = ce;
		continue;
	}

	fclose(f);
	return;

syntax_error:
	fprintf(stderr, "Error: `%s' in configuration file `%s' line %d.\n", errstr, fx, lineno);
	exit(EXIT_FAILURE);
}

char *get_config(char *key, char **target)
{
	struct config_entry *ce;
	for (ce = config_top; ce; ce = ce->next)
		if (strcmp(ce->key, key) == 0) {
			if (target) *target = ce->value;
			return ce->value;
		}
	return 0;
}

char *get_command(char *cookie)
{
	struct auth_entry *tmp;
	for (tmp=auth_top; tmp; tmp=tmp->next) {
		if (apr_password_validate(cookie, tmp->cookie) == 0)
			return tmp->cmd;
	}
	return 0;
}

char *get_response(char *cookie)
{
	struct auth_entry *tmp;
	for (tmp=auth_top; tmp; tmp=tmp->next) {
		if (apr_password_validate(cookie, tmp->cookie) == 0)
			return tmp->response;
	}
	return 0;
}

void free_config(void)
{
	struct config_entry * x, * nextptr;
	for (x=config_top; x; x=nextptr) {
		nextptr = x->next;
		free(x->key);
		free(x->value);
		free(x);
	}
	config_top = NULL;
}

void free_auth(void)
{
	struct auth_entry * x, * nextptr;
	for (x=auth_top; x; x=nextptr) {
		nextptr = x->next;
		free(x->cookie);
		free(x);
	}
	auth_top = NULL;
}

