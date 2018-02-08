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

#ifndef HASH_PROFILE_MAIN
#  include "td2.h"
#endif

unsigned int dohash(const char *data, unsigned int len, unsigned int mod)
{
	unsigned int i, hash = mod;
	for (i = 0; i < len; i++) {
		unsigned int tmp = (hash % 7) + 9; /* note that 7 is a prime < 8. */
		hash = (hash << tmp) ^ (hash >> (32 - tmp)) ^ data[i];
	}
	return hash;
}

/*
 *  A simple 'profiler' for the dohash() function.
 *
 *  gcc -o hash_profile -DHASH_PROFILE_MAIN hash.c
 *  ./hash_profile
 */
#ifdef HASH_PROFILE_MAIN

#define N 100000
#define M 5557

#define R (N/M+6)
#define F (N/M-5)

struct ipent;
struct ipent {
	unsigned int ip;
	struct ipent *next;
};

unsigned int ips[N];

struct ipent listent[3][N];
struct ipent *list[3][M];

int main()
{
	unsigned int i, m, x=0;
	unsigned roof=0, floor=0;

	srandom(time(0));
	m = random();

	for (i=0; i<N; i++) {
		if ((i&0x3ff) == 0) x+=random()%N + N*7;
		ips[i] = x++ ^ m;
		
	}
	printf("Max: %08x (%d) ^ %08x.\n", x, x, m);

	x=random();
	printf("Pass 1 with mod = %08x\n", x);
	for (i=0; i<N; i++) {
		int slot = dohash((void*)&ips[i], 4, x) % M;
		listent[0][i].ip = ips[i];
		listent[0][i].next = list[0][slot];
		list[0][slot] = &listent[0][i];
	}

	// x=random();
	printf("Pass 2 with mod = %08x\n", ++x);
	for (i=0; i<N; i++) {
		int slot = dohash((void*)&ips[i], 4, x) % M;
		listent[1][i].ip = ips[i];
		listent[1][i].next = list[1][slot];
		list[1][slot] = &listent[1][i];
	}

	// x=random();
	printf("Pass 3 with mod = %08x\n", ++x);
	for (i=0; i<N; i++) {
		int slot = dohash((void*)&ips[i], 4, x) % M;
		listent[2][i].ip = ips[i];
		listent[2][i].next = list[2][slot];
		list[2][slot] = &listent[2][i];
	}

	for (i=0; i<N; i++) {
		if ( listent[0][i].next ) {
			struct ipent *t = listent[1][i].next;
			while (t) {
				if ( listent[0][i].next->ip == t->ip ) {
					int j, k, l, s;
					int ip1 = listent[0][i].ip, ip2 = listent[0][i].next->ip;
					for (j=k=0; j<1000; j++) {
						int r = random();
						if ( dohash((void*)&ip1, 4, r) ==
						     dohash((void*)&ip2, 4, r) ) k++;
					}
					for (j=l=0; j<1000; j++) {
						if ( dohash((void*)&ip1, 4, x+j) ==
						     dohash((void*)&ip2, 4, x+j) ) l++;
					}
					printf("[%06d]  Double: %08x %08x "
							"%04.1f/%04.1f%% XX", i,
							listent[0][i].ip, listent[0][i].next->ip,
							k/10.0, l/10.0);
					for (s=1; s<31; s++) {
						if ( dohash((void*)&ip1, 4, x+s) ==
						     dohash((void*)&ip2, 4, x+s) )
							printf("X");
						else
							printf(".");
					}
					printf("\n");
				}
				t = t->next;
			}
		}
	}

	for (i=0; i<N; i++) {
		if ( listent[0][i].next ) {
			struct ipent *t = listent[1][i].next;
			while (t) {
				if ( listent[0][i].next->ip == t->ip ) {
					struct ipent *u = listent[2][i].next;
					while (u) {
						if ( listent[0][i].next->ip == u->ip ) {
							int j, k, l, s;
							int ip1 = listent[0][i].ip, ip2 = listent[0][i].next->ip;
							for (j=k=0; j<1000; j++) {
								int r = random();
								if ( dohash((void*)&ip1, 4, r) ==
								     dohash((void*)&ip2, 4, r) ) k++;
							}
							for (j=l=0; j<1000; j++) {
								if ( dohash((void*)&ip1, 4, x+j) ==
								     dohash((void*)&ip2, 4, x+j) ) l++;
							}
							printf("[%06d] Tripple: %08x %08x "
									"%04.1f/%04.1f%% XXX", i,
									listent[0][i].ip, listent[0][i].next->ip,
									k/10.0, l/10.0);
							for (s=1; s<30; s++) {
								if ( dohash((void*)&ip1, 4, x+s) ==
								     dohash((void*)&ip2, 4, x+s) )
									printf("X");
								else
									printf(".");
							}
							printf("\n");
						}
						u = u->next;
					}
				}
				t = t->next;
			}
		}
	}

	for (i=0; i<M; i++) {
		int members = 0;
		struct ipent *t = list[1][i];
		while (t) { members++; t = t->next; }
		if ( members > R ) roof++;
		if ( members < F ) floor++;
	}

	printf("Distribution: %d (%.2f%%) slots over roof (%d).\n", roof, (100.0*roof)/M, R);
	printf("Distribution: %d (%.2f%%) slots under floor (%d).\n", floor, (100.0*floor)/M, F);

	return 0;
}

#endif

