/* pref.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#define DEFINES_PREF_LIST 1
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "errors.h"
#include "memory.h"
#include "util.h"
#include "ttyio.h"
#include "i18n.h"
#include "pref.h"


#define N_CIPHERS 3
#define N_DIGESTS 4
#define N_COMPRS  3

struct pref_list_s {
    PREF_LIST *extend; /* if we need more, we link them together */
    byte cipher[N_CIPHERS]; /* cipher algos */
    byte digest[N_DIGESTS]; /* digest algos */
    byte compr [N_COMPRS ]; /* compress algos (a 255 denotes no compression)*/
};


#if 0
PREF_LIST
new_pref_list()
{
    return m_alloc_clear( sizeof(*PREF_LIST) );
}

void
release_pref_list( PREF_LIST pref )
{
    while( pref ) {
	PREF_LIST tmp = pref->extend;
	m_free( pref );
	pref = tmp;
    }
}

PREF_LIST
copy_pref_list( PREF_LIST s )
{
    PREF_LIST ss, ss, d = new_pref_list();
    *d = *s;
    for( ss = s->extend; ss; ss = ss->extend ) {

	WORK WORK WORK
	d->extend = new_pref_list();

	*d->extend = *ss;
    }
    return d;
}
#endif

