/* strlist.c -  string helpers
 *	Copyright (C) 1998, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "libjnlib-config.h"
#include "strlist.h"


void
free_strlist( STRLIST sl )
{
    STRLIST sl2;

    for(; sl; sl = sl2 ) {
	sl2 = sl->next;
	jnlib_free(sl);
    }
}


STRLIST
add_to_strlist( STRLIST *list, const char *string )
{
    STRLIST sl;

    sl = jnlib_xmalloc( sizeof *sl + strlen(string));
    sl->flags = 0;
    strcpy(sl->d, string);
    sl->next = *list;
    *list = sl;
    return sl;
}

#if 0
/****************
 * same as add_to_strlist() but if is_utf8 is *not* set a conversion
 * to UTF8 is done
 */
STRLIST
add_to_strlist2( STRLIST *list, const char *string, int is_utf8 )
{
    STRLIST sl;

    if( is_utf8 )
	sl = add_to_strlist( list, string );
    else {
	char *p = native_to_utf8( string );
	sl = add_to_strlist( list, p );
	m_free( p );
    }
    return sl;
}
#endif

STRLIST
append_to_strlist( STRLIST *list, const char *string )
{
    STRLIST r, sl;

    sl = jnlib_xmalloc( sizeof *sl + strlen(string));
    sl->flags = 0;
    strcpy(sl->d, string);
    sl->next = NULL;
    if( !*list )
	*list = sl;
    else {
	for( r = *list; r->next; r = r->next )
	    ;
	r->next = sl;
    }
    return sl;
}

#if 0
STRLIST
append_to_strlist2( STRLIST *list, const char *string, int is_utf8 )
{
    STRLIST sl;

    if( is_utf8 )
	sl = append_to_strlist( list, string );
    else {
	char *p = native_to_utf8( string );
	sl = append_to_strlist( list, p );
	m_free( p );
    }
    return sl;
}
#endif

STRLIST
strlist_prev( STRLIST head, STRLIST node )
{
    STRLIST n;

    for(n=NULL; head && head != node; head = head->next )
	n = head;
    return n;
}

STRLIST
strlist_last( STRLIST node )
{
    if( node )
	for( ; node->next ; node = node->next )
	    ;
    return node;
}



