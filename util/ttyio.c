/* ttyio.c -  tty i/O functions
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"

static int last_prompt_len;

static FILE *
open_tty(void)
{
    FILE *tty = fopen("/dev/tty", "r");
    if( !tty )
	log_fatal("cannot open /dev/tty: %s\n", strerror(errno) );
    return tty;
}

static void
close_tty( FILE *tty )
{
    fclose(tty);
}



void
tty_printf( const char *fmt, ... )
{
    va_list arg_ptr;

    va_start( arg_ptr, fmt ) ;
    last_prompt_len += vfprintf(stderr,fmt,arg_ptr) ;
    va_end(arg_ptr);
    fflush(stderr);
}


char *
tty_get( const char *prompt )
{
    char *buf;
    int c, n, i;
    FILE *fp;

    last_prompt_len = 0;
    tty_printf( prompt );
    buf = m_alloc(n=50);
    i = 0;
    fp = open_tty();
    while( (c=getc(fp)) != EOF && c != '\n' ) {
	last_prompt_len++;
	if( c == '\t' )
	    c = ' ';
	else if( iscntrl(c) )
	    continue;
	if( !(i < n-1) ) {
	    n += 50;
	    buf = m_realloc( buf, n );
	}
	buf[i++] = c;
    }
    close_tty(fp);
    buf[i] = 0;
    return buf;
}

char *
tty_get_hidden( const char *prompt )
{
    return tty_get( prompt ); /* fixme */
}


void
tty_kill_prompt()
{
    int i;
#if 0
    for(i=0; i < last_prompt_len; i ++ )
	fputc('\b', stderr);
    for(i=0; i < last_prompt_len; i ++ )
	fputc(' ', stderr);
    for(i=0; i < last_prompt_len; i ++ )
	fputc('\b', stderr);
#endif
    last_prompt_len = 0;
    fflush(stderr);
}

