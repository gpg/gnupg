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
#include <termios.h>
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"

static int last_prompt_len;

static FILE *
open_tty(struct termios *termsave )
{
    struct termios term;

    FILE *tty = fopen("/dev/tty", "r");
    if( !tty )
	log_fatal("cannot open /dev/tty: %s\n", strerror(errno) );

    if( termsave ) { /* hide input */
	if( tcgetattr(fileno(tty), termsave) )
	    log_fatal("tcgetattr() failed: %s\n", strerror(errno) );
	term = *termsave;
	term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	if( tcsetattr( fileno(tty), TCSAFLUSH, &term ) )
	    log_fatal("tcsetattr() failed: %s\n", strerror(errno) );
    }


    return tty;
}

static void
close_tty( FILE *tty, struct termios *termsave )
{
    if( termsave ) {
	if( tcsetattr(fileno(tty), TCSAFLUSH, termsave) )
	    log_error("tcsetattr() failed: %s\n", strerror(errno) );
	putc('\n', stderr);
    }
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


/****************
 * Print a string, but filter all control characters out.
 */
void
tty_print_string( byte *p, size_t n )
{
    for( ; n; n--, p++ )
	if( iscntrl( *p ) ) {
	    putc('\\', stderr);
	    if( *p == '\n' )
		putc('n', stderr);
	    else if( !*p )
		putc('0', stderr);
	    else
		fprintf(stderr, "x%02x", *p );
	}
	else
	    putc(*p, stderr);
}





static char *
do_get( const char *prompt, int hidden )
{
    char *buf;
    int c, n, i;
    FILE *fp;
    struct termios termsave;

    last_prompt_len = 0;
    tty_printf( prompt );
    buf = m_alloc(n=50);
    i = 0;
    fp = open_tty(hidden? &termsave: NULL);
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
    close_tty(fp, hidden? &termsave: NULL);
    buf[i] = 0;
    return buf;
}


char *
tty_get( const char *prompt )
{
    return do_get( prompt, 0 );
}

char *
tty_get_hidden( const char *prompt )
{
    return do_get( prompt, 1 );
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

