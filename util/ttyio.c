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
#include <unistd.h>
#ifdef HAVE_TCGETATTR
  #include <termios.h>
#endif
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"

static FILE *ttyfp = NULL;
static int last_prompt_len;

static void
init_ttyfp()
{
    if( ttyfp )
	return;

  #if defined(__MINGW32__)
    ttyfp = stderr; /* fixme */
  #else
    ttyfp = fopen("/dev/tty", "r+");
  #endif
    if( !ttyfp )
	log_fatal("cannot open /dev/tty: %s\n", strerror(errno) );
}


void
tty_printf( const char *fmt, ... )
{
    va_list arg_ptr;

    if( !ttyfp )
	init_ttyfp();

    va_start( arg_ptr, fmt ) ;
    last_prompt_len += vfprintf(ttyfp,fmt,arg_ptr) ;
    va_end(arg_ptr);
    fflush(ttyfp);
}


/****************
 * Print a string, but filter all control characters out.
 */
void
tty_print_string( byte *p, size_t n )
{
    if( !ttyfp )
	init_ttyfp();

    for( ; n; n--, p++ )
	if( iscntrl( *p ) ) {
	    putc('\\', ttyfp);
	    if( *p == '\n' )
		putc('n', ttyfp);
	    else if( !*p )
		putc('0', ttyfp);
	    else
		fprintf(ttyfp, "x%02x", *p );
	}
	else
	    putc(*p, ttyfp);
}





static char *
do_get( const char *prompt, int hidden )
{
    char *buf;
    byte cbuf[1];
    int c, n, i;
  #ifdef HAVE_TCGETATTR
    struct termios termsave;
  #endif

    if( !ttyfp )
	init_ttyfp();

    last_prompt_len = 0;
    tty_printf( prompt );
    buf = m_alloc(n=50);
    i = 0;

    if( hidden ) {
      #ifdef HAVE_TCGETATTR
	struct termios term;

	if( tcgetattr(fileno(ttyfp), &termsave) )
	    log_fatal("tcgetattr() failed: %s\n", strerror(errno) );
	term = termsave;
	term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	if( tcsetattr( fileno(ttyfp), TCSAFLUSH, &term ) )
	    log_fatal("tcsetattr() failed: %s\n", strerror(errno) );
      #endif
    }

    /* fixme: How can we avoid that the \n is echoed w/o disabling
     * canonical mode - w/o this kill_prompt can't work */
    while( read(fileno(ttyfp), cbuf, 1) == 1 && *cbuf != '\n' ) {
	if( !hidden )
	    last_prompt_len++;
	c = *cbuf;
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


    if( hidden ) {
      #ifdef HAVE_TCGETATTR
	if( tcsetattr(fileno(ttyfp), TCSAFLUSH, &termsave) )
	    log_error("tcsetattr() failed: %s\n", strerror(errno) );
      #endif
    }
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

    if( !ttyfp )
	init_ttyfp();
    if( !last_prompt_len )
	return;
    fputc('\r', ttyfp);
    for(i=0; i < last_prompt_len; i ++ )
	fputc(' ', ttyfp);
    fputc('\r', ttyfp);
    last_prompt_len = 0;
    fflush(ttyfp);
}

