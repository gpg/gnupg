/* ttyio.c -  tty i/O functions
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#ifdef HAVE_TCGETATTR
  #include <termios.h>
#else
  #ifdef HAVE_TERMIO_H
    /* simulate termios with termio */
    #include <termio.h>
    #define termios termio
    #define tcsetattr ioctl
    #define TCSAFLUSH TCSETAF
    #define tcgetattr(A,B) ioctl(A,TCGETA,B)
    #define HAVE_TCGETATTR
  #endif
#endif
#ifdef __MINGW32__ /* use the odd Win32 functions */
  #include <windows.h>
  #ifdef HAVE_TCGETATTR
     #error mingw32 and termios
  #endif
#endif
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"

#define CONTROL_D ('D' - 'A' + 1)
#ifdef __VMS
  #define TERMDEVICE "/dev/tty"
#else
  #define TERMDEVICE "/dev/tty"
#endif

#ifdef __MINGW32__ /* use the odd Win32 functions */
static struct {
    HANDLE in, out;
} con;
#define DEF_INPMODE  (ENABLE_LINE_INPUT|ENABLE_ECHO_INPUT    \
					|ENABLE_PROCESSED_INPUT )
#define HID_INPMODE  (ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT )
#define DEF_OUTMODE  (ENABLE_WRAP_AT_EOL_OUTPUT|ENABLE_PROCESSED_OUTPUT)

#else /* yeah, we have a real OS */
static FILE *ttyfp = NULL;
#endif

static int initialized;
static int last_prompt_len;
static int batchmode;
static int no_terminal;

#ifdef HAVE_TCGETATTR
static struct termios termsave;
static int restore_termios;
#endif

#ifdef HAVE_TCGETATTR
static void
cleanup(void)
{
    if( restore_termios ) {
	restore_termios = 0; /* do it prios in case it is interrupted again */
	if( tcsetattr(fileno(ttyfp), TCSAFLUSH, &termsave) )
	    log_error("tcsetattr() failed: %s\n", strerror(errno) );
    }
}
#endif

static void
init_ttyfp(void)
{
    if( initialized )
	return;

  #if defined(__MINGW32__)
    {
	SECURITY_ATTRIBUTES sa;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	con.out = CreateFileA( "CONOUT$", GENERIC_READ|GENERIC_WRITE,
			       FILE_SHARE_READ|FILE_SHARE_WRITE,
			       &sa, OPEN_EXISTING, 0, 0 );
	if( con.out == INVALID_HANDLE_VALUE )
	    log_fatal("open(CONOUT$) failed: rc=%d", (int)GetLastError() );
	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	con.in = CreateFileA( "CONIN$", GENERIC_READ|GENERIC_WRITE,
			       FILE_SHARE_READ|FILE_SHARE_WRITE,
			       &sa, OPEN_EXISTING, 0, 0 );
	if( con.in == INVALID_HANDLE_VALUE )
	    log_fatal("open(CONIN$) failed: rc=%d", (int)GetLastError() );
    }
    SetConsoleMode(con.in, DEF_INPMODE );
    SetConsoleMode(con.out, DEF_OUTMODE );

  #elif defined(__EMX__)
    ttyfp = stdout; /* Fixme: replace by the real functions: see wklib */
  #else
    ttyfp = batchmode? stderr : fopen(TERMDEVICE, "r+");
    if( !ttyfp ) {
	log_error("cannot open /dev/tty: %s\n", strerror(errno) );
	exit(2);
    }
  #endif
  #ifdef HAVE_TCGETATTR
    atexit( cleanup );
  #endif
    initialized = 1;
}

int
tty_batchmode( int onoff )
{
    int old = batchmode;
    if( onoff != -1 )
	batchmode = onoff;
    return old;
}

int
tty_no_terminal(int onoff)
{
    int old = no_terminal;
    no_terminal = onoff ? 1 : 0;
    return old;
}

void
tty_printf( const char *fmt, ... )
{
    va_list arg_ptr;

    if (no_terminal)
	return;

    if( !initialized )
	init_ttyfp();

    va_start( arg_ptr, fmt ) ;
  #ifdef __MINGW32__
    { static char *buf;
      static size_t bufsize;
	int n;
	DWORD nwritten;

      #if 0 /* the dox say, that there is a snprintf, but I didn't found
	     * it, so we use a static buffer for now */
	do {
	    if( n == -1 || !buf ) {
		m_free(buf);
		bufsize += 200;
		/* better check the new size; (we use M$ functions) */
		if( bufsize > 50000 )
		    log_bug("vsnprintf probably failed\n");
		buf = m_alloc( bufsize );
	    }
	    n = _vsnprintf(buf, bufsize-1, fmt, arg_ptr);
	} while( n == -1 );
      #else
	if( !buf ) {
	    bufsize += 1000;
	    buf = m_alloc( bufsize );
	}
	n = vsprintf(buf, fmt, arg_ptr);
	if( n == -1 )
	    log_bug("vsprintf() failed\n");
      #endif

	if( !WriteConsoleA( con.out, buf, n, &nwritten, NULL ) )
	    log_fatal("WriteConsole failed: rc=%d", (int)GetLastError() );
	if( n != nwritten )
	    log_fatal("WriteConsole failed: %d != %d\n", n, nwritten );
	last_prompt_len += n;
    }
  #else
    last_prompt_len += vfprintf(ttyfp,fmt,arg_ptr) ;
    fflush(ttyfp);
  #endif
    va_end(arg_ptr);
}


/****************
 * Print a string, but filter all control characters out.
 */
void
tty_print_string( byte *p, size_t n )
{
    if (no_terminal)
	return;

    if( !initialized )
	init_ttyfp();

  #ifdef __MINGW32__
    /* not so effective, change it if you want */
    for( ; n; n--, p++ )
	if( iscntrl( *p ) ) {
	    if( *p == '\n' )
		tty_printf("\\n");
	    else if( !*p )
		tty_printf("\\0");
	    else
		tty_printf("\\x%02x", *p);
	}
	else
	    tty_printf("%c", *p);
  #else
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
  #endif
}

void
tty_print_utf8_string2( byte *p, size_t n, size_t max_n )
{
    size_t i;
    char *buf;

    if (no_terminal)
	return;

    /* we can handle plain ascii simpler, so check for it first */
    for(i=0; i < n; i++ ) {
	if( p[i] & 0x80 )
	    break;
    }
    if( i < n ) {
	buf = utf8_to_native( p, n );
	if( strlen( buf ) > max_n ) {
	    buf[max_n] = 0;
	}
	/*(utf8 conversion already does the control character quoting)*/
	tty_printf("%s", buf );
	m_free( buf );
    }
    else {
	if( n > max_n ) {
	    n = max_n;
	}
	tty_print_string( p, n );
    }
}

void
tty_print_utf8_string( byte *p, size_t n )
{
    tty_print_utf8_string2( p, n, n );
}


static char *
do_get( const char *prompt, int hidden )
{
    char *buf;
    byte cbuf[1];
    int c, n, i;

    if( batchmode ) {
	log_error("Sorry, we are in batchmode - can't get input\n");
	exit(2);
    }

    if (no_terminal) {
	log_error("Sorry, no terminal at all requested - can't get input\n");
	exit(2);
    }

    if( !initialized )
	init_ttyfp();

    last_prompt_len = 0;
    tty_printf( "%s", prompt );
    buf = m_alloc(n=50);
    i = 0;

  #ifdef __MINGW32__ /* windoze version */
    if( hidden )
	SetConsoleMode(con.in, HID_INPMODE );

    for(;;) {
	DWORD nread;

	if( !ReadConsoleA( con.in, cbuf, 1, &nread, NULL ) )
	    log_fatal("ReadConsole failed: rc=%d", (int)GetLastError() );
	if( !nread )
	    continue;
	if( *cbuf == '\n' )
	    break;

	if( !hidden )
	    last_prompt_len++;
	c = *cbuf;
	if( c == '\t' )
	    c = ' ';
	else if( c > 0xa0 )
	    ; /* we don't allow 0xa0, as this is a protected blank which may
	       * confuse the user */
	else if( iscntrl(c) )
	    continue;
	if( !(i < n-1) ) {
	    n += 50;
	    buf = m_realloc( buf, n );
	}
	buf[i++] = c;
    }

    if( hidden )
	SetConsoleMode(con.in, DEF_INPMODE );

  #else /* unix version */
    if( hidden ) {
      #ifdef HAVE_TCGETATTR
	struct termios term;

	if( tcgetattr(fileno(ttyfp), &termsave) )
	    log_fatal("tcgetattr() failed: %s\n", strerror(errno) );
	restore_termios = 1;
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
	if( c == CONTROL_D )
	    log_info("control d found\n");
	if( c == '\t' )
	    c = ' ';
	else if( c > 0xa0 )
	    ; /* we don't allow 0xa0, as this is a protected blank which may
	       * confuse the user */
	else if( iscntrl(c) )
	    continue;
	if( !(i < n-1) ) {
	    n += 50;
	    buf = m_realloc( buf, n );
	}
	buf[i++] = c;
    }
    if( *cbuf != '\n' ) {
	buf[0] = CONTROL_D;
	i = 1;
    }


    if( hidden ) {
      #ifdef HAVE_TCGETATTR
	if( tcsetattr(fileno(ttyfp), TCSAFLUSH, &termsave) )
	    log_error("tcsetattr() failed: %s\n", strerror(errno) );
	restore_termios = 0;
      #endif
    }
  #endif /* end unix version */
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
    if ( no_terminal )
	return;

    if( !initialized )
	init_ttyfp();

    if( batchmode )
	last_prompt_len = 0;
    if( !last_prompt_len )
	return;
  #ifdef __MINGW32__
    tty_printf("\r%*s\r", last_prompt_len, "");
  #else
    {
	int i;
	putc('\r', ttyfp);
	for(i=0; i < last_prompt_len; i ++ )
	    putc(' ', ttyfp);
	putc('\r', ttyfp);
	fflush(ttyfp);
    }
  #endif
    last_prompt_len = 0;
}


int
tty_get_answer_is_yes( const char *prompt )
{
    int yes;
    char *p = tty_get( prompt );
    tty_kill_prompt();
    yes = answer_is_yes(p);
    m_free(p);
    return yes;
}

