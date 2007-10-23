/* ttyio.c -  tty i/O functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#ifdef _WIN32 /* use the odd Win32 functions */
#include <windows.h>
#ifdef HAVE_TCGETATTR
#error windows and termios
#endif
#endif
#include <errno.h>
#include <ctype.h>
#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "util.h"
#include "memory.h"
#include "ttyio.h"

#define CONTROL_D ('D' - 'A' + 1)

#ifdef _WIN32 /* use the odd Win32 functions */
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



/* This is a wrapper around ttyname so that we can use it even when
   the standard streams are redirected.  It figures the name out the
   first time and returns it in a statically allocated buffer. */
const char *
tty_get_ttyname (void)
{
  static char *name;

  /* On a GNU system ctermid() always return /dev/tty, so this does
     not make much sense - however if it is ever changed we do the
     Right Thing now. */
#ifdef HAVE_CTERMID
  static int got_name;

  if (!got_name)
    {
      const char *s;
      s = ctermid (NULL);
      if (s)
        name = strdup (s);
      got_name = 1;
    }
#endif
  /* Assume the standard tty on memory error or when there is no
     ctermid. */
  return name? name : "/dev/tty";
}


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

#if defined(_WIN32)
    {
	SECURITY_ATTRIBUTES sa;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	con.out = CreateFileA( "CONOUT$", GENERIC_READ|GENERIC_WRITE,
			       FILE_SHARE_READ|FILE_SHARE_WRITE,
			       &sa, OPEN_EXISTING, 0, 0 );
	if( con.out == INVALID_HANDLE_VALUE )
	    log_fatal ("open(CONOUT$) failed: %s", w32_strerror (0));
	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	con.in = CreateFileA( "CONIN$", GENERIC_READ|GENERIC_WRITE,
			       FILE_SHARE_READ|FILE_SHARE_WRITE,
			       &sa, OPEN_EXISTING, 0, 0 );
	if (con.in == INVALID_HANDLE_VALUE)
            log_fatal ("open(CONIN$) failed: %s", w32_strerror (0));
    }
    SetConsoleMode(con.in, DEF_INPMODE );
    SetConsoleMode(con.out, DEF_OUTMODE );

#elif defined(__EMX__)
    ttyfp = stdout; /* Fixme: replace by the real functions: see wklib */
#else
    ttyfp = batchmode? stderr : fopen( tty_get_ttyname (), "r+");
    if( !ttyfp ) {
	log_error("cannot open `%s': %s\n",
                  tty_get_ttyname (), strerror(errno) );
	exit(2);
    }
#ifdef HAVE_LIBREADLINE
    rl_catch_signals = 0;
    rl_instream = rl_outstream = ttyfp;
    rl_inhibit_completion = 1;
#endif
#endif
#ifdef HAVE_TCGETATTR
    atexit( cleanup );
#endif
    initialized = 1;
}

#ifdef HAVE_LIBREADLINE
void
tty_enable_completion(rl_completion_func_t *completer)
{
  if( no_terminal )
    return;

  if( !initialized )
    init_ttyfp();

  rl_attempted_completion_function=completer;
  rl_inhibit_completion=0;
}

void
tty_disable_completion(void)
{
  if( no_terminal )
    return;

  if( !initialized )
    init_ttyfp();

  rl_inhibit_completion=1;
}
#endif /*HAVE_LIBREADLINE*/

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
#ifdef _WIN32
    {   
        char *buf = NULL;
        int n;
	DWORD nwritten;

	n = vasprintf(&buf, fmt, arg_ptr);
	if( !buf )
	    log_bug("vasprintf() failed\n");
        
	if (!WriteConsoleA (con.out, buf, n, &nwritten, NULL))
	    log_fatal ("WriteConsole failed: %s", w32_strerror (0));
	if( n != nwritten )
	    log_fatal ("WriteConsole failed: %d != %d\n", n, (int)nwritten );
	last_prompt_len += n;
        xfree (buf);
    }
#else
    last_prompt_len += vfprintf(ttyfp,fmt,arg_ptr) ;
    fflush(ttyfp);
#endif
    va_end(arg_ptr);
}


/* Same as tty_printf but if FP is not NULL, behave like the standard
   fprintf. */
void
tty_fprintf (FILE *fp, const char *fmt, ... )
{
  va_list arg_ptr;

  if (fp)
    {
      va_start (arg_ptr, fmt) ;
      vfprintf (fp, fmt, arg_ptr );
      va_end (arg_ptr);
      return;
    }

  if (no_terminal)
    return;

  if( !initialized )
    init_ttyfp();

    va_start( arg_ptr, fmt ) ;
#ifdef _WIN32
    {   
        char *buf = NULL;
        int n;
	DWORD nwritten;

	n = vasprintf(&buf, fmt, arg_ptr);
	if( !buf )
	    log_bug("vasprintf() failed\n");
        
	if (!WriteConsoleA (con.out, buf, n, &nwritten, NULL))
	    log_fatal ("WriteConsole failed: %s", w32_strerror (0));
	if (n != nwritten)
	    log_fatal ("WriteConsole failed: %d != %d\n", n, (int)nwritten);
	last_prompt_len += n;
        xfree (buf);
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
tty_print_string( const byte *p, size_t n )
{
    if (no_terminal)
	return;

    if( !initialized )
	init_ttyfp();

#ifdef _WIN32
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
tty_print_utf8_string2 (const byte *p, size_t n, size_t max_n )
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
	buf = utf8_to_native( p, n, 0 );
	if( max_n && (strlen( buf ) > max_n )) {
	    buf[max_n] = 0;
	}
	/*(utf8 conversion already does the control character quoting)*/
	tty_printf("%s", buf );
	xfree( buf );
    }
    else {
	if( max_n && (n > max_n) ) {
	    n = max_n;
	}
	tty_print_string( p, n );
    }
}

void
tty_print_utf8_string( const byte *p, size_t n )
{
    tty_print_utf8_string2( p, n, 0 );
}


static char *
do_get( const char *prompt, int hidden )
{
    char *buf;
#ifndef __riscos__
    byte cbuf[1];
#endif
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
    n = 50;
    buf = hidden ? xmalloc_secure(n) : xmalloc(n);
    i = 0;

#ifdef _WIN32 /* windoze version */
    if( hidden )
	SetConsoleMode(con.in, HID_INPMODE );

    tty_printf( "%s", prompt );

    for(;;) {
	DWORD nread;

	if (!ReadConsoleA (con.in, cbuf, 1, &nread, NULL))
	    log_fatal ("ReadConsole failed: %s", w32_strerror (0));
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
	    buf = xrealloc( buf, n );
	}
	buf[i++] = c;
    }

    if( hidden )
	SetConsoleMode(con.in, DEF_INPMODE );

#elif defined(__riscos__)
    tty_printf( "%s", prompt );
    do {
        c = riscos_getchar();
        if (c == 0xa || c == 0xd) { /* Return || Enter */
            c = (int) '\n';
        } else if (c == 0x8 || c == 0x7f) { /* Backspace || Delete */
            if (i>0) {
                i--;
                if (!hidden) {
                    last_prompt_len--;
                    fputc(8, ttyfp);
                    fputc(32, ttyfp);
                    fputc(8, ttyfp);
                    fflush(ttyfp);
                }
            } else {
                fputc(7, ttyfp);
                fflush(ttyfp);
            }
            continue;
        } else if (c == (int) '\t') { /* Tab */
            c = ' ';
        } else if (c > 0xa0) {
            ; /* we don't allow 0xa0, as this is a protected blank which may
               * confuse the user */
        } else if (iscntrl(c)) {
            continue;
        }
        if(!(i < n-1)) {
            n += 50;
            buf = xrealloc(buf, n);
        }
        buf[i++] = c;
        if (!hidden) {
	    last_prompt_len++;
            fputc(c, ttyfp);
            fflush(ttyfp);
        }
    } while (c != '\n');
    i = (i>0) ? i-1 : 0;
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

    tty_printf( "%s", prompt );

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
	    buf = xrealloc( buf, n );
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
#ifdef HAVE_LIBREADLINE
    if (!batchmode && !no_terminal) {
      char *line;
      char *buf;

      if( !initialized )
	init_ttyfp();

      last_prompt_len = 0;

      line = readline (prompt?prompt:"");

      /* We need to copy it to memory controlled by our malloc
         implementations; further we need to convert an EOF to our
         convention. */
      buf = xmalloc(line? strlen(line)+1:2);
      if (line)
        {
          strcpy (buf, line);
          trim_spaces (buf);
          if (strlen (buf) > 2 )
            add_history (line); /* Note that we test BUF but add LINE. */
          free (line);
        }
      else
        {
          buf[0] = CONTROL_D;
          buf[1] = 0;
        }
      return buf;
    }
    else
#endif /* HAVE_LIBREADLINE */
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
#ifdef _WIN32
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
    xfree(p);
    return yes;
}
