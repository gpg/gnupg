/* ttyio.c -  tty i/O functions
 * Copyright (C) 1997-2019 Werner Koch
 * Copyright (C) 1998-2020 Free Software Foundation, Inc.
 * Copyright (C) 2015-2020 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#ifdef HAVE_TCGETATTR
# include <termios.h>
#else
# ifdef HAVE_TERMIO_H
/* simulate termios with termio */
#  include <termio.h>
#  define termios termio
#  define tcsetattr ioctl
#  define TCSAFLUSH TCSETAF
#  define tcgetattr(A,B) ioctl(A,TCGETA,B)
#  define HAVE_TCGETATTR
# endif
#endif
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
# ifdef HAVE_TCGETATTR
#  error mingw32 and termios
# endif
#endif
#include <errno.h>
#include <ctype.h>

#include "util.h"
#include "ttyio.h"
#include "i18n.h"
#include "common-defs.h"

#define CONTROL_D ('D' - 'A' + 1)


#ifdef HAVE_W32_SYSTEM
static struct {
    HANDLE in, out;
} con;
#define DEF_INPMODE  (ENABLE_LINE_INPUT|ENABLE_ECHO_INPUT    \
                                       |ENABLE_PROCESSED_INPUT )
#define HID_INPMODE  (ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT )
#define DEF_OUTMODE  (ENABLE_WRAP_AT_EOL_OUTPUT|ENABLE_PROCESSED_OUTPUT)

#else /* Unix */
static FILE *ttyfp = NULL;
#endif /* Unix */

static int initialized;
static int last_prompt_len;
static int batchmode;
static int no_terminal;

#ifdef HAVE_TCGETATTR
    static struct termios termsave;
    static int restore_termios;
#endif

/* Hooks set by gpgrlhelp.c if required. */
static void (*my_rl_set_completer) (rl_completion_func_t *);
static void (*my_rl_inhibit_completion) (int);
static void (*my_rl_cleanup_after_signal) (void);
static void (*my_rl_init_stream) (FILE *);
static char *(*my_rl_readline) (const char*);
static void (*my_rl_add_history) (const char*);


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
      /* Note that despite our checks for these macros the function is
         not necessarily thread save.  We mainly do this for
         portability reasons, in case L_ctermid is not defined. */
# if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(_POSIX_TRHEADS)
      char buffer[L_ctermid];
      s = ctermid (buffer);
# else
      s = ctermid (NULL);
# endif
      if (s)
        name = strdup (s);
      got_name = 1;
    }
#endif /*HAVE_CTERMID*/
  /* Assume the standard tty on memory error or when there is no
     ctermid. */
  return name? name : "/dev/tty";
}



#ifdef HAVE_TCGETATTR
static void
cleanup(void)
{
  if (restore_termios)
    {
      restore_termios = 0; /* do it prior in case it is interrupted again */
      if (tcsetattr(fileno(ttyfp), TCSAFLUSH, &termsave))
        log_error ("tcsetattr() failed: %s\n", strerror (errno));
    }
}
#endif /*HAVE_TCGETATTR*/


static void
init_ttyfp(void)
{
  if (initialized)
    return;

#ifdef HAVE_W32_SYSTEM
  {
    SECURITY_ATTRIBUTES sa;

    memset (&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    con.out = CreateFileA ("CONOUT$", GENERIC_READ|GENERIC_WRITE,
                           FILE_SHARE_READ|FILE_SHARE_WRITE,
                           &sa, OPEN_EXISTING, 0, 0 );
    if (con.out == INVALID_HANDLE_VALUE)
      log_fatal ("open(CONOUT$) failed: %s\n", w32_strerror (-1));

    memset (&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    con.in = CreateFileA ("CONIN$", GENERIC_READ|GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                          &sa, OPEN_EXISTING, 0, 0 );
    if (con.in == INVALID_HANDLE_VALUE)
      log_fatal ("open(CONIN$) failed: %s\n", w32_strerror (-1));
  }
  SetConsoleMode (con.in, DEF_INPMODE);
  SetConsoleMode (con.out, DEF_OUTMODE);

#else /* Unix */
  ttyfp = batchmode? stderr : fopen (tty_get_ttyname (), "r+");
  if (!ttyfp)
    {
      log_error ("cannot open '%s': %s\n", tty_get_ttyname (), strerror(errno));
      exit (2);
    }
  if (my_rl_init_stream)
    my_rl_init_stream (ttyfp);
#endif /* Unix */

#ifdef HAVE_TCGETATTR
  atexit (cleanup);
#endif

  initialized = 1;
}


int
tty_batchmode( int onoff )
{
  int old = batchmode;
  if (onoff != -1)
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


#ifdef HAVE_W32_SYSTEM
/* Write the UTF-8 encoded STRING to the console.  */
static void
w32_write_console (const char *string)
{
  wchar_t *wstring;
  DWORD n, nwritten;

  wstring = utf8_to_wchar (string);
  if (!wstring)
    log_fatal ("w32_write_console failed: %s", strerror (errno));
  n = wcslen (wstring);

  if (!WriteConsoleW (con.out, wstring, n, &nwritten, NULL))
    {
      static int shown;
      if (!shown)
        {
          shown = 1;
          log_info ("WriteConsole failed: %s", w32_strerror (-1));
          log_info ("Please configure a suitable font for the console\n");
        }
      n = strlen (string);
      if (!WriteConsoleA (con.out, string, n , &nwritten, NULL))
        log_fatal ("WriteConsole fallback failed: %s", w32_strerror (-1));
    }
  else
    {
      if (n != nwritten)
        log_fatal ("WriteConsole failed: %lu != %lu\n",
                   (unsigned long)n, (unsigned long)nwritten);
    }
  last_prompt_len += n;
  xfree (wstring);
}
#endif /*HAVE_W32_SYSTEM*/


void
tty_printf (const char *fmt, ... )
{
  va_list arg_ptr;

  if (no_terminal)
    return;

  if (!initialized)
    init_ttyfp ();

  va_start (arg_ptr, fmt);

#ifdef HAVE_W32_SYSTEM
  {
    char *buf = NULL;

    vasprintf(&buf, fmt, arg_ptr);
    if (!buf)
      log_bug ("vasprintf() failed\n");
    w32_write_console (buf);
    xfree (buf);
  }
#else /* Unix */
  last_prompt_len += vfprintf (ttyfp, fmt, arg_ptr) ;
  fflush (ttyfp);
#endif /* Unix */
  va_end(arg_ptr);
}


/* Same as tty_printf but if FP is not NULL, behave like a regular
   fprintf. */
void
tty_fprintf (estream_t fp, const char *fmt, ... )
{
  va_list arg_ptr;

  if (fp)
    {
      va_start (arg_ptr, fmt) ;
      es_vfprintf (fp, fmt, arg_ptr );
      va_end (arg_ptr);
      return;
    }

  if (no_terminal)
    return;

  if (!initialized)
    init_ttyfp ();

  va_start (arg_ptr, fmt);

#ifdef HAVE_W32_SYSTEM
  {
    char *buf = NULL;

    vasprintf (&buf, fmt, arg_ptr);
    if (!buf)
      log_bug ("vasprintf() failed\n");
    w32_write_console (buf);
    xfree (buf);
  }
#else /* Unix */
  last_prompt_len += vfprintf(ttyfp,fmt,arg_ptr) ;
  fflush(ttyfp);
#endif /* Unix */

  va_end(arg_ptr);
}


/* Print a string, but filter all control characters out.  If FP is
 * not NULL print to that stream instead to the tty.  */
static void
do_print_string (estream_t fp, const byte *p, size_t n )
{
  if (no_terminal && !fp)
    return;

  if (!initialized && !fp)
    init_ttyfp();

  if (fp)
    {
      print_utf8_buffer (fp, p, n);
      return;
    }

#ifdef HAVE_W32_SYSTEM
  /* Not so effective, change it if you want */
  for (; n; n--, p++)
    {
      if (iscntrl (*p))
        {
          if( *p == '\n' )
            tty_printf ("\\n");
          else if( !*p )
            tty_printf ("\\0");
          else
            tty_printf ("\\x%02x", *p);
        }
      else
        tty_printf ("%c", *p);
    }
#else /* Unix */
  for (; n; n--, p++)
    {
      if (iscntrl (*p))
        {
          putc ('\\', ttyfp);
          if ( *p == '\n' )
            putc ('n', ttyfp);
          else if ( !*p )
            putc ('0', ttyfp);
          else
            fprintf (ttyfp, "x%02x", *p );
        }
      else
        putc (*p, ttyfp);
    }
#endif /* Unix */
}


void
tty_print_utf8_string2 (estream_t fp, const byte *p, size_t n, size_t max_n)
{
  size_t i;
  char *buf;

  if (no_terminal && !fp)
    return;

  /* We can handle plain ascii simpler, so check for it first. */
  for(i=0; i < n; i++ )
    {
      if (p[i] & 0x80)
        break;
    }
  if (i < n)
    {
      buf = utf8_to_native ((const char *)p, n, 0);
      if (max_n && (strlen (buf) > max_n))
        buf[max_n] = 0;
      /* (utf8_to_native already did  the control character quoting) */
      tty_fprintf (fp, "%s", buf);
      xfree (buf);
    }
  else
    {
      if (max_n && (n > max_n))
        n = max_n;
      do_print_string (fp, p, n );
    }
}


void
tty_print_utf8_string (const byte *p, size_t n)
{
  tty_print_utf8_string2 (NULL, p, n, 0);
}


/* Read a string from the tty using PROMPT.  If HIDDEN is set the
 * input is not echoed.  */
static char *
do_get (const char *prompt, int hidden)
{
  char *buf;
  int  n;  /* Allocated size of BUF.  */
  int  i;  /* Number of bytes in BUF. */
  int  c;
#ifdef HAVE_W32_SYSTEM
  char *utf8buf;
  int errcount = 0;
#else
  byte cbuf[1];
#endif

  if (batchmode)
    {
      log_error (_("Sorry, we are in batchmode - can't get input\n"));
      exit (2);
    }

  if (no_terminal)
    {
      log_error (_("Sorry, no terminal at all requested - can't get input\n"));
      exit (2);
    }

  if( !initialized )
    init_ttyfp();

  last_prompt_len = 0;
  tty_printf( "%s", prompt );
  buf = xmalloc((n=50));
  i = 0;

#ifdef HAVE_W32_SYSTEM
  if (hidden)
    SetConsoleMode(con.in, HID_INPMODE );

  utf8buf = NULL;
  for (;;)
    {
      DWORD nread;
      wchar_t wbuf[2];
      const unsigned char *s;

      if (!ReadConsoleW (con.in, wbuf, 1, &nread, NULL))
        log_fatal ("ReadConsole failed: %s", w32_strerror (-1));
      if (!nread)
        continue;

      wbuf[1] = 0;
      xfree (utf8buf);
      utf8buf = wchar_to_utf8 (wbuf);
      if (!utf8buf)
        {
          log_info ("wchar_to_utf8 failed: %s\n", strerror (errno));
          if (++errcount > 10)
            log_fatal (_("too many errors; giving up\n"));
          continue;
        }
      if (*utf8buf == '\n')
        {
          if (utf8buf[1])
            {
              log_info ("ReadConsole returned more than requested"
                        " (0x0a,0x%02x)\n", utf8buf[1]);
              if (++errcount > 10)
                log_fatal (_("too many errors; giving up\n"));
            }
          break;
        }
      if (!hidden)
        last_prompt_len++;

      for (s=utf8buf; *s; s++)
        {
          c = *s;
          if (c == '\t')
            c = ' ';  /* Map tab to a space.  */
          else if ((c >= 0 && c <= 0x1f) || c == 0x7f)
            continue; /* Remove control characters.  */
          if (!(i < n-1))
            {
              n += 50;
              buf = xrealloc (buf, n);
            }
          buf[i++] = c;
        }
    }
  xfree (utf8buf);

  if (hidden)
    SetConsoleMode(con.in, DEF_INPMODE );

#else /* Unix */

  if (hidden)
    {
#ifdef HAVE_TCGETATTR
      struct termios term;

      if (tcgetattr(fileno(ttyfp), &termsave))
        log_fatal ("tcgetattr() failed: %s\n", strerror(errno));
      restore_termios = 1;
      term = termsave;
      term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
      if (tcsetattr( fileno(ttyfp), TCSAFLUSH, &term ) )
        log_fatal("tcsetattr() failed: %s\n", strerror(errno));
#endif /*HAVE_TCGETATTR*/
    }

  /* fixme: How can we avoid that the \n is echoed w/o disabling
   * canonical mode - w/o this kill_prompt can't work */
  while (read(fileno(ttyfp), cbuf, 1) == 1 && *cbuf != '\n')
    {
      if (!hidden)
        last_prompt_len++;
      c = *cbuf;
      if (c == CONTROL_D)
        log_info (_("Control-D detected\n"));

      if (c == '\t') /* Map tab to a space.  */
        c = ' ';
      else if ( (c >= 0 && c <= 0x1f) || c == 0x7f)
        continue; /* Skip all other ASCII control characters.  */
      if (!(i < n-1))
        {
          n += 50;
          buf = xrealloc (buf, n);
        }
      buf[i++] = c;
    }

  if (*cbuf != '\n')
    {
      buf[0] = CONTROL_D;
      i = 1;
    }

  if (hidden)
    {
#ifdef HAVE_TCGETATTR
      if (tcsetattr (fileno(ttyfp), TCSAFLUSH, &termsave))
        log_error ("tcsetattr() failed: %s\n", strerror(errno));
      restore_termios = 0;
#endif /*HAVE_TCGETATTR*/
    }
#endif /* Unix */

  buf[i] = 0;
  return buf;
}


char *
tty_get( const char *prompt )
{
  if (!batchmode && !no_terminal && my_rl_readline && my_rl_add_history)
    {
      char *line;
      char *buf;

      if (!initialized)
	init_ttyfp();

      last_prompt_len = 0;

      line = my_rl_readline (prompt?prompt:"");

      /* We need to copy it to memory controlled by our malloc
         implementations; further we need to convert an EOF to our
         convention. */
      buf = xmalloc(line? strlen(line)+1:2);
      if (line)
        {
          strcpy (buf, line);
          trim_spaces (buf);
          if (strlen (buf) > 2 )
            my_rl_add_history (line); /* Note that we test BUF but add LINE. */
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
    return do_get ( prompt, 0 );
}


/* Variable argument version of tty_get.  The prompt is actually a
 * format string with arguments.  */
char *
tty_getf (const char *promptfmt, ... )
{
  va_list arg_ptr;
  char *prompt;
  char *answer;

  va_start (arg_ptr, promptfmt);
  if (gpgrt_vasprintf (&prompt, promptfmt, arg_ptr) < 0)
    log_fatal ("estream_vasprintf failed: %s\n", strerror (errno));
  va_end (arg_ptr);
  answer = tty_get (prompt);
  xfree (prompt);
  return answer;
}


char *
tty_get_hidden( const char *prompt )
{
  return do_get (prompt, 1);
}


void
tty_kill_prompt (void)
{
  if (no_terminal)
    return;

  if (!initialized)
    init_ttyfp ();

  if (batchmode)
    last_prompt_len = 0;
  if (!last_prompt_len)
    return;
#ifdef HAVE_W32_SYSTEM
  tty_printf ("\r%*s\r", last_prompt_len, "");
#else /* Unix */
  {
    int i;
    putc ('\r', ttyfp);
    for (i=0; i < last_prompt_len; i ++ )
      putc (' ', ttyfp);
    putc ('\r', ttyfp);
    fflush (ttyfp);
  }
#endif /* Unix */
  last_prompt_len = 0;
}


int
tty_get_answer_is_yes( const char *prompt )
{
  int yes;
  char *p;

  p = tty_get (prompt);
  tty_kill_prompt ();
  yes = answer_is_yes (p);
  xfree (p);

  return yes;
}


/* Called by gnupg_rl_initialize to setup the readline support. */
void
tty_private_set_rl_hooks (void (*init_stream) (FILE *),
                          void (*set_completer) (rl_completion_func_t*),
                          void (*inhibit_completion) (int),
                          void (*cleanup_after_signal) (void),
                          char *(*readline_fun) (const char*),
                          void (*add_history_fun) (const char*))
{
  my_rl_init_stream = init_stream;
  my_rl_set_completer = set_completer;
  my_rl_inhibit_completion = inhibit_completion;
  my_rl_cleanup_after_signal = cleanup_after_signal;
  my_rl_readline = readline_fun;
  my_rl_add_history = add_history_fun;
}


#ifdef HAVE_LIBREADLINE
void
tty_enable_completion (rl_completion_func_t *completer)
{
  if (no_terminal || !my_rl_set_completer )
    return;

  if (!initialized)
    init_ttyfp();

  my_rl_set_completer (completer);
}

void
tty_disable_completion (void)
{
  if (no_terminal || !my_rl_inhibit_completion)
    return;

  if (!initialized)
    init_ttyfp();

  my_rl_inhibit_completion (1);
}
#endif /* HAVE_LIBREADLINE */

void
tty_cleanup_after_signal (void)
{
#ifdef HAVE_TCGETATTR
  cleanup ();
#endif
}

void
tty_cleanup_rl_after_signal (void)
{
  if (my_rl_cleanup_after_signal)
    my_rl_cleanup_after_signal ();
}
