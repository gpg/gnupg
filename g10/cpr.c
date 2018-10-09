/* status.c - Status message and command-fd interface
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2004, 2005, 2006, 2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#include "gpg.h"
#include "../common/util.h"
#include "../common/status.h"
#include "../common/ttyio.h"
#include "options.h"
#include "main.h"
#include "../common/i18n.h"

#define CONTROL_D ('D' - 'A' + 1)


/* The stream to output the status information.  Output is disabled if
   this is NULL.  */
static estream_t statusfp;


static void
progress_cb (void *ctx, const char *what, int printchar,
             int current, int total)
{
  char buf[50];

  (void)ctx;

  if ( printchar == '\n' && !strcmp (what, "primegen") )
    snprintf (buf, sizeof buf, "%.20s X 100 100", what );
  else
    snprintf (buf, sizeof buf, "%.20s %c %d %d",
              what, printchar=='\n'?'X':printchar, current, total );
  write_status_text (STATUS_PROGRESS, buf);
}


/* Return true if the status message NO may currently be issued.  We
   need this to avoid syncronisation problem while auto retrieving a
   key.  There it may happen that a status NODATA is issued for a non
   available key and the user may falsely interpret this has a missing
   signature. */
static int
status_currently_allowed (int no)
{
  if (!glo_ctrl.in_auto_key_retrieve)
    return 1; /* Yes. */

  /* We allow some statis anyway, so that import statistics are
     correct and to avoid problems if the retrieval subsystem will
     prompt the user. */
  switch (no)
    {
    case STATUS_GET_BOOL:
    case STATUS_GET_LINE:
    case STATUS_GET_HIDDEN:
    case STATUS_GOT_IT:
    case STATUS_IMPORTED:
    case STATUS_IMPORT_OK:
    case STATUS_IMPORT_CHECK:
    case STATUS_IMPORT_RES:
      return 1; /* Yes. */
    default:
      break;
    }
  return 0; /* No. */
}


void
set_status_fd (int fd)
{
  static int last_fd = -1;

  if (fd != -1 && last_fd == fd)
    return;

  if (statusfp && statusfp != es_stdout && statusfp != es_stderr )
    es_fclose (statusfp);
  statusfp = NULL;
  if (fd == -1)
    return;

  if (! gnupg_fd_valid (fd))
    log_fatal ("status-fd is invalid: %s\n", strerror (errno));

  if (fd == 1)
    statusfp = es_stdout;
  else if (fd == 2)
    statusfp = es_stderr;
  else
    statusfp = es_fdopen (fd, "w");
  if (!statusfp)
    {
      log_fatal ("can't open fd %d for status output: %s\n",
                 fd, strerror (errno));
    }
  last_fd = fd;

  gcry_set_progress_handler (progress_cb, NULL);
}


int
is_status_enabled ()
{
  return !!statusfp;
}


void
write_status ( int no )
{
    write_status_text( no, NULL );
}


/* Write a status line with code NO followed by the string TEXT and
   directly followed by the remaining strings up to a NULL. */
void
write_status_strings (int no, const char *text, ...)
{
  va_list arg_ptr;
  const char *s;

  if (!statusfp || !status_currently_allowed (no) )
    return;  /* Not enabled or allowed. */

  es_fputs ("[GNUPG:] ", statusfp);
  es_fputs (get_status_string (no), statusfp);
  if ( text )
    {
      es_putc ( ' ', statusfp);
      va_start (arg_ptr, text);
      s = text;
      do
        {
          for (; *s; s++)
            {
              if (*s == '\n')
                es_fputs ("\\n", statusfp);
              else if (*s == '\r')
                es_fputs ("\\r", statusfp);
              else
                es_fputc (*(const byte *)s, statusfp);
            }
        }
      while ((s = va_arg (arg_ptr, const char*)));
      va_end (arg_ptr);
    }
  es_putc ('\n', statusfp);
  if (es_fflush (statusfp) && opt.exit_on_status_write_error)
    g10_exit (0);
}


void
write_status_text (int no, const char *text)
{
  write_status_strings (no, text, NULL);
}


/* Write a status line with code NO followed by the output of the
 * printf style FORMAT.  The caller needs to make sure that LFs and
 * CRs are not printed.  */
void
write_status_printf (int no, const char *format, ...)
{
  va_list arg_ptr;

  if (!statusfp || !status_currently_allowed (no) )
    return;  /* Not enabled or allowed. */

  es_fputs ("[GNUPG:] ", statusfp);
  es_fputs (get_status_string (no), statusfp);
  if (format)
    {
      es_putc ( ' ', statusfp);
      va_start (arg_ptr, format);
      es_vfprintf (statusfp, format, arg_ptr);
      va_end (arg_ptr);
    }
  es_putc ('\n', statusfp);
  if (es_fflush (statusfp) && opt.exit_on_status_write_error)
    g10_exit (0);
}


/* Write an ERROR status line using a full gpg-error error value.  */
void
write_status_error (const char *where, gpg_error_t err)
{
  if (!statusfp || !status_currently_allowed (STATUS_ERROR))
    return;  /* Not enabled or allowed. */

  es_fprintf (statusfp, "[GNUPG:] %s %s %u\n",
              get_status_string (STATUS_ERROR), where, err);
  if (es_fflush (statusfp) && opt.exit_on_status_write_error)
    g10_exit (0);
}


/* Same as above but outputs the error code only.  */
void
write_status_errcode (const char *where, int errcode)
{
  if (!statusfp || !status_currently_allowed (STATUS_ERROR))
    return;  /* Not enabled or allowed. */

  es_fprintf (statusfp, "[GNUPG:] %s %s %u\n",
              get_status_string (STATUS_ERROR), where, gpg_err_code (errcode));
  if (es_fflush (statusfp) && opt.exit_on_status_write_error)
    g10_exit (0);
}


/* Write a FAILURE status line.  */
void
write_status_failure (const char *where, gpg_error_t err)
{
  static int any_failure_printed;

  if (!statusfp || !status_currently_allowed (STATUS_FAILURE))
    return;  /* Not enabled or allowed. */
  if (any_failure_printed)
    return;
  any_failure_printed = 1;
  es_fprintf (statusfp, "[GNUPG:] %s %s %u\n",
              get_status_string (STATUS_FAILURE), where, err);
  if (es_fflush (statusfp) && opt.exit_on_status_write_error)
    g10_exit (0);
}


/*
 * Write a status line with a buffer using %XX escapes.  If WRAP is >
 * 0 wrap the line after this length.  If STRING is not NULL it will
 * be prepended to the buffer, no escaping is done for string.
 * A wrap of -1 forces spaces not to be encoded as %20.
 */
void
write_status_text_and_buffer (int no, const char *string,
                              const char *buffer, size_t len, int wrap)
{
  const char *s, *text;
  int esc, first;
  int lower_limit = ' ';
  size_t n, count, dowrap;

  if (!statusfp || !status_currently_allowed (no))
    return;  /* Not enabled or allowed. */

  if (wrap == -1)
    {
      lower_limit--;
      wrap = 0;
    }

  text = get_status_string (no);
  count = dowrap = first = 1;
  do
    {
      if (dowrap)
        {
          es_fprintf (statusfp, "[GNUPG:] %s ", text);
          count = dowrap = 0;
          if (first && string)
            {
              es_fputs (string, statusfp);
              count += strlen (string);
              /* Make sure that there is a space after the string.  */
              if (*string && string[strlen (string)-1] != ' ')
                {
                  es_putc (' ', statusfp);
                  count++;
                }
            }
          first = 0;
        }
      for (esc=0, s=buffer, n=len; n && !esc; s++, n--)
        {
          if (*s == '%' || *(const byte*)s <= lower_limit
              || *(const byte*)s == 127 )
            esc = 1;
          if (wrap && ++count > wrap)
            {
              dowrap=1;
              break;
            }
        }
      if (esc)
        {
          s--; n++;
        }
      if (s != buffer)
        es_fwrite (buffer, s-buffer, 1, statusfp);
      if ( esc )
        {
          es_fprintf (statusfp, "%%%02X", *(const byte*)s );
          s++; n--;
        }
      buffer = s;
      len = n;
      if (dowrap && len)
        es_putc ('\n', statusfp);
    }
  while (len);

  es_putc ('\n',statusfp);
  if (es_fflush (statusfp) && opt.exit_on_status_write_error)
    g10_exit (0);
}


void
write_status_buffer (int no, const char *buffer, size_t len, int wrap)
{
  write_status_text_and_buffer (no, NULL, buffer, len, wrap);
}


/* Print the BEGIN_SIGNING status message.  If MD is not NULL it is
   used to retrieve the hash algorithms used for the message. */
void
write_status_begin_signing (gcry_md_hd_t md)
{
  if (md)
    {
      char buf[100];
      size_t buflen;
      int i, ga;

      buflen = 0;
      for (i=1; i <= 110; i++)
        {
          ga = map_md_openpgp_to_gcry (i);
          if (ga && gcry_md_is_enabled (md, ga) && buflen+10 < DIM(buf))
            {
              snprintf (buf+buflen, DIM(buf) - buflen,
                        "%sH%d", buflen? " ":"",i);
              buflen += strlen (buf+buflen);
            }
        }
      write_status_text (STATUS_BEGIN_SIGNING, buf);
    }
  else
    write_status ( STATUS_BEGIN_SIGNING );
}


static int
myread(int fd, void *buf, size_t count)
{
  int rc;
  do
    {
      rc = read( fd, buf, count );
    }
  while (rc == -1 && errno == EINTR);

  if (!rc && count)
    {
      static int eof_emmited=0;
      if ( eof_emmited < 3 )
        {
          *(char*)buf = CONTROL_D;
          rc = 1;
          eof_emmited++;
        }
      else /* Ctrl-D not caught - do something reasonable */
        {
#ifdef HAVE_DOSISH_SYSTEM
#ifndef HAVE_W32CE_SYSTEM
          raise (SIGINT); /* Nothing to hangup under DOS.  */
#endif
#else
          raise (SIGHUP); /* No more input data.  */
#endif
        }
    }
  return rc;
}



/* Request a string from the client over the command-fd.  If GETBOOL
   is set the function returns a static string (do not free) if the
   entered value was true or NULL if the entered value was false.  */
static char *
do_get_from_fd ( const char *keyword, int hidden, int getbool )
{
  int i, len;
  char *string;

  if (statusfp != es_stdout)
    es_fflush (es_stdout);

  write_status_text (getbool? STATUS_GET_BOOL :
                     hidden? STATUS_GET_HIDDEN : STATUS_GET_LINE, keyword);

  for (string = NULL, i = len = 200; ; i++ )
    {
      if (i >= len-1 )
        {
          /* On the first iteration allocate a new buffer.  If that
           * buffer is too short at further iterations do a poor man's
           * realloc.  */
          char *save = string;
          len += 100;
          string = hidden? xmalloc_secure ( len ) : xmalloc ( len );
          if (save)
            {
              memcpy (string, save, i);
              xfree (save);
            }
          else
            i = 0;
	}
      /* Fixme: why not use our read_line function here? */
      if ( myread( opt.command_fd, string+i, 1) != 1 || string[i] == '\n'  )
        break;
      else if ( string[i] == CONTROL_D )
        {
          /* Found ETX - Cancel the line and return a sole ETX.  */
          string[0] = CONTROL_D;
          i = 1;
          break;
        }
    }
  string[i] = 0;

  write_status (STATUS_GOT_IT);

  if (getbool)	 /* Fixme: is this correct??? */
    return (string[0] == 'Y' || string[0] == 'y') ? "" : NULL;

  return string;
}



int
cpr_enabled()
{
    if( opt.command_fd != -1 )
	return 1;
    return 0;
}

char *
cpr_get_no_help( const char *keyword, const char *prompt )
{
    char *p;

    if( opt.command_fd != -1 )
	return do_get_from_fd ( keyword, 0, 0 );
    for(;;) {
	p = tty_get( prompt );
        return p;
    }
}

char *
cpr_get( const char *keyword, const char *prompt )
{
    char *p;

    if( opt.command_fd != -1 )
	return do_get_from_fd ( keyword, 0, 0 );
    for(;;) {
	p = tty_get( prompt );
	if( *p=='?' && !p[1] && !(keyword && !*keyword)) {
	    xfree(p);
	    display_online_help( keyword );
	}
	else
	    return p;
    }
}


char *
cpr_get_utf8( const char *keyword, const char *prompt )
{
    char *p;
    p = cpr_get( keyword, prompt );
    if( p ) {
	char *utf8 = native_to_utf8( p );
	xfree( p );
	p = utf8;
    }
    return p;
}

char *
cpr_get_hidden( const char *keyword, const char *prompt )
{
    char *p;

    if( opt.command_fd != -1 )
	return do_get_from_fd ( keyword, 1, 0 );
    for(;;) {
	p = tty_get_hidden( prompt );
	if( *p == '?' && !p[1] ) {
	    xfree(p);
	    display_online_help( keyword );
	}
	else
	    return p;
    }
}

void
cpr_kill_prompt(void)
{
    if( opt.command_fd != -1 )
	return;
    tty_kill_prompt();
    return;
}

int
cpr_get_answer_is_yes_def (const char *keyword, const char *prompt, int def_yes)
{
    int yes;
    char *p;

    if( opt.command_fd != -1 )
	return !!do_get_from_fd ( keyword, 0, 1 );
    for(;;) {
	p = tty_get( prompt );
	trim_spaces(p); /* it is okay to do this here */
	if( *p == '?' && !p[1] ) {
	    xfree(p);
	    display_online_help( keyword );
	}
	else {
	    tty_kill_prompt();
	    yes = answer_is_yes_no_default (p, def_yes);
	    xfree(p);
	    return yes;
	}
    }
}

int
cpr_get_answer_is_yes (const char *keyword, const char *prompt)
{
  return cpr_get_answer_is_yes_def (keyword, prompt, 0);
}

int
cpr_get_answer_yes_no_quit( const char *keyword, const char *prompt )
{
    int yes;
    char *p;

    if( opt.command_fd != -1 )
	return !!do_get_from_fd ( keyword, 0, 1 );
    for(;;) {
	p = tty_get( prompt );
	trim_spaces(p); /* it is okay to do this here */
	if( *p == '?' && !p[1] ) {
	    xfree(p);
	    display_online_help( keyword );
	}
	else {
	    tty_kill_prompt();
	    yes = answer_is_yes_no_quit(p);
	    xfree(p);
	    return yes;
	}
    }
}


int
cpr_get_answer_okay_cancel (const char *keyword,
                            const char *prompt,
                            int def_answer)
{
  int yes;
  char *answer = NULL;
  char *p;

  if( opt.command_fd != -1 )
    answer = do_get_from_fd ( keyword, 0, 0 );

  if (answer)
    {
      yes = answer_is_okay_cancel (answer, def_answer);
      xfree (answer);
      return yes;
    }

  for(;;)
    {
      p = tty_get( prompt );
      trim_spaces(p); /* it is okay to do this here */
      if (*p == '?' && !p[1])
        {
          xfree(p);
          display_online_help (keyword);
	}
      else
        {
          tty_kill_prompt();
          yes = answer_is_okay_cancel (p, def_answer);
          xfree(p);
          return yes;
	}
    }
}
