/* sh-exectool.c - Utility functions to execute a helper tool
 * Copyright (C) 2015 Werner Koch
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
#include <errno.h>
#include <assert.h>

#include "g13-syshelp.h"
#include <assuan.h>
#include "i18n.h"
#include "membuf.h"
#include "exechelp.h"
#include "sysutils.h"

typedef struct
{
  const char *pgmname;
  int cont;
  int used;
  char buffer[256];
} read_and_log_buffer_t;


static void
read_and_log_stderr (read_and_log_buffer_t *state, es_poll_t *fderr)
{
  gpg_error_t err;
  int c;

  if (!fderr)
    {
      /* Flush internal buffer.  */
      if (state->used)
        {
          const char *pname;
          int len;

          state->buffer[state->used] = 0;
          state->used = 0;

          pname = strrchr (state->pgmname, '/');
          if (pname && pname != state->pgmname && pname[1])
            pname++;
          else
            pname = state->pgmname;
          /* If our pgmname plus colon is identical to the start of
             the output, print only the output.  */
          len = strlen (pname);
          if (!state->cont
              && !strncmp (state->buffer, pname, len)
              && strlen (state->buffer) > strlen (pname)
              && state->buffer[len] == ':' )
            log_info ("%s\n", state->buffer);
          else
            log_info ("%s%c %s\n",
                      pname, state->cont? '+':':', state->buffer);
        }
      state->cont = 0;
      return;
    }
  for (;;)
    {
      c = es_fgetc (fderr->stream);
      if (c == EOF)
        {
          if (es_feof (fderr->stream))
            {
              fderr->ignore = 1; /* Not anymore needed.  */
            }
          else if (es_ferror (fderr->stream))
            {
              err = gpg_error_from_syserror ();
              log_error ("error reading stderr of '%s': %s\n",
                         state->pgmname, gpg_strerror (err));
              fderr->ignore = 1; /* Disable.  */
            }

          break;
        }
      else if (c == '\n')
        {
          read_and_log_stderr (state, NULL);
        }
      else
        {
          if (state->used >= sizeof state->buffer - 1)
            {
              read_and_log_stderr (state, NULL);
              state->cont = 1;
            }
          state->buffer[state->used++] = c;
        }
    }
}


static gpg_error_t
read_stdout (membuf_t *mb, es_poll_t *fdout, const char *pgmname)
{
  gpg_error_t err = 0;
  int c;

  for (;;)
    {
      c = es_fgetc (fdout->stream);
      if (c == EOF)
        {
          if (es_feof (fdout->stream))
            {
              fdout->ignore = 1; /* Ready.  */
            }
          else if (es_ferror (fdout->stream))
            {
              err = gpg_error_from_syserror ();
              log_error ("error reading stdout of '%s': %s\n",
                         pgmname, gpg_strerror (err));
              fdout->ignore = 1; /* Disable.  */
            }

          break;
        }
      else
        {
          char buf[1];
          *buf = c;
          put_membuf (mb, buf, 1);
        }
    }

  return err;
}


/* Run the program PGMNAME with the command line arguments given in
   the NULL terminates array ARGV.  If INPUT_STRING is not NULL it
   will be fed to stdin of the process.  stderr is logged using
   log_info and the process' stdout is returned in a newly malloced
   buffer RESULT with the length stored at RESULTLEN if not given as
   NULL.  A hidden Nul is appended to the output.  On error NULL is
   stored at RESULT, a diagnostic is printed, and an error code
   returned.  */
gpg_error_t
sh_exec_tool (const char *pgmname, const char *argv[],
              const char *input_string,
              char **result, size_t *resultlen)
{
  gpg_error_t err;
  pid_t pid;
  estream_t infp = NULL;
  estream_t outfp, errfp;
  es_poll_t fds[3];
  int count;
  read_and_log_buffer_t fderrstate;
  membuf_t fdout_mb;
  size_t len, nwritten;

  *result = NULL;
  if (resultlen)
    *resultlen = 0;
  memset (fds, 0, sizeof fds);
  memset (&fderrstate, 0, sizeof fderrstate);
  init_membuf (&fdout_mb, 4096);

  err = gnupg_spawn_process (pgmname, argv, GPG_ERR_SOURCE_DEFAULT,
                             NULL, GNUPG_SPAWN_NONBLOCK,
                             input_string? &infp : NULL,
                             &outfp, &errfp, &pid);
  if (err)
    {
      log_error ("error running '%s': %s\n", pgmname, gpg_strerror (err));
      return err;
    }

  fderrstate.pgmname = pgmname;

  fds[0].stream = infp;
  fds[0].want_write = 1;
  if (!input_string)
    fds[0].ignore = 1;
  fds[1].stream = outfp;
  fds[1].want_read = 1;
  fds[2].stream = errfp;
  fds[2].want_read = 1;
  /* Now read as long as we have something to poll.  We continue
     reading even after EOF or error on stdout so that we get the
     other error messages or remaining outout.  */
  while (!fds[1].ignore && !fds[2].ignore)
    {
      count = es_poll (fds, DIM(fds), -1);
      if (count == -1)
        {
          err = gpg_error_from_syserror ();
          log_error ("error polling '%s': %s\n", pgmname, gpg_strerror (err));
          goto leave;
        }
      if (!count)
        {
          log_debug ("unexpected timeout while polling '%s'\n", pgmname);
          break;
        }

      if (fds[0].got_write)
        {
          len = strlen (input_string);
          log_debug ("writing '%s'\n", input_string);
          if (es_write (fds[0].stream, input_string, len, &nwritten))
	    {
              if (errno != EAGAIN)
                {
                  err = gpg_error_from_syserror ();
                  log_error ("error writing '%s': %s\n",
                             pgmname, gpg_strerror (err));
                  goto leave;
                }
              else
                log_debug ("  .. EAGAIN\n");
            }
          else
            {
              assert (nwritten <= len);
              input_string += nwritten;
	    }

          if (es_fflush (fds[0].stream) && errno != EAGAIN)
            {
              err = gpg_error_from_syserror ();
              log_error ("error writing '%s' (flush): %s\n",
                         pgmname, gpg_strerror (err));
              if (gpg_err_code (err) == GPG_ERR_EPIPE && !*input_string)
                {
                  /* fixme: How can we tell whether estream has
                     pending bytes after a HUP - which is an
                     error?  */
                }
              else
                goto leave;
            }
          if (!*input_string)
            {
              fds[0].ignore = 1; /* ready.  */
              es_fclose (infp); infp = NULL;
            }
        }

      if (fds[1].got_read)
        read_stdout (&fdout_mb, fds + 1, pgmname); /* FIXME: Add error
                                                      handling.  */
      if (fds[2].got_read)
        read_and_log_stderr (&fderrstate, fds + 2);

    }

  read_and_log_stderr (&fderrstate, NULL); /* Flush.  */
  es_fclose (infp); infp = NULL;
  es_fclose (outfp); outfp = NULL;
  es_fclose (errfp); errfp = NULL;

  err = gnupg_wait_process (pgmname, pid, 1, NULL);
  pid = (pid_t)(-1);

 leave:
  if (err)
    {
      gnupg_kill_process (pid);
      xfree (get_membuf (&fdout_mb, NULL));
    }
  else
    {
      put_membuf (&fdout_mb, "", 1); /* Make sure it is a string.  */
      *result = get_membuf (&fdout_mb, resultlen);
      if (!*result)
        err = gpg_error_from_syserror ();
    }

  es_fclose (infp);
  es_fclose (outfp);
  es_fclose (errfp);
  if (pid != (pid_t)(-1))
    gnupg_wait_process (pgmname, pid, 1, NULL);
  gnupg_release_process (pid);

  return err;
}
