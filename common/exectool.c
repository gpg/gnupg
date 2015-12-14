/* exectool.c - Utility functions to execute a helper tool
 * Copyright (C) 2015 Werner Koch
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <gpg-error.h>

#include <assuan.h>
#include "i18n.h"
#include "logging.h"
#include "membuf.h"
#include "mischelp.h"
#include "exechelp.h"
#include "sysutils.h"
#include "util.h"

typedef struct
{
  const char *pgmname;
  int cont;
  int used;
  char buffer[256];
} read_and_log_buffer_t;


static inline gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}


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
              err = my_error_from_syserror ();
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



/* A buffer to copy from one stream to another.  */
struct copy_buffer
{
  char buffer[4096];
  char *writep;
  size_t nread;
};


/* Initialize a copy buffer.  */
static void
copy_buffer_init (struct copy_buffer *c)
{
  c->writep = c->buffer;
  c->nread = 0;
}


/* Securely wipe a copy buffer.  */
static void
copy_buffer_shred (struct copy_buffer *c)
{
  wipememory (c->buffer, sizeof c->buffer);
  c->writep = NULL;
  c->nread = ~0U;
}


/* Copy data from SOURCE to SINK using copy buffer C.  */
static gpg_error_t
copy_buffer_do_copy (struct copy_buffer *c, estream_t source, estream_t sink)
{
  gpg_error_t err;
  size_t nwritten;

  if (c->nread == 0)
    {
      c->writep = c->buffer;
      err = es_read (source, c->buffer, sizeof c->buffer, &c->nread);
      if (err)
        {
          if (errno == EAGAIN)
            return 0;	/* We will just retry next time.  */

          return my_error_from_syserror ();
        }

      assert (c->nread <= sizeof c->buffer);
    }

  if (c->nread == 0)
    return 0;	/* Done copying.  */

  err = es_write (sink, c->writep, c->nread, &nwritten);
  if (err)
    {
      if (errno == EAGAIN)
        return 0;	/* We will just retry next time.  */

      return my_error_from_syserror ();
    }

  assert (nwritten <= c->nread);
  c->writep += nwritten;
  c->nread -= nwritten;
  assert (c->writep - c->buffer <= sizeof c->buffer);

  if (es_fflush (sink) && errno != EAGAIN)
    err = my_error_from_syserror ();

  return err;
}


/* Flush the remaining data to SINK.  */
static gpg_error_t
copy_buffer_flush (struct copy_buffer *c, estream_t sink)
{
  gpg_error_t err;

  while (c->nread > 0)
    {
      err = copy_buffer_do_copy (c, NULL, sink);
      if (err)
        return err;
    }

  return 0;
}



/* Run the program PGMNAME with the command line arguments given in
   the NULL terminates array ARGV.  If INPUT is not NULL it will be
   fed to stdin of the process.  stderr is logged using log_info and
   the process' stdout is written to OUTPUT.  On error a diagnostic is
   printed, and an error code returned.  */
gpg_error_t
gnupg_exec_tool_stream (const char *pgmname, const char *argv[],
                        estream_t input,
                        estream_t output)
{
  gpg_error_t err;
  pid_t pid;
  estream_t infp = NULL;
  estream_t outfp, errfp;
  es_poll_t fds[3];
  int count;
  read_and_log_buffer_t fderrstate;
  struct copy_buffer cpbuf[2];

  memset (fds, 0, sizeof fds);
  memset (&fderrstate, 0, sizeof fderrstate);
  copy_buffer_init (&cpbuf[0]);
  copy_buffer_init (&cpbuf[1]);

  err = gnupg_spawn_process (pgmname, argv, GPG_ERR_SOURCE_DEFAULT,
                             NULL, GNUPG_SPAWN_NONBLOCK,
                             input? &infp : NULL,
                             &outfp, &errfp, &pid);
  if (err)
    {
      log_error ("error running '%s': %s\n", pgmname, gpg_strerror (err));
      return err;
    }

  fderrstate.pgmname = pgmname;

  fds[0].stream = infp;
  fds[0].want_write = 1;
  if (!input)
    fds[0].ignore = 1;
  fds[1].stream = outfp;
  fds[1].want_read = 1;
  fds[2].stream = errfp;
  fds[2].want_read = 1;
  /* Now read as long as we have something to poll.  We continue
     reading even after EOF or error on stdout so that we get the
     other error messages or remaining outut.  */
  while (!fds[1].ignore && !fds[2].ignore)
    {
      count = es_poll (fds, DIM(fds), -1);
      if (count == -1)
        {
          err = my_error_from_syserror ();
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
          err = copy_buffer_do_copy (&cpbuf[0], input, fds[0].stream);
          if (err)
            {
              log_error ("error feeding data to '%s': %s\n",
                         pgmname, gpg_strerror (err));
              goto leave;
            }

          if (es_feof (input))
            {
              err = copy_buffer_flush (&cpbuf[0], fds[0].stream);
              if (err)
                {
                  log_error ("error feeding data to '%s': %s\n",
                             pgmname, gpg_strerror (err));
                  goto leave;
                }

              fds[0].ignore = 1; /* ready.  */
              es_fclose (infp); infp = NULL;
            }
        }

      if (fds[1].got_read)
        {
          err = copy_buffer_do_copy (&cpbuf[1], fds[1].stream, output);
          if (err)
            {
              log_error ("error reading data from '%s': %s\n",
                         pgmname, gpg_strerror (err));
              goto leave;
            }
        }

      if (fds[2].got_read)
        read_and_log_stderr (&fderrstate, fds + 2);
    }

  err = copy_buffer_flush (&cpbuf[1], output);
  if (err)
    {
      log_error ("error reading data from '%s': %s\n",
                 pgmname, gpg_strerror (err));
      goto leave;
    }

  read_and_log_stderr (&fderrstate, NULL); /* Flush.  */
  es_fclose (infp); infp = NULL;
  es_fclose (outfp); outfp = NULL;
  es_fclose (errfp); errfp = NULL;

  err = gnupg_wait_process (pgmname, pid, 1, NULL);
  pid = (pid_t)(-1);

 leave:
  if (err)
    gnupg_kill_process (pid);

  es_fclose (infp);
  es_fclose (outfp);
  es_fclose (errfp);
  if (pid != (pid_t)(-1))
    gnupg_wait_process (pgmname, pid, 1, NULL);
  gnupg_release_process (pid);

  copy_buffer_shred (&cpbuf[0]);
  copy_buffer_shred (&cpbuf[1]);
  return err;
}


/* A dummy free function to pass to 'es_mopen'.  */
static void
nop_free (void *ptr)
{
  (void) ptr;
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
gnupg_exec_tool (const char *pgmname, const char *argv[],
                 const char *input_string,
                 char **result, size_t *resultlen)
{
  gpg_error_t err;
  estream_t input = NULL;
  estream_t output;
  size_t len;
  size_t nread;

  *result = NULL;
  if (resultlen)
    *resultlen = 0;

  if (input_string)
    {
      len = strlen (input_string);
      input = es_mopen ((char *) input_string, len, len,
                        0 /* don't grow */, NULL, nop_free, "rb");
      if (! input)
        return my_error_from_syserror ();
    }

  output = es_fopenmem (0, "wb");
  if (! output)
    {
      err = my_error_from_syserror ();
      goto leave;
    }

  err = gnupg_exec_tool_stream (pgmname, argv, input, output);
  if (err)
    goto leave;

  len = es_ftello (output);
  err = es_fseek (output, 0, SEEK_SET);
  if (err)
    goto leave;

  *result = xtrymalloc (len);
  if (*result == NULL)
    {
      err = my_error_from_syserror ();
      goto leave;
    }

  err = es_read (output, *result, len, &nread);
  if (! err)
    {
      assert (nread == len || !"short read on memstream");
      if (resultlen)
        *resultlen = len;
    }

 leave:
  if (input)
    es_fclose (input);
  es_fclose (output);
  return err;
}
