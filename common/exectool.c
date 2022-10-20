/* exectool.c - Utility functions to execute a helper tool
 * Copyright (C) 2015 Werner Koch
 * Copyright (C) 2016 g10 Code GmbH
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
#include "exectool.h"

typedef struct
{
  const char *pgmname;
  exec_tool_status_cb_t status_cb;
  void *status_cb_value;
  int cont;
  int quiet;
  size_t used;
  size_t buffer_size;
  char *buffer;
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
          len = strlen (pname);

          if (state->status_cb
              && !strncmp (state->buffer, "[GNUPG:] ", 9)
              && state->buffer[9] >= 'A' && state->buffer[9] <= 'Z')
            {
              char *rest;

              rest = strchr (state->buffer + 9, ' ');
              if (!rest)
                {
                  /* Set REST to an empty string.  */
                  rest = state->buffer + strlen (state->buffer);
                }
              else
                {
                  *rest++ = 0;
                  trim_spaces (rest);
                }
              state->status_cb (state->status_cb_value,
                                state->buffer + 9, rest);
            }
          else if (state->quiet)
            ;
          else if (!state->cont
              && !strncmp (state->buffer, pname, len)
              && strlen (state->buffer) > strlen (pname)
              && state->buffer[len] == ':' )
            {
              /* PGMNAME plus colon is identical to the start of
                 the output: print only the output.  */
              log_info ("%s\n", state->buffer);
            }
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
          if (state->used >= state->buffer_size - 1)
            {
              if (state->status_cb)
                {
                  /* A status callback requires that we have a full
                   * line.  Thus we need to enlarget the buffer in
                   * this case.  */
                  char *newbuffer;
                  size_t newsize = state->buffer_size + 256;

                  newbuffer = xtrymalloc (newsize);
                  if (!newbuffer)
                    {
                      log_error ("error allocating memory for status cb: %s\n",
                                 gpg_strerror (my_error_from_syserror ()));
                      /* We better disable the status CB in this case.  */
                      state->status_cb = NULL;
                      read_and_log_stderr (state, NULL);
                      state->cont = 1;
                    }
                  else
                    {
                      memcpy (newbuffer, state->buffer, state->used);
                      xfree (state->buffer);
                      state->buffer = newbuffer;
                      state->buffer_size = newsize;
                    }
                }
              else
                {
                  read_and_log_stderr (state, NULL);
                  state->cont = 1;
                }
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
  if (c == NULL)
    return;
  wipememory (c->buffer, sizeof c->buffer);
  c->writep = NULL;
  c->nread = ~0U;
}


/* Copy data from SOURCE to SINK using copy buffer C.  */
static gpg_error_t
copy_buffer_do_copy (struct copy_buffer *c, estream_t source, estream_t sink)
{
  gpg_error_t err;
  size_t nwritten = 0;

  if (c->nread == 0)
    {
      c->writep = c->buffer;
      if (es_read (source, c->buffer, sizeof c->buffer, &c->nread))
        {
          err = my_error_from_syserror ();
          if (gpg_err_code (err) == GPG_ERR_EAGAIN)
            return 0;	/* We will just retry next time.  */

          return err;
        }

      log_assert (c->nread <= sizeof c->buffer);
    }

  if (c->nread == 0)
    return 0;	/* Done copying.  */

  nwritten = 0;
  if (sink && es_write (sink, c->writep, c->nread, &nwritten))
    err = my_error_from_syserror ();
  else
    err = 0;

  log_assert (nwritten <= c->nread);
  c->writep += nwritten;
  c->nread -= nwritten;
  log_assert (c->writep - c->buffer <= sizeof c->buffer);

  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_EAGAIN)
        return 0;	/* We will just retry next time.  */

      return err;
    }

  if (sink && es_fflush (sink) && errno != EAGAIN)
    err = my_error_from_syserror ();

  return err;
}


/* Flush the remaining data to SINK.  */
static gpg_error_t
copy_buffer_flush (struct copy_buffer *c, estream_t sink)
{
  gpg_error_t err = 0;
  size_t nwritten = 0;

  if (es_write (sink, c->writep, c->nread, &nwritten))
    err = my_error_from_syserror ();

  log_assert (nwritten <= c->nread);
  c->writep += nwritten;
  c->nread -= nwritten;
  log_assert (c->writep - c->buffer <= sizeof c->buffer);

  if (err)
    return err;

  if (es_fflush (sink))
    err = my_error_from_syserror ();

  return err;
}



/* Run the program PGMNAME with the command line arguments given in
 * the NULL terminates array ARGV.  If INPUT is not NULL it will be
 * fed to stdin of the process.  stderr is logged using log_info and
 * the process's stdout is written to OUTPUT.  If OUTPUT is NULL the
 * output is discarded.  If INEXTRA is given, an additional input
 * stream will be passed to the child; to tell the child about this
 * ARGV is scanned and the first occurrence of an argument
 * "-&@INEXTRA@" is replaced by the concatenation of "-&" and the
 * child's file descriptor of the pipe created for the INEXTRA stream.
 *
 * On error a diagnostic is printed and an error code returned.  */
gpg_error_t
gnupg_exec_tool_stream (const char *pgmname, const char *argv[],
                        estream_t input, estream_t inextra,
                        estream_t output,
                        exec_tool_status_cb_t status_cb,
                        void *status_cb_value)
{
  gpg_error_t err;
  pid_t pid = (pid_t) -1;
  estream_t infp = NULL;
  estream_t extrafp = NULL;
  estream_t outfp = NULL, errfp = NULL;
  es_poll_t fds[4];
  int exceptclose[2];
  int extrapipe[2] = {-1, -1};
  char extrafdbuf[20];
  const char *argsave = NULL;
  int argsaveidx;
  int count;
  read_and_log_buffer_t fderrstate;
  struct copy_buffer *cpbuf_in = NULL, *cpbuf_out = NULL, *cpbuf_extra = NULL;
  int quiet = 0;
  int dummy_exitcode;

  memset (fds, 0, sizeof fds);
  memset (&fderrstate, 0, sizeof fderrstate);

  /* If the first argument to the program is "--quiet" avoid all extra
   * diagnostics.  */
  quiet = (argv && argv[0] && !strcmp (argv[0], "--quiet"));

  cpbuf_in = xtrymalloc (sizeof *cpbuf_in);
  if (cpbuf_in == NULL)
    {
      err = my_error_from_syserror ();
      goto leave;
    }
  copy_buffer_init (cpbuf_in);

  cpbuf_out = xtrymalloc (sizeof *cpbuf_out);
  if (cpbuf_out == NULL)
    {
      err = my_error_from_syserror ();
      goto leave;
    }
  copy_buffer_init (cpbuf_out);

  cpbuf_extra = xtrymalloc (sizeof *cpbuf_extra);
  if (cpbuf_extra == NULL)
    {
      err = my_error_from_syserror ();
      goto leave;
    }
  copy_buffer_init (cpbuf_extra);

  fderrstate.pgmname = pgmname;
  fderrstate.quiet = quiet;
  fderrstate.status_cb = status_cb;
  fderrstate.status_cb_value = status_cb_value;
  fderrstate.buffer_size = 256;
  fderrstate.buffer = xtrymalloc (fderrstate.buffer_size);
  if (!fderrstate.buffer)
    {
      err = my_error_from_syserror ();
      goto leave;
    }

  if (inextra)
    {
      err = gnupg_create_outbound_pipe (extrapipe, &extrafp, 1);
      if (err)
        {
          log_error ("error creating outbound pipe for extra fp: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      exceptclose[0] = extrapipe[0]; /* Do not close in child. */
      exceptclose[1] = -1;
      /* Now find the argument marker and replace by the pipe's fd.
         Yeah, that is an ugly non-thread safe hack but it safes us to
         create a copy of the array.  */
#ifdef HAVE_W32_SYSTEM
      snprintf (extrafdbuf, sizeof extrafdbuf, "-&%lu",
                (unsigned long)_get_osfhandle (extrapipe[0]));
#else
      snprintf (extrafdbuf, sizeof extrafdbuf, "-&%d", extrapipe[0]);
#endif
      for (argsaveidx=0; argv[argsaveidx]; argsaveidx++)
        if (!strcmp (argv[argsaveidx], "-&@INEXTRA@"))
          {
            argsave = argv[argsaveidx];
            argv[argsaveidx] = extrafdbuf;
            break;
          }
    }
  else
    exceptclose[0] = -1;

  err = gnupg_spawn_process (pgmname, argv,
                             exceptclose, GNUPG_SPAWN_NONBLOCK,
                             input? &infp : NULL,
                             &outfp, &errfp, &pid);
  if (extrapipe[0] != -1)
    close (extrapipe[0]);
  if (argsave)
    argv[argsaveidx] = argsave;
  if (err)
    {
      if (!quiet)
        log_error ("error running '%s': %s\n", pgmname, gpg_strerror (err));
      goto leave;
    }

  fds[0].stream = infp;
  fds[0].want_write = 1;
  if (!input)
    fds[0].ignore = 1;
  fds[1].stream = outfp;
  fds[1].want_read = 1;
  fds[2].stream = errfp;
  fds[2].want_read = 1;
  fds[3].stream = extrafp;
  fds[3].want_write = 1;
  if (!inextra)
    fds[3].ignore = 1;

  /* Now read as long as we have something to poll.  We continue
     reading even after EOF or error on stdout so that we get the
     other error messages or remaining output.  */
  while (! (fds[1].ignore && fds[2].ignore))
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
          err = copy_buffer_do_copy (cpbuf_in, input, fds[0].stream);
          if (err)
            {
              log_error ("error feeding data to '%s': %s\n",
                         pgmname, gpg_strerror (err));
              goto leave;
            }

          if (es_feof (input))
            {
              err = copy_buffer_flush (cpbuf_in, fds[0].stream);
              if (gpg_err_code (err) == GPG_ERR_EAGAIN)
                continue;	/* Retry next time.  */
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

      if (fds[3].got_write)
        {
          log_assert (inextra);
          err = copy_buffer_do_copy (cpbuf_extra, inextra, fds[3].stream);
          if (err)
            {
              log_error ("error feeding data to '%s': %s\n",
                         pgmname, gpg_strerror (err));
              goto leave;
            }

          if (es_feof (inextra))
            {
              err = copy_buffer_flush (cpbuf_extra, fds[3].stream);
              if (gpg_err_code (err) == GPG_ERR_EAGAIN)
                continue;	/* Retry next time.  */
              if (err)
                {
                  log_error ("error feeding data to '%s': %s\n",
                             pgmname, gpg_strerror (err));
                  goto leave;
                }

              fds[3].ignore = 1; /* ready.  */
              es_fclose (extrafp); extrafp = NULL;
            }
        }

      if (fds[1].got_read)
        {
          err = copy_buffer_do_copy (cpbuf_out, fds[1].stream, output);
          if (err)
            {
              log_error ("error reading data from '%s': %s\n",
                         pgmname, gpg_strerror (err));
              goto leave;
            }

          if (es_feof (fds[1].stream))
            {
              err = copy_buffer_flush (cpbuf_out, output);
              if (err)
                {
                  log_error ("error reading data from '%s': %s\n",
                             pgmname, gpg_strerror (err));
                  goto leave;
                }

              fds[1].ignore = 1; /* ready.  */
            }
        }

      if (fds[2].got_read)
        read_and_log_stderr (&fderrstate, fds + 2);
    }

  read_and_log_stderr (&fderrstate, NULL); /* Flush.  */
  es_fclose (infp); infp = NULL;
  es_fclose (extrafp); extrafp = NULL;
  es_fclose (outfp); outfp = NULL;
  es_fclose (errfp); errfp = NULL;

  err = gnupg_wait_process (pgmname, pid, 1, quiet? &dummy_exitcode : NULL);
  pid = (pid_t)(-1);

 leave:
  if (err && pid != (pid_t) -1)
    gnupg_kill_process (pid);

  es_fclose (infp);
  es_fclose (extrafp);
  es_fclose (outfp);
  es_fclose (errfp);
  if (pid != (pid_t)(-1))
    gnupg_wait_process (pgmname, pid, 1,  quiet? &dummy_exitcode : NULL);
  gnupg_release_process (pid);

  copy_buffer_shred (cpbuf_in);
  xfree (cpbuf_in);
  copy_buffer_shred (cpbuf_out);
  xfree (cpbuf_out);
  copy_buffer_shred (cpbuf_extra);
  xfree (cpbuf_extra);
  xfree (fderrstate.buffer);
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
   log_info and the process's stdout is returned in a newly malloced
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

  err = gnupg_exec_tool_stream (pgmname, argv, input, NULL, output, NULL, NULL);
  if (err)
    goto leave;

  len = es_ftello (output);
  err = es_fseek (output, 0, SEEK_SET);
  if (err)
    goto leave;

  *result = xtrymalloc (len + 1);
  if (!*result)
    {
      err = my_error_from_syserror ();
      goto leave;
    }

  if (len)
    {
      if (es_read (output, *result, len, &nread))
        {
          err = my_error_from_syserror ();
          goto leave;
        }
      if (nread != len)
        log_fatal ("%s: short read from memstream\n", __func__);
    }
  (*result)[len] = 0;

  if (resultlen)
    *resultlen = len;

 leave:
  es_fclose (input);
  es_fclose (output);
  if (err)
    {
      xfree (*result);
      *result = NULL;
    }
  return err;
}
