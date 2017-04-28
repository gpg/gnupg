/* call-gpg.c - Communication with the GPG
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#include <assert.h>
#include <assuan.h>
#include <errno.h>
#include <npth.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "call-gpg.h"
#include "exechelp.h"
#include "i18n.h"
#include "logging.h"
#include "membuf.h"
#include "strlist.h"
#include "util.h"


static GPGRT_INLINE gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}

static GPGRT_INLINE gpg_error_t
my_error_from_errno (int e)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_errno (e));
}


/* Fire up a new GPG.  Handle the server's initial greeting.  Returns
   0 on success and stores the assuan context at R_CTX.  */
static gpg_error_t
start_gpg (ctrl_t ctrl, const char *gpg_program, strlist_t gpg_arguments,
           int input_fd, int output_fd, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx = NULL;
  const char *pgmname;
  const char **argv;
  assuan_fd_t no_close_list[5];
  int i;
  char line[ASSUAN_LINELENGTH];

  (void)ctrl;

  *r_ctx = NULL;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (err));
      return err;
    }

  /* The first time we are used, initialize the gpg_program variable.  */
  if ( !gpg_program || !*gpg_program )
    gpg_program = gnupg_module_name (GNUPG_MODULE_NAME_GPG);

  /* Compute argv[0].  */
  if ( !(pgmname = strrchr (gpg_program, '/')))
    pgmname = gpg_program;
  else
    pgmname++;

  if (fflush (NULL))
    {
      err = my_error_from_syserror ();
      log_error ("error flushing pending output: %s\n", gpg_strerror (err));
      return err;
    }

  argv = xtrycalloc (strlist_length (gpg_arguments) + 3, sizeof *argv);
  if (argv == NULL)
    {
      err = my_error_from_syserror ();
      return err;
    }
  i = 0;
  argv[i++] = pgmname;
  argv[i++] = "--server";
  for (; gpg_arguments; gpg_arguments = gpg_arguments->next)
    argv[i++] = gpg_arguments->d;
  argv[i++] = NULL;

  i = 0;
  if (log_get_fd () != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (log_get_fd ());
  no_close_list[i++] = assuan_fd_from_posix_fd (fileno (stderr));
  if (input_fd != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (input_fd);
  if (output_fd != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (output_fd);
  no_close_list[i] = ASSUAN_INVALID_FD;

  /* Connect to GPG and perform initial handshaking.  */
  err = assuan_pipe_connect (ctx, gpg_program, argv, no_close_list,
			     NULL, NULL, 0);
  if (err)
    {
      assuan_release (ctx);
      log_error ("can't connect to GPG: %s\n", gpg_strerror (err));
      return gpg_error (GPG_ERR_NO_ENGINE);
    }

  if (input_fd != -1)
    {
      snprintf (line, sizeof line, "INPUT FD=%d", input_fd);
      err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (err)
        {
          assuan_release (ctx);
          log_error ("error sending INPUT command: %s\n", gpg_strerror (err));
          return err;
        }
    }

  if (output_fd != -1)
    {
      snprintf (line, sizeof line, "OUTPUT FD=%d", output_fd);
      err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (err)
        {
          assuan_release (ctx);
          log_error ("error sending OUTPUT command: %s\n", gpg_strerror (err));
          return err;
        }
    }

  *r_ctx = ctx;
  return 0;
}


/* Release the assuan context created by start_gpg.  */
static void
release_gpg (assuan_context_t ctx)
{
  assuan_release (ctx);
}



/* The data passed to the writer_thread.  */
struct writer_thread_parms
{
  int fd;
  const void *data;
  size_t datalen;
  estream_t stream;
  gpg_error_t *err_addr;
};


/* The thread started by start_writer.  */
static void *
writer_thread_main (void *arg)
{
  gpg_error_t err = 0;
  struct writer_thread_parms *parm = arg;
  char _buffer[4096];
  char *buffer;
  size_t length;

  if (parm->stream)
    {
      buffer = _buffer;
      err = es_read (parm->stream, buffer, sizeof _buffer, &length);
      if (err)
        {
          log_error ("reading stream failed: %s\n", gpg_strerror (err));
          goto leave;
        }
    }
  else
    {
      buffer = (char *) parm->data;
      length = parm->datalen;
    }

  while (length)
    {
      ssize_t nwritten;

      nwritten = npth_write (parm->fd, buffer, length < 4096? length:4096);
      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          err = my_error_from_syserror ();
          break; /* Write error.  */
        }
      length -= nwritten;

      if (parm->stream)
        {
          if (length == 0)
            {
              err = es_read (parm->stream, buffer, sizeof _buffer, &length);
              if (err)
                {
                  log_error ("reading stream failed: %s\n",
                             gpg_strerror (err));
                  break;
                }
              if (length == 0)
                /* We're done.  */
                break;
            }
        }
      else
        buffer += nwritten;
    }

 leave:
  *parm->err_addr = err;
  if (close (parm->fd))
    log_error ("closing writer fd %d failed: %s\n", parm->fd, strerror (errno));
  xfree (parm);
  return NULL;
}


/* Fire up a thread to send (DATA,DATALEN) to the file descriptor FD.
   On success the thread receives the ownership over FD.  The thread
   ID is stored at R_TID.  WRITER_ERR is the address of an gpg_error_t
   variable to receive a possible write error after the thread has
   finished.  */
static gpg_error_t
start_writer (int fd, const void *data, size_t datalen, estream_t stream,
              npth_t *r_thread, gpg_error_t *err_addr)
{
  gpg_error_t err;
  struct writer_thread_parms *parm;
  npth_attr_t tattr;
  npth_t thread;
  int ret;

  memset (r_thread, '\0', sizeof (*r_thread));
  *err_addr = 0;

  parm = xtrymalloc (sizeof *parm);
  if (!parm)
    return my_error_from_syserror ();
  parm->fd = fd;
  parm->data = data;
  parm->datalen = datalen;
  parm->stream = stream;
  parm->err_addr = err_addr;

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  ret = npth_create (&thread, &tattr, writer_thread_main, parm);
  if (ret)
    {
      err = my_error_from_errno (ret);
      log_error ("error spawning writer thread: %s\n", gpg_strerror (err));
    }
  else
    {
      npth_setname_np (thread, "fd-writer");
      err = 0;
      *r_thread = thread;
    }
  npth_attr_destroy (&tattr);

  return err;
}



/* The data passed to the reader_thread.  */
struct reader_thread_parms
{
  int fd;
  membuf_t *mb;
  estream_t stream;
  gpg_error_t *err_addr;
};


/* The thread started by start_reader.  */
static void *
reader_thread_main (void *arg)
{
  gpg_error_t err = 0;
  struct reader_thread_parms *parm = arg;
  char buffer[4096];
  int nread;

  while ( (nread = npth_read (parm->fd, buffer, sizeof buffer)) )
    {
      if (nread < 0)
        {
          if (errno == EINTR)
            continue;
          err = my_error_from_syserror ();
          break;  /* Read error.  */
        }

      if (parm->stream)
        {
          const char *p = buffer;
          size_t nwritten;
          while (nread)
            {
              err = es_write (parm->stream, p, nread, &nwritten);
              if (err)
                {
                  log_error ("writing stream failed: %s\n",
                             gpg_strerror (err));
                  goto leave;
                }
              nread -= nwritten;
              p += nwritten;
            }
        }
      else
        put_membuf (parm->mb, buffer, nread);
    }

 leave:
  *parm->err_addr = err;
  if (close (parm->fd))
    log_error ("closing reader fd %d failed: %s\n", parm->fd, strerror (errno));
  xfree (parm);
  return NULL;
}


/* Fire up a thread to receive data from the file descriptor FD.  On
   success the thread receives the ownership over FD.  The thread ID
   is stored at R_TID.  After the thread has finished an error from
   the thread will be stored at ERR_ADDR.  */
static gpg_error_t
start_reader (int fd, membuf_t *mb, estream_t stream,
              npth_t *r_thread, gpg_error_t *err_addr)
{
  gpg_error_t err;
  struct reader_thread_parms *parm;
  npth_attr_t tattr;
  npth_t thread;
  int ret;

  memset (r_thread, '\0', sizeof (*r_thread));
  *err_addr = 0;

  parm = xtrymalloc (sizeof *parm);
  if (!parm)
    return my_error_from_syserror ();
  parm->fd = fd;
  parm->mb = mb;
  parm->stream = stream;
  parm->err_addr = err_addr;

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  ret = npth_create (&thread, &tattr, reader_thread_main, parm);
  if (ret)
    {
      err = my_error_from_errno (ret);
      log_error ("error spawning reader thread: %s\n", gpg_strerror (err));
    }
  else
    {
      npth_setname_np (thread, "fd-reader");
      err = 0;
      *r_thread = thread;
    }
  npth_attr_destroy (&tattr);

  return err;
}




/* Call GPG to encrypt a block of data.


 */
static gpg_error_t
_gpg_encrypt (ctrl_t ctrl,
              const char *gpg_program,
              strlist_t gpg_arguments,
              const void *plain, size_t plainlen,
              estream_t plain_stream,
              strlist_t keys,
              membuf_t *reader_mb,
              estream_t cipher_stream)
{
  gpg_error_t err;
  assuan_context_t ctx = NULL;
  int outbound_fds[2] = { -1, -1 };
  int inbound_fds[2]  = { -1, -1 };
  npth_t writer_thread = (npth_t)0;
  npth_t reader_thread = (npth_t)0;
  gpg_error_t writer_err, reader_err;
  char line[ASSUAN_LINELENGTH];
  strlist_t sl;
  int ret;

  /* Make sure that either the stream interface xor the buffer
     interface is used.  */
  assert ((plain == NULL) != (plain_stream == NULL));
  assert ((reader_mb == NULL) != (cipher_stream == NULL));

  /* Create two pipes.  */
  err = gnupg_create_outbound_pipe (outbound_fds, NULL, 0);
  if (!err)
    err = gnupg_create_inbound_pipe (inbound_fds, NULL, 0);
  if (err)
    {
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Start GPG and send the INPUT and OUTPUT commands.  */
  err = start_gpg (ctrl, gpg_program, gpg_arguments,
                   outbound_fds[0], inbound_fds[1], &ctx);
  if (err)
    goto leave;
  close (outbound_fds[0]); outbound_fds[0] = -1;
  close (inbound_fds[1]); inbound_fds[1] = -1;

  /* Start a writer thread to feed the INPUT command of the server.  */
  err = start_writer (outbound_fds[1], plain, plainlen, plain_stream,
                      &writer_thread, &writer_err);
  if (err)
    return err;
  outbound_fds[1] = -1;  /* The thread owns the FD now.  */

  /* Start a reader thread to eat from the OUTPUT command of the
     server.  */
  err = start_reader (inbound_fds[0], reader_mb, cipher_stream,
                      &reader_thread, &reader_err);
  if (err)
    return err;
  outbound_fds[0] = -1;  /* The thread owns the FD now.  */

  /* Run the encryption.  */
  for (sl = keys; sl; sl = sl->next)
    {
      snprintf (line, sizeof line, "RECIPIENT -- %s", sl->d);
      err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);
      if (err)
        {
          log_error ("the engine's RECIPIENT command failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
          goto leave;
        }
    }

  err = assuan_transact (ctx, "ENCRYPT", NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    {
      log_error ("the engine's ENCRYPT command failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
      goto leave;
    }

  /* Wait for reader and return the data.  */
  ret = npth_join (reader_thread, NULL);
  if (ret)
    {
      err = my_error_from_errno (ret);
      log_error ("waiting for reader thread failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  /* FIXME: Not really valid, as npth_t is an opaque type.  */
  memset (&reader_thread, '\0', sizeof (reader_thread));
  if (reader_err)
    {
      err = reader_err;
      log_error ("read error in reader thread: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Wait for the writer to catch  a writer error.  */
  ret = npth_join (writer_thread, NULL);
  if (ret)
    {
      err = my_error_from_errno (ret);
      log_error ("waiting for writer thread failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  memset (&writer_thread, '\0', sizeof (writer_thread));
  if (writer_err)
    {
      err = writer_err;
      log_error ("write error in writer thread: %s\n", gpg_strerror (err));
      goto leave;
    }

 leave:
  /* FIXME: Not valid, as npth_t is an opaque type.  */
  if (reader_thread)
    npth_detach (reader_thread);
  if (writer_thread)
    npth_detach (writer_thread);
  if (outbound_fds[0] != -1)
    close (outbound_fds[0]);
  if (outbound_fds[1] != -1)
    close (outbound_fds[1]);
  if (inbound_fds[0] != -1)
    close (inbound_fds[0]);
  if (inbound_fds[1] != -1)
    close (inbound_fds[1]);
  release_gpg (ctx);
  return err;
}

gpg_error_t
gpg_encrypt_blob (ctrl_t ctrl,
                  const char *gpg_program,
                  strlist_t gpg_arguments,
                  const void *plain, size_t plainlen,
                  strlist_t keys,
                  void **r_ciph, size_t *r_ciphlen)
{
  gpg_error_t err;
  membuf_t reader_mb;

  *r_ciph = NULL;
  *r_ciphlen = 0;

  /* Init the memory buffer to receive the encrypted stuff.  */
  init_membuf (&reader_mb, 4096);

  err = _gpg_encrypt (ctrl, gpg_program, gpg_arguments,
                      plain, plainlen, NULL,
                      keys,
                      &reader_mb, NULL);

  if (! err)
    {
      /* Return the data.  */
      *r_ciph = get_membuf (&reader_mb, r_ciphlen);
      if (!*r_ciph)
        {
          err = my_error_from_syserror ();
          log_error ("error while storing the data in the reader thread: %s\n",
                     gpg_strerror (err));
        }
    }

  xfree (get_membuf (&reader_mb, NULL));
  return err;
}

gpg_error_t
gpg_encrypt_stream (ctrl_t ctrl,
                    const char *gpg_program,
                    strlist_t gpg_arguments,
                    estream_t plain_stream,
                    strlist_t keys,
                    estream_t cipher_stream)
{
  return _gpg_encrypt (ctrl, gpg_program, gpg_arguments,
                       NULL, 0, plain_stream,
                       keys,
                       NULL, cipher_stream);
}

/* Call GPG to decrypt a block of data.


 */
static gpg_error_t
_gpg_decrypt (ctrl_t ctrl,
              const char *gpg_program,
              strlist_t gpg_arguments,
              const void *ciph, size_t ciphlen,
              estream_t cipher_stream,
              membuf_t *reader_mb,
              estream_t plain_stream)
{
  gpg_error_t err;
  assuan_context_t ctx = NULL;
  int outbound_fds[2] = { -1, -1 };
  int inbound_fds[2]  = { -1, -1 };
  npth_t writer_thread = (npth_t)0;
  npth_t reader_thread = (npth_t)0;
  gpg_error_t writer_err, reader_err;
  int ret;

  /* Make sure that either the stream interface xor the buffer
     interface is used.  */
  assert ((ciph == NULL) != (cipher_stream == NULL));
  assert ((reader_mb == NULL) != (plain_stream == NULL));

  /* Create two pipes.  */
  err = gnupg_create_outbound_pipe (outbound_fds, NULL, 0);
  if (!err)
    err = gnupg_create_inbound_pipe (inbound_fds, NULL, 0);
  if (err)
    {
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Start GPG and send the INPUT and OUTPUT commands.  */
  err = start_gpg (ctrl, gpg_program, gpg_arguments,
                   outbound_fds[0], inbound_fds[1], &ctx);
  if (err)
    goto leave;
  close (outbound_fds[0]); outbound_fds[0] = -1;
  close (inbound_fds[1]); inbound_fds[1] = -1;

  /* Start a writer thread to feed the INPUT command of the server.  */
  err = start_writer (outbound_fds[1], ciph, ciphlen, cipher_stream,
                      &writer_thread, &writer_err);
  if (err)
    return err;
  outbound_fds[1] = -1;  /* The thread owns the FD now.  */

  /* Start a reader thread to eat from the OUTPUT command of the
     server.  */
  err = start_reader (inbound_fds[0], reader_mb, plain_stream,
                      &reader_thread, &reader_err);
  if (err)
    return err;
  outbound_fds[0] = -1;  /* The thread owns the FD now.  */

  /* Run the decryption.  */
  err = assuan_transact (ctx, "DECRYPT", NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    {
      log_error ("the engine's DECRYPT command failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
      goto leave;
    }

  /* Wait for reader and return the data.  */
  ret = npth_join (reader_thread, NULL);
  if (ret)
    {
      err = my_error_from_errno (ret);
      log_error ("waiting for reader thread failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  memset (&reader_thread, '\0', sizeof (reader_thread));
  if (reader_err)
    {
      err = reader_err;
      log_error ("read error in reader thread: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Wait for the writer to catch a writer error.  */
  ret = npth_join (writer_thread, NULL);
  if (ret)
    {
      err = my_error_from_errno (ret);
      log_error ("waiting for writer thread failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  memset (&writer_thread, '\0', sizeof (writer_thread));
  if (writer_err)
    {
      err = writer_err;
      log_error ("write error in writer thread: %s\n", gpg_strerror (err));
      goto leave;
    }

 leave:
  if (reader_thread)
    npth_detach (reader_thread);
  if (writer_thread)
    npth_detach (writer_thread);
  if (outbound_fds[0] != -1)
    close (outbound_fds[0]);
  if (outbound_fds[1] != -1)
    close (outbound_fds[1]);
  if (inbound_fds[0] != -1)
    close (inbound_fds[0]);
  if (inbound_fds[1] != -1)
    close (inbound_fds[1]);
  release_gpg (ctx);
  return err;
}

gpg_error_t
gpg_decrypt_blob (ctrl_t ctrl,
                  const char *gpg_program,
                  strlist_t gpg_arguments,
                  const void *ciph, size_t ciphlen,
                  void **r_plain, size_t *r_plainlen)
{
  gpg_error_t err;
  membuf_t reader_mb;

  *r_plain = NULL;
  *r_plainlen = 0;

  /* Init the memory buffer to receive the encrypted stuff.  */
  init_membuf_secure (&reader_mb, 1024);

  err = _gpg_decrypt (ctrl, gpg_program, gpg_arguments,
                      ciph, ciphlen, NULL,
                      &reader_mb, NULL);

  if (! err)
    {
      /* Return the data.  */
      *r_plain = get_membuf (&reader_mb, r_plainlen);
      if (!*r_plain)
        {
          err = my_error_from_syserror ();
          log_error ("error while storing the data in the reader thread: %s\n",
                     gpg_strerror (err));
        }
    }

  xfree (get_membuf (&reader_mb, NULL));
  return err;
}

gpg_error_t
gpg_decrypt_stream (ctrl_t ctrl,
                    const char *gpg_program,
                    strlist_t gpg_arguments,
                    estream_t cipher_stream,
                    estream_t plain_stream)
{
  return _gpg_decrypt (ctrl, gpg_program, gpg_arguments,
                       NULL, 0, cipher_stream,
                       NULL, plain_stream);
}
