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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <npth.h>

#include "g13.h"
#include <assuan.h>
#include "i18n.h"
#include "call-gpg.h"
#include "utils.h"
#include "../common/exechelp.h"



/* Fire up a new GPG.  Handle the server's initial greeting.  Returns
   0 on success and stores the assuan context at R_CTX.  */
static gpg_error_t
start_gpg (ctrl_t ctrl, int input_fd, int output_fd, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx = NULL;
  const char *pgmname;
  const char *argv[10];
  int no_close_list[5];
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

  /* The first time we are used, intialize the gpg_program variable.  */
  if ( !opt.gpg_program || !*opt.gpg_program )
    opt.gpg_program = gnupg_module_name (GNUPG_MODULE_NAME_GPG);

  if (opt.verbose)
    log_info (_("no running gpg - starting '%s'\n"), opt.gpg_program);

  /* Compute argv[0].  */
  if ( !(pgmname = strrchr (opt.gpg_program, '/')))
    pgmname = opt.gpg_program;
  else
    pgmname++;

  if (fflush (NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("error flushing pending output: %s\n", gpg_strerror (err));
      return err;
    }

  i = 0;
  argv[i++] = pgmname;
  argv[i++] = "--server";
  if ((opt.debug & 1024))
    argv[i++] = "--debug=1024";
  argv[i++] = "-z";
  argv[i++] = "0";
  argv[i++] = "--trust-model";
  argv[i++] = "always";
  argv[i++] = NULL;

  i = 0;
  if (log_get_fd () != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (log_get_fd ());
  no_close_list[i++] = assuan_fd_from_posix_fd (fileno (stderr));
  if (input_fd != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (input_fd);
  if (output_fd != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (output_fd);
  no_close_list[i] = -1;

  /* Connect to GPG and perform initial handshaking.  */
  err = assuan_pipe_connect (ctx, opt.gpg_program, argv, no_close_list,
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

  if (DBG_IPC)
    log_debug ("connection to GPG established\n");
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
  gpg_error_t *err_addr;
};


/* The thread started by start_writer.  */
static void *
writer_thread_main (void *arg)
{
  struct writer_thread_parms *parm = arg;
  const char *buffer = parm->data;
  size_t length = parm->datalen;

  while (length)
    {
      ssize_t nwritten;

      nwritten = npth_write (parm->fd, buffer, length < 4096? length:4096);
      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          *parm->err_addr = gpg_error_from_syserror ();
          break; /* Write error.  */
        }
      length -= nwritten;
      buffer += nwritten;
    }

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
start_writer (int fd, const void *data, size_t datalen,
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
    return gpg_error_from_syserror ();
  parm->fd = fd;
  parm->data = data;
  parm->datalen = datalen;
  parm->err_addr = err_addr;

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  ret = npth_create (&thread, &tattr, writer_thread_main, parm);
  if (ret)
    {
      err = gpg_error_from_errno (ret);
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
  gpg_error_t *err_addr;
};


/* The thread started by start_reader.  */
static void *
reader_thread_main (void *arg)
{
  struct reader_thread_parms *parm = arg;
  char buffer[4096];
  int nread;

  while ( (nread = npth_read (parm->fd, buffer, sizeof buffer)) )
    {
      if (nread < 0)
        {
          if (errno == EINTR)
            continue;
          *parm->err_addr = gpg_error_from_syserror ();
          break;  /* Read error.  */
        }

      put_membuf (parm->mb, buffer, nread);
    }

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
start_reader (int fd, membuf_t *mb, npth_t *r_thread, gpg_error_t *err_addr)
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
    return gpg_error_from_syserror ();
  parm->fd = fd;
  parm->mb = mb;
  parm->err_addr = err_addr;

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  ret = npth_create (&thread, &tattr, reader_thread_main, parm);
  if (ret)
    {
      err = gpg_error_from_errno (ret);
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
gpg_error_t
gpg_encrypt_blob (ctrl_t ctrl, const void *plain, size_t plainlen,
                  strlist_t keys, void **r_ciph, size_t *r_ciphlen)
{
  gpg_error_t err;
  assuan_context_t ctx = NULL;
  int outbound_fds[2] = { -1, -1 };
  int inbound_fds[2]  = { -1, -1 };
  npth_t writer_thread = (npth_t)0;
  npth_t reader_thread = (npth_t)0;
  gpg_error_t writer_err, reader_err;
  membuf_t reader_mb;
  char line[ASSUAN_LINELENGTH];
  strlist_t sl;
  int ret;

  *r_ciph = NULL;
  *r_ciphlen = 0;

  /* Init the memory buffer to receive the encrypted stuff.  */
  init_membuf (&reader_mb, 4096);

  /* Create two pipes.  */
  err = gnupg_create_outbound_pipe (outbound_fds);
  if (!err)
    err = gnupg_create_inbound_pipe (inbound_fds);
  if (err)
    {
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Start GPG and send the INPUT and OUTPUT commands.  */
  err = start_gpg (ctrl, outbound_fds[0], inbound_fds[1], &ctx);
  if (err)
    goto leave;
  close (outbound_fds[0]); outbound_fds[0] = -1;
  close (inbound_fds[1]); inbound_fds[1] = -1;

  /* Start a writer thread to feed the INPUT command of the server.  */
  err = start_writer (outbound_fds[1], plain, plainlen,
                      &writer_thread, &writer_err);
  if (err)
    return err;
  outbound_fds[1] = -1;  /* The thread owns the FD now.  */

  /* Start a reader thread to eat from the OUTPUT command of the
     server.  */
  err = start_reader (inbound_fds[0], &reader_mb,
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
      err = gpg_error_from_errno (ret);
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
      err = gpg_error_from_errno (ret);
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

  /* Return the data.  */
  *r_ciph = get_membuf (&reader_mb, r_ciphlen);
  if (!*r_ciph)
    {
      err = gpg_error_from_syserror ();
      log_error ("error while storing the data in the reader thread: %s\n",
                 gpg_strerror (err));
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
  xfree (get_membuf (&reader_mb, NULL));
  return err;
}



/* Call GPG to decrypt a block of data.


 */
gpg_error_t
gpg_decrypt_blob (ctrl_t ctrl, const void *ciph, size_t ciphlen,
                  void **r_plain, size_t *r_plainlen)
{
  gpg_error_t err;
  assuan_context_t ctx = NULL;
  int outbound_fds[2] = { -1, -1 };
  int inbound_fds[2]  = { -1, -1 };
  npth_t writer_thread = (npth_t)0;
  npth_t reader_thread = (npth_t)0;
  gpg_error_t writer_err, reader_err;
  membuf_t reader_mb;
  int ret;

  *r_plain = NULL;
  *r_plainlen = 0;

  /* Init the memory buffer to receive the encrypted stuff.  */
  init_membuf_secure (&reader_mb, 1024);

  /* Create two pipes.  */
  err = gnupg_create_outbound_pipe (outbound_fds);
  if (!err)
    err = gnupg_create_inbound_pipe (inbound_fds);
  if (err)
    {
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Start GPG and send the INPUT and OUTPUT commands.  */
  err = start_gpg (ctrl, outbound_fds[0], inbound_fds[1], &ctx);
  if (err)
    goto leave;
  close (outbound_fds[0]); outbound_fds[0] = -1;
  close (inbound_fds[1]); inbound_fds[1] = -1;

  /* Start a writer thread to feed the INPUT command of the server.  */
  err = start_writer (outbound_fds[1], ciph, ciphlen,
                      &writer_thread, &writer_err);
  if (err)
    return err;
  outbound_fds[1] = -1;  /* The thread owns the FD now.  */

  /* Start a reader thread to eat from the OUTPUT command of the
     server.  */
  err = start_reader (inbound_fds[0], &reader_mb,
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
      err = gpg_error_from_errno (ret);
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
      err = gpg_error_from_errno (ret);
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

  /* Return the data.  */
  *r_plain = get_membuf (&reader_mb, r_plainlen);
  if (!*r_plain)
    {
      err = gpg_error_from_syserror ();
      log_error ("error while storing the data in the reader thread: %s\n",
                 gpg_strerror (err));
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
  xfree (get_membuf (&reader_mb, NULL));
  return err;
}
