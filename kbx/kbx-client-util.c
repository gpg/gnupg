/* kbx-client-util.c - Utility functions to implement a keyboxd client
 * Copyright (C) 2020 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <npth.h>
#include <assuan.h>

#include "../common/util.h"
#include "../common/membuf.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/exechelp.h"
#include "../common/sysutils.h"
#include "../common/host2net.h"
#include "kbx-client-util.h"


#define MAX_DATABLOB_SIZE (16*1024*1024)



/* This object is used to implement a client to the keyboxd.  */
struct kbx_client_data_s
{
  /* The used assuan context.  */
  assuan_context_t ctx;

  /* A stream used to receive data.  If this is NULL D-lines are used
   * to receive the data. */
  estream_t fp;

  /* Condition variable to sync the datastream with the command.  */
  npth_mutex_t mutex;
  npth_cond_t  cond;

  /* The data received from the keyboxd and an error code if there was
   * a problem (in which case DATA is also set to NULL.  This is only
   * used if FP is not NULL.  */
  char *data;
  size_t datalen;
  gpg_error_t dataerr;

  /* Helper variables in case D-lines are used (FP is NULL)  */
  char *dlinedata;
  size_t dlinedatalen;
  gpg_error_t dlineerr;
};



static void *datastream_thread (void *arg);



static void
lock_datastream (kbx_client_data_t kcd)
{
  int rc = npth_mutex_lock (&kcd->mutex);
  if (rc)
    log_fatal ("%s: failed to acquire mutex: %s\n", __func__,
               gpg_strerror (gpg_error_from_errno (rc)));
}


static void
unlock_datastream (kbx_client_data_t kcd)
{
  int rc = npth_mutex_unlock (&kcd->mutex);
  if (rc)
    log_fatal ("%s: failed to release mutex: %s\n", __func__,
               gpg_strerror (gpg_error_from_errno (rc)));
}



/* Setup the pipe used for receiving data from the keyboxd.  Store the
 * info on KCD.  */
static gpg_error_t
prepare_data_pipe (kbx_client_data_t kcd)
{
  gpg_error_t err;
  int rc;
  int inpipe[2];
  estream_t infp;
  npth_t thread;
  npth_attr_t tattr;

  kcd->fp = NULL;
  kcd->data = NULL;
  kcd->datalen = 0;
  kcd->dataerr = 0;

  err = gnupg_create_inbound_pipe (inpipe, &infp, 0);
  if (err)
    {
      log_error ("error creating inbound pipe: %s\n", gpg_strerror (err));
      return err;  /* That should not happen.  */
    }

  err = assuan_sendfd (kcd->ctx, INT2FD (inpipe[1]));
  if (err)
    {
      log_error ("sending sending fd %d to keyboxd: %s <%s>\n",
                 inpipe[1], gpg_strerror (err), gpg_strsource (err));
      es_fclose (infp);
      gnupg_close_pipe (inpipe[1]);
      return 0; /* Server may not support fd-passing.  */
    }

  err = assuan_transact (kcd->ctx, "OUTPUT FD",
                         NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    {
      log_info ("keyboxd does not accept our fd: %s <%s>\n",
                gpg_strerror (err), gpg_strsource (err));
      es_fclose (infp);
      return 0;
    }

  kcd->fp = infp;


  rc = npth_attr_init (&tattr);
  if (rc)
    {
      err = gpg_error_from_errno (rc);
      log_error ("error preparing thread for keyboxd: %s\n",gpg_strerror (err));
      es_fclose (infp);
      kcd->fp = NULL;
      return err;
    }
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);
  rc = npth_create (&thread, &tattr, datastream_thread, kcd);
  if (rc)
    {
      err = gpg_error_from_errno (rc);
      log_error ("error spawning thread for keyboxd: %s\n", gpg_strerror (err));
      npth_attr_destroy (&tattr);
      es_fclose (infp);
      kcd->fp = NULL;
      return err;
    }

  return 0;
}


/* The thread used to read from the data stream.  This is running as
 * long as the connection and its datastream exists.  */
static void *
datastream_thread (void *arg)
{
  kbx_client_data_t kcd = arg;
  gpg_error_t err;
  int rc;
  unsigned char lenbuf[4];
  size_t nread, datalen;
  char *data = NULL;
  char *tmpdata;

  /* log_debug ("%s: started\n", __func__); */
  while (kcd->fp)
    {
      /* log_debug ("%s: waiting ...\n", __func__); */
      if (es_read (kcd->fp, lenbuf, 4, &nread))
        {
          err = gpg_error_from_syserror ();
          if (gpg_err_code (err) == GPG_ERR_EAGAIN)
            continue;
          log_error ("error reading data length from keyboxd: %s\n",
                     gpg_strerror (err));
          gnupg_sleep (1);
          continue;
        }
      if (nread != 4)
        {
          err = gpg_error (GPG_ERR_EIO);
          log_error ("error reading data length from keyboxd: %s\n",
                     "short read");
          continue;
        }

      datalen = buf32_to_size_t (lenbuf);
      /* log_debug ("keyboxd announced %zu bytes\n", datalen); */
      if (!datalen)
        {
          log_info ("ignoring empty blob received from keyboxd\n");
          continue;
        }

      if (datalen > MAX_DATABLOB_SIZE)
        {
          err = gpg_error (GPG_ERR_TOO_LARGE);
          /* Drop connection or what shall we do?  */
        }
      else if (!(data = xtrymalloc (datalen+1)))
        {
          err = gpg_error_from_syserror ();
        }
      else if (es_read (kcd->fp, data, datalen, &nread))
        {
          err = gpg_error_from_syserror ();
        }
      else if (datalen != nread)
        {
          err = gpg_error (GPG_ERR_TOO_SHORT);
        }
      else
        err = 0;

      if (err)
        {
          log_error ("error reading data from keyboxd: %s <%s>\n",
                     gpg_strerror (err), gpg_strsource (err));
          xfree (data);
          data = NULL;
          datalen = 0;
        }
      else
        {
          /* log_debug ("parsing datastream succeeded\n"); */
        }

      /* Thread-safe assignment to the result var:  */
      tmpdata = kcd->data;
      kcd->data = data;
      kcd->datalen = datalen;
      kcd->dataerr = err;
      xfree (tmpdata);
      data = NULL;

      /* Tell the main thread.  */
      lock_datastream (kcd);
      rc = npth_cond_signal (&kcd->cond);
      if (rc)
        {
          err = gpg_error_from_errno (rc);
          log_error ("%s: signaling condition failed: %s\n",
                     __func__, gpg_strerror (err));
        }
      unlock_datastream (kcd);
    }
  /* log_debug ("%s: finished\n", __func__); */

  return NULL;
}



/* Create a new keyboxd client data object and return it at R_KCD.
 * CTX is the assuan context to be used for connecting the keyboxd.
 * If dlines is set, communication is done without fd passing via
 * D-lines.  */
gpg_error_t
kbx_client_data_new (kbx_client_data_t *r_kcd, assuan_context_t ctx,
                     int dlines)
{
  kbx_client_data_t kcd;
  int rc;
  gpg_error_t err;

  kcd = xtrycalloc (1, sizeof *kcd);
  if (!kcd)
    return gpg_error_from_syserror ();

  kcd->ctx = ctx;

  if (dlines)
    goto leave;

  rc = npth_mutex_init (&kcd->mutex, NULL);
  if (rc)
    {
      err = gpg_error_from_errno (rc);
      log_error ("error initializing mutex: %s\n", gpg_strerror (err));
      xfree (kcd);
      return err;
    }
  rc = npth_cond_init (&kcd->cond, NULL);
  if (rc)
    {
      err = gpg_error_from_errno (rc);
      log_error ("error initializing condition: %s\n", gpg_strerror (err));
      npth_mutex_destroy (&kcd->mutex);
      xfree (kcd);
      return err;
    }

  err = prepare_data_pipe (kcd);
  if (err)
    {
      npth_cond_destroy (&kcd->cond);
      npth_mutex_destroy (&kcd->mutex);
      xfree (kcd);
      return err;
    }

 leave:
  *r_kcd = kcd;
  return 0;
}


void
kbx_client_data_release (kbx_client_data_t kcd)
{
  estream_t fp;

  if (!kcd)
    return;
  fp = kcd->fp;
  kcd->fp = NULL;
  es_fclose (fp);  /* That close should let the thread run into an error.  */
  /* FIXME: Make thread killing explicit.  Otherwise we run in a
   * log_fatal due to the destroyed mutex. */
  npth_cond_destroy (&kcd->cond);
  npth_mutex_destroy (&kcd->mutex);
  xfree (kcd);
}


/* Send a simple Assuan command to the server.  */
gpg_error_t
kbx_client_data_simple (kbx_client_data_t kcd, const char *command)
{
  /* log_debug ("%s: sending command '%s'\n", __func__, command); */
  return assuan_transact (kcd->ctx, command,
                          NULL, NULL, NULL, NULL, NULL, NULL);
}


/* Send the COMMAND down to the keyboxd associated with KCD.
 * STATUS_CB and STATUS_CB_VALUE are the usual status callback as used
 * by assuan_transact.  After this function has returned success
 * kbx_client_data_wait needs to be called to actually return the
 * data.  */
gpg_error_t
kbx_client_data_cmd (kbx_client_data_t kcd, const char *command,
                     gpg_error_t (*status_cb)(void *opaque, const char *line),
                     void *status_cb_value)
{
  gpg_error_t err;

  xfree (kcd->dlinedata);
  kcd->dlinedata = NULL;
  kcd->dlinedatalen = 0;
  kcd->dlineerr = 0;

  if (kcd->fp)
    {
      /* log_debug ("%s: sending command '%s'\n", __func__, command); */
      err = assuan_transact (kcd->ctx, command,
                             NULL, NULL,
                             NULL, NULL,
                             status_cb, status_cb_value);
      if (err)
        {
          if (gpg_err_code (err) != GPG_ERR_NOT_FOUND
              && gpg_err_code (err) != GPG_ERR_NOTHING_FOUND)
            log_debug ("%s: finished command with error: %s\n",
                       __func__, gpg_strerror (err));
          /* Fixme: On unexpected errors we need a way to cancel the
           * data stream.  Probably it will be best to close and
           * reopen it.  */
        }
    }
  else /* Slower D-line version if fd-passing is not available.  */
    {
      membuf_t mb;
      size_t len;

      /* log_debug ("%s: sending command '%s' (no fd-passing)\n", */
      /*            __func__, command); */
      init_membuf (&mb, 8192);
      err = assuan_transact (kcd->ctx, command,
                             put_membuf_cb, &mb,
                             NULL, NULL,
                             status_cb, status_cb_value);
      if (err)
        {
          /* if (gpg_err_code (err) != GPG_ERR_NOT_FOUND */
          /*     && gpg_err_code (err) != GPG_ERR_NOTHING_FOUND) */
          /*   log_debug ("%s: finished command with error: %s\n", */
          /*              __func__, gpg_strerror (err)); */
          xfree (get_membuf (&mb, &len));
          kcd->dlineerr = err;
          goto leave;
        }

      kcd->dlinedata = get_membuf (&mb, &kcd->dlinedatalen);
      if (!kcd->dlinedata)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

 leave:
  return err;
}



/* Wait for the data from the server and on success return it at
 * (R_DATA, R_DATALEN). */
gpg_error_t
kbx_client_data_wait (kbx_client_data_t kcd, char **r_data, size_t *r_datalen)
{
  gpg_error_t err = 0;
  int rc;

  *r_data = NULL;
  *r_datalen = 0;
  if (kcd->fp)
    {
      lock_datastream (kcd);
      if (!kcd->data && !kcd->dataerr)
        {
          /* log_debug ("%s: waiting on datastream_cond ...\n", __func__); */
          rc = npth_cond_wait (&kcd->cond, &kcd->mutex);
          if (rc)
            {
              err = gpg_error_from_errno (rc);
              log_error ("%s: waiting on condition failed: %s\n",
                         __func__, gpg_strerror (err));
            }
          /* else */
          /*   log_debug ("%s: waiting on datastream.cond done\n", __func__); */
        }
      *r_data = kcd->data;
      kcd->data = NULL;
      *r_datalen = kcd->datalen;
      err = err? err : kcd->dataerr;

      unlock_datastream (kcd);
    }
  else
    {
      *r_data = kcd->dlinedata;
      kcd->dlinedata = NULL;
      *r_datalen = kcd->dlinedatalen;
      err = kcd->dlineerr;
    }

  return err;
}
