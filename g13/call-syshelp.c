/* call-syshelp.c - Communication with g13-syshelp
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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
#include "../common/i18n.h"
#include "g13tuple.h"
#include "keyblob.h"
#include "../common/membuf.h"
#include "create.h"
#include "call-syshelp.h"


/* Local data for this module.  A pointer to this is stored in the
   CTRL object of each connection.  */
struct call_syshelp_s
{
  assuan_context_t assctx;  /* The Assuan context for the current
                               g13-syshep connection.  */
};


/* Parameter used with the CREATE command.  */
struct create_parm_s
{
  assuan_context_t ctx;
  ctrl_t ctrl;
  membuf_t plaintext;
  unsigned int expect_plaintext:1;
  unsigned int got_plaintext:1;
};


/* Parameter used with the MOUNT command.  */
struct mount_parm_s
{
  assuan_context_t ctx;
  ctrl_t ctrl;
  const void *keyblob;
  size_t keybloblen;
};





/* Fork off the syshelp tool if this has not already been done.  On
   success stores the current Assuan context for the syshelp tool at
   R_CTX.  */
static gpg_error_t
start_syshelp (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;
  assuan_fd_t no_close_list[3];

  *r_ctx = NULL;

  if (ctrl->syshelp_local && (*r_ctx = ctrl->syshelp_local->assctx))
    return 0; /* Already set.  */

  if (opt.verbose)
    log_info ("starting a new syshelp\n");

  if (!ctrl->syshelp_local)
    {
      ctrl->syshelp_local = xtrycalloc (1, sizeof *ctrl->syshelp_local);
      if (!ctrl->syshelp_local)
        return gpg_error_from_syserror ();
    }

  if (es_fflush (NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("error flushing pending output: %s\n", gpg_strerror (err));
      return err;
    }

  no_close_list[0] = assuan_fd_from_posix_fd (es_fileno (es_stderr));
  no_close_list[1] = ASSUAN_INVALID_FD;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (err));
      return err;
    }

  /* Call userv to start g13-syshelp.  This userv script needs to be
   * installed under the name "gnupg-g13-syshelp":
   *
   *   if ( glob service-user root
   *      )
   *       reset
   *       suppress-args
   *       execute /home/wk/b/gnupg/g13/g13-syshelp -v
   *   else
   *       error Nothing to do for this service-user
   *   fi
   *   quit
   */
  {
    const char *argv[4];

    argv[0] = "userv";
    argv[1] = "root";
    argv[2] = "gnupg-g13-syshelp";
    argv[3] = NULL;

    err = assuan_pipe_connect (ctx, "/usr/bin/userv", argv,
                               no_close_list, NULL, NULL, 0);
  }
  if (err)
    {
      log_error ("can't connect to '%s': %s %s\n",
                 "g13-syshelp", gpg_strerror (err), gpg_strsource (err));
      log_info ("(is userv and its gnupg-g13-syshelp script installed?)\n");
      assuan_release (ctx);
      return err;
    }

  *r_ctx = ctrl->syshelp_local->assctx = ctx;

  if (DBG_IPC)
    log_debug ("connection to g13-syshelp established\n");

  return 0;
}


/* Release local resources associated with CTRL.  */
void
call_syshelp_release (ctrl_t ctrl)
{
  if (!ctrl)
    return;
  if (ctrl->syshelp_local)
    {
      assuan_release (ctrl->syshelp_local->assctx);
      ctrl->syshelp_local->assctx = NULL;
      xfree (ctrl->syshelp_local);
      ctrl->syshelp_local = NULL;
    }
}



/* Status callback for call_syshelp_find_device.  */
static gpg_error_t
finddevice_status_cb (void *opaque, const char *line)
{
  char **r_blockdev = opaque;
  char *p;

  if ((p = has_leading_keyword (line, "BLOCKDEV")) && *p && !*r_blockdev)
    {
      *r_blockdev = xtrystrdup (p);
      if (!*r_blockdev)
        return gpg_error_from_syserror ();
    }

  return 0;
}


/* Send the FINDDEVICE command to the syshelper.  On success the name
 * of the block device is stored at R_BLOCKDEV. */
gpg_error_t
call_syshelp_find_device (ctrl_t ctrl, const char *name, char **r_blockdev)
{
  gpg_error_t err;
  assuan_context_t ctx;
  char *line = NULL;
  char *blockdev = NULL;  /* The result.  */

  *r_blockdev = NULL;

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  line = xtryasprintf ("FINDDEVICE %s", name);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL,
                         finddevice_status_cb, &blockdev);
  if (err)
    goto leave;
  if (!blockdev)
    {
      log_error ("status line for successful FINDDEVICE missing\n");
      err = gpg_error (GPG_ERR_UNEXPECTED);
      goto leave;
    }
  *r_blockdev = blockdev;
  blockdev = NULL;

 leave:
  xfree (blockdev);
  xfree (line);
  return err;
}



static gpg_error_t
getkeyblob_data_cb (void *opaque, const void *data, size_t datalen)
{
  membuf_t *mb = opaque;

  if (data)
    put_membuf (mb, data, datalen);

  return 0;
}


/* Send the GTEKEYBLOB command to the syshelper.  On success the
 * encrypted keyblpob is stored at (R_ENCKEYBLOB,R_ENCKEYBLOBLEN).  */
gpg_error_t
call_syshelp_get_keyblob (ctrl_t ctrl,
                          void **r_enckeyblob, size_t *r_enckeybloblen)
{
  gpg_error_t err;
  assuan_context_t ctx;
  membuf_t mb;

  *r_enckeyblob = NULL;
  *r_enckeybloblen = 0;
  init_membuf (&mb, 512);

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  err = assuan_transact (ctx, "GETKEYBLOB",
                         getkeyblob_data_cb, &mb,
                         NULL, NULL, NULL, NULL);
  if (err)
    goto leave;
  *r_enckeyblob = get_membuf (&mb, r_enckeybloblen);
  if (!*r_enckeyblob)
    err = gpg_error_from_syserror ();

 leave:
  xfree (get_membuf (&mb, NULL));
  return err;
}



/* Send the DEVICE command to the syshelper.  FNAME is the name of the
   device.  */
gpg_error_t
call_syshelp_set_device (ctrl_t ctrl, const char *fname)
{
  gpg_error_t err;
  assuan_context_t ctx;
  char *line = NULL;

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  line = xtryasprintf ("DEVICE %s", fname);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, NULL, NULL, NULL, NULL, NULL, NULL);

 leave:
  xfree (line);
  return err;
}



static gpg_error_t
create_status_cb (void *opaque, const char *line)
{
  struct create_parm_s *parm = opaque;

  if (has_leading_keyword (line, "PLAINTEXT_FOLLOWS"))
    parm->expect_plaintext = 1;

  return 0;
}


static gpg_error_t
create_data_cb (void *opaque, const void *data, size_t datalen)
{
  struct create_parm_s *parm = opaque;
  gpg_error_t err = 0;

  if (!parm->expect_plaintext)
    {
      log_error ("status line for data missing\n");
      err = gpg_error (GPG_ERR_UNEXPECTED);
    }
  else if (data)
    {
      put_membuf (&parm->plaintext, data, datalen);
    }
  else
    {
      parm->expect_plaintext = 0;
      parm->got_plaintext = 1;
    }

  return err;
}


static gpg_error_t
create_inq_cb (void *opaque, const char *line)
{
  struct create_parm_s *parm = opaque;
  gpg_error_t err;

  if (has_leading_keyword (line, "ENCKEYBLOB"))
    {
      void *plaintext;
      size_t plaintextlen;

      if (!parm->got_plaintext)
        err = gpg_error (GPG_ERR_UNEXPECTED);
      else if (!(plaintext = get_membuf (&parm->plaintext, &plaintextlen)))
        err = gpg_error_from_syserror ();
      else
        {
          void *ciphertext;
          size_t ciphertextlen;

          log_printhex (plaintext, plaintextlen, "plain");
          err = g13_encrypt_keyblob (parm->ctrl,
                                     plaintext, plaintextlen,
                                     &ciphertext, &ciphertextlen);
          wipememory (plaintext, plaintextlen);
          xfree (plaintext);
          if (err)
            log_error ("error encrypting keyblob: %s\n", gpg_strerror (err));
          else
            {
              err = assuan_send_data (parm->ctx, ciphertext, ciphertextlen);
              xfree (ciphertext);
              if (err)
                log_error ("sending ciphertext to g13-syshelp failed: %s\n",
                           gpg_strerror (err));
            }
        }
    }
  else
    err = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);

  return err;
}


/* Run the CREATE command on the current device.  CONTTYPES gives the
   requested content type for the new container.  */
gpg_error_t
call_syshelp_run_create (ctrl_t ctrl, int conttype)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct create_parm_s parm;

  memset (&parm, 0, sizeof parm);

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  /* tty_get ("waiting for debugger"); */
  /* tty_kill_prompt (); */

  parm.ctx = ctx;
  parm.ctrl = ctrl;
  init_membuf (&parm.plaintext, 512);
  if (conttype == CONTTYPE_DM_CRYPT)
    {
      err = assuan_transact (ctx, "CREATE dm-crypt",
                             create_data_cb, &parm,
                             create_inq_cb, &parm,
                             create_status_cb, &parm);
    }
  else
    {
      log_error ("invalid backend type %d given\n", conttype);
      err = GPG_ERR_INTERNAL;
      goto leave;
    }

 leave:
  xfree (get_membuf (&parm.plaintext, NULL));
  return err;
}



static gpg_error_t
mount_status_cb (void *opaque, const char *line)
{
  struct mount_parm_s *parm = opaque;
  const char *s;

  (void)parm;

  if ((s=has_leading_keyword (line, "PLAINDEV")))
    {
      if (opt.verbose || opt.no_mount)
        log_info ("Device: %s\n", s);
    }

  return 0;
}


/* Inquire callback for MOUNT and RESUME.  */
static gpg_error_t
mount_inq_cb (void *opaque, const char *line)
{
  struct mount_parm_s *parm = opaque;
  gpg_error_t err;

  if (has_leading_keyword (line, "KEYBLOB"))
    {
      int setconfidential = !assuan_get_flag (parm->ctx, ASSUAN_CONFIDENTIAL);

      if (setconfidential)
        assuan_begin_confidential (parm->ctx);
      err = assuan_send_data (parm->ctx, parm->keyblob, parm->keybloblen);
      if (setconfidential)
        assuan_end_confidential (parm->ctx);
      if (err)
        log_error ("sending keyblob to g13-syshelp failed: %s\n",
                   gpg_strerror (err));
    }
  else
    err = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);

  return err;
}


/*
 * Run the MOUNT command on the current device.  CONTTYPES gives the
 * requested content type for the new container.  MOUNTPOINT the
 * desired mount point or NULL for default.
 */
gpg_error_t
call_syshelp_run_mount (ctrl_t ctrl, int conttype, const char *mountpoint,
                        tupledesc_t tuples)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct mount_parm_s parm;

  memset (&parm, 0, sizeof parm);

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  /* tty_get ("waiting for debugger"); */
  /* tty_kill_prompt (); */

  parm.ctx = ctx;
  parm.ctrl = ctrl;
  if (conttype == CONTTYPE_DM_CRYPT)
    {
      ref_tupledesc (tuples);
      parm.keyblob = get_tupledesc_data (tuples, &parm.keybloblen);
      err = assuan_transact (ctx,
                             (opt.no_mount
                              ? "MOUNT --no-mount dm-crypt"
                              : "MOUNT dm-crypt"),
                             NULL, NULL,
                             mount_inq_cb, &parm,
                             mount_status_cb, &parm);
      unref_tupledesc (tuples);
    }
  else
    {
      (void)mountpoint; /* Not used.  */
      log_error ("invalid backend type %d given\n", conttype);
      err = GPG_ERR_INTERNAL;
      goto leave;
    }

 leave:
  return err;
}



/*
 * Run the UMOUNT command on the current device.  CONTTYPES gives the
 * content type of the container (fixme: Do we really need this?).
 */
gpg_error_t
call_syshelp_run_umount (ctrl_t ctrl, int conttype)
{
  gpg_error_t err;
  assuan_context_t ctx;

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  if (conttype == CONTTYPE_DM_CRYPT)
    {
      err = assuan_transact (ctx, "UMOUNT dm-crypt",
                             NULL, NULL,
                             NULL, NULL,
                             NULL, NULL);
    }
  else
    {
      log_error ("invalid backend type %d given\n", conttype);
      err = GPG_ERR_INTERNAL;
      goto leave;
    }

 leave:
  return err;
}



/*
 * Run the SUSPEND command on the current device.  CONTTYPES gives the
 * requested content type for the new container.
 */
gpg_error_t
call_syshelp_run_suspend (ctrl_t ctrl, int conttype)
{
  gpg_error_t err;
  assuan_context_t ctx;

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  if (conttype == CONTTYPE_DM_CRYPT)
    {
      err = assuan_transact (ctx, "SUSPEND dm-crypt",
                             NULL, NULL,
                             NULL, NULL,
                             NULL, NULL);
    }
  else
    {
      log_error ("invalid backend type %d given\n", conttype);
      err = GPG_ERR_INTERNAL;
      goto leave;
    }

 leave:
  return err;
}



/* Run the RESUME command on the current device.  CONTTYPES gives the
   requested content type for the container.  */
gpg_error_t
call_syshelp_run_resume (ctrl_t ctrl, int conttype, tupledesc_t tuples)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct mount_parm_s parm;

  memset (&parm, 0, sizeof parm);

  err = start_syshelp (ctrl, &ctx);
  if (err)
    goto leave;

  /* tty_get ("waiting for debugger"); */
  /* tty_kill_prompt (); */

  parm.ctx = ctx;
  parm.ctrl = ctrl;
  if (conttype == CONTTYPE_DM_CRYPT)
    {
      ref_tupledesc (tuples);
      parm.keyblob = get_tupledesc_data (tuples, &parm.keybloblen);
      err = assuan_transact (ctx, "RESUME dm-crypt",
                             NULL, NULL,
                             mount_inq_cb, &parm,
                             NULL, NULL);
      unref_tupledesc (tuples);
    }
  else
    {
      log_error ("invalid backend type %d given\n", conttype);
      err = GPG_ERR_INTERNAL;
      goto leave;
    }

 leave:
  return err;
}
