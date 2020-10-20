/* mount.c - Mount a crypto container
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#include "g13.h"
#include "../common/i18n.h"
#include "mount.h"

#include "keyblob.h"
#include "backend.h"
#include "g13tuple.h"
#include "mountinfo.h"
#include "runner.h"
#include "../common/host2net.h"
#include "server.h"  /*(g13_keyblob_decrypt)*/
#include "../common/sysutils.h"
#include "call-syshelp.h"


/* Mount the container with name FILENAME at MOUNTPOINT.  */
gpg_error_t
g13_mount_container (ctrl_t ctrl, const char *filename, const char *mountpoint)
{
  gpg_error_t err;
  dotlock_t lock;
  int needs_syshelp = 0;
  void *enckeyblob = NULL;
  size_t enckeybloblen;
  void *keyblob = NULL;
  size_t keybloblen;
  tupledesc_t tuples = NULL;
  size_t n;
  const unsigned char *value;
  int conttype;
  unsigned int rid;
  char *mountpoint_buffer = NULL;
  char *blockdev_buffer = NULL;

  /* Decide whether we need to use the g13-syshelp.  */
  err = call_syshelp_find_device (ctrl, filename, &blockdev_buffer);
  if (!err)
    {
      needs_syshelp = 1;
      filename = blockdev_buffer;
    }
  else if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    {
      log_error ("error finding device '%s': %s <%s>\n",
                 filename, gpg_strerror (err), gpg_strsource (err));
      return err;
    }
  else
    {
      /* A quick check to see whether we can the container exists.  */
      if (gnupg_access (filename, R_OK))
        return gpg_error_from_syserror ();
    }

  if (!mountpoint)
    {
      mountpoint_buffer = xtrystrdup ("/tmp/g13-XXXXXX");
      if (!mountpoint_buffer)
        return gpg_error_from_syserror ();
      if (!gnupg_mkdtemp (mountpoint_buffer))
        {
          err = gpg_error_from_syserror ();
          log_error (_("can't create directory '%s': %s\n"),
                     "/tmp/g13-XXXXXX", gpg_strerror (err));
          xfree (mountpoint_buffer);
          return err;
        }
      mountpoint = mountpoint_buffer;
    }

  err = 0;
  if (needs_syshelp)
    lock = NULL;
  else
    {
      /* Try to take a lock.  */
      lock = dotlock_create (filename, 0);
      if (!lock)
        {
          xfree (mountpoint_buffer);
          return gpg_error_from_syserror ();
        }

      if (dotlock_take (lock, 0))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* Check again that the file exists.  */
  if (!needs_syshelp)
    {
      struct stat sb;

      if (gnupg_stat (filename, &sb))
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* Read the encrypted keyblob.  */
  if (needs_syshelp)
    {
      err = call_syshelp_set_device (ctrl, filename);
      if (err)
        goto leave;
      err = call_syshelp_get_keyblob (ctrl, &enckeyblob, &enckeybloblen);
    }
  else
    err = g13_keyblob_read (filename, &enckeyblob, &enckeybloblen);
  if (err)
    goto leave;

  /* Decrypt that keyblob and store it in a tuple descriptor.  */
  err = g13_keyblob_decrypt (ctrl, enckeyblob, enckeybloblen,
                             &keyblob, &keybloblen);
  if (err)
    goto leave;
  xfree (enckeyblob);
  enckeyblob = NULL;

  err = create_tupledesc (&tuples, keyblob, keybloblen);
  if (!err)
    keyblob = NULL;
  else
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_SUPPORTED)
        log_error ("unknown keyblob version\n");
      goto leave;
    }
  if (opt.verbose)
    dump_tupledesc (tuples);

  value = find_tuple (tuples, KEYBLOB_TAG_CONTTYPE, &n);
  if (!value || n != 2)
    conttype = 0;
  else
    conttype = (value[0] << 8 | value[1]);
  if (!be_is_supported_conttype (conttype))
    {
      log_error ("content type %d is not supported\n", conttype);
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }
  err = be_mount_container (ctrl, conttype, filename, mountpoint, tuples, &rid);
  if (err)
    ;
  else if (conttype == CONTTYPE_DM_CRYPT)
    g13_request_shutdown ();
  else
    {
      /* Unless this is a DM-CRYPT mount we put it into our mounttable
         so that we can manage the mounts ourselves.  For dm-crypt we
         do not keep a process to monitor he mounts (for now).  */
      err = mountinfo_add_mount (filename, mountpoint, conttype, rid,
                                 !!mountpoint_buffer);
      /* Fixme: What shall we do if this fails?  Add a provisional
         mountinfo entry first and remove it on error? */
      if (!err)
        {
          char *tmp = percent_plus_escape (mountpoint);
          if (!tmp)
            err = gpg_error_from_syserror ();
          else
            {
              g13_status (ctrl, STATUS_MOUNTPOINT, tmp, NULL);
              xfree (tmp);
            }
        }
    }

 leave:
  destroy_tupledesc (tuples);
  xfree (keyblob);
  xfree (enckeyblob);
  dotlock_destroy (lock);
  xfree (mountpoint_buffer);
  xfree (blockdev_buffer);
  return err;
}


/* Unmount the container with name FILENAME or the one mounted at
   MOUNTPOINT.  If both are given the FILENAME takes precedence.  */
gpg_error_t
g13_umount_container (ctrl_t ctrl, const char *filename, const char *mountpoint)
{
  gpg_error_t err;
  char *blockdev;

  if (!filename && !mountpoint)
    return gpg_error (GPG_ERR_ENOENT);

  /* Decide whether we need to use the g13-syshelp.  */
  err = call_syshelp_find_device (ctrl, filename, &blockdev);
  if (!err)
    {
      /* Need to employ the syshelper to umount the file system.  */
      /* FIXME: We should get the CONTTYPE from the blockdev.  */
      err = be_umount_container (ctrl, CONTTYPE_DM_CRYPT, blockdev);
      if (!err)
        {
          /* if (conttype == CONTTYPE_DM_CRYPT) */
          g13_request_shutdown ();
        }
    }
  else if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    {
      log_error ("error finding device '%s': %s <%s>\n",
                 filename, gpg_strerror (err), gpg_strsource (err));
    }
  else
    {
      /* Not in g13tab - kill the runner process for this mount.  */
      unsigned int rid;
      runner_t runner;

      err = mountinfo_find_mount (filename, mountpoint, &rid);
      if (err)
        return err;

      runner = runner_find_by_rid (rid);
      if (!runner)
        {
          log_error ("runner %u not found\n", rid);
          return gpg_error (GPG_ERR_NOT_FOUND);
        }

      runner_cancel (runner);
      runner_release (runner);
    }

  xfree (blockdev);
  return err;
}
