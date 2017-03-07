/* be-dmcrypt.c - The DM-Crypt based backend
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
#include <unistd.h>

#include "g13.h"
#include "../common/i18n.h"
#include "keyblob.h"
#include "call-syshelp.h"
#include "be-dmcrypt.h"


/* Create the container using the current device.
 * information in TUPLES. */
gpg_error_t
be_dmcrypt_create_container (ctrl_t ctrl)
{
  gpg_error_t err;

  err = call_syshelp_run_create (ctrl, CONTTYPE_DM_CRYPT);

  return err;
}


/* Mount the container described by the filename FNAME and the keyblob
 * information in TUPLES.  On success the runner id is stored at R_ID. */
gpg_error_t
be_dmcrypt_mount_container (ctrl_t ctrl,
                            const char *fname, const char *mountpoint,
                            tupledesc_t tuples)
{
  gpg_error_t err;

  err = call_syshelp_set_device (ctrl, fname);
  if (err)
    goto leave;

  err = call_syshelp_run_mount (ctrl, CONTTYPE_DM_CRYPT, mountpoint, tuples);

 leave:
  return err;
}


/* Unmount the container described by the filename FNAME.  */
gpg_error_t
be_dmcrypt_umount_container (ctrl_t ctrl, const char *fname)
{
  gpg_error_t err;

  err = call_syshelp_set_device (ctrl, fname);
  if (err)
    goto leave;

  err = call_syshelp_run_umount (ctrl, CONTTYPE_DM_CRYPT);

 leave:
  return err;
}


/* Suspend the container described by the filename FNAME.  */
gpg_error_t
be_dmcrypt_suspend_container (ctrl_t ctrl, const char *fname)
{
  gpg_error_t err;

  err = call_syshelp_set_device (ctrl, fname);
  if (err)
    goto leave;

  err = call_syshelp_run_suspend (ctrl, CONTTYPE_DM_CRYPT);

 leave:
  return err;
}


/* Resume the container described by the filename FNAME and the keyblob
 * information in TUPLES.  */
gpg_error_t
be_dmcrypt_resume_container (ctrl_t ctrl, const char *fname, tupledesc_t tuples)
{
  gpg_error_t err;

  err = call_syshelp_set_device (ctrl, fname);
  if (err)
    goto leave;

  err = call_syshelp_run_resume (ctrl, CONTTYPE_DM_CRYPT, tuples);

 leave:
  return err;
}
