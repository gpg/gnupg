/* backend.c - Dispatcher to the various backends.
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

#include "g13.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "keyblob.h"
#include "backend.h"
#include "be-encfs.h"
#include "be-truecrypt.h"
#include "be-dmcrypt.h"
#include "call-syshelp.h"

#define no_such_backend(a) _no_such_backend ((a), __func__)
static gpg_error_t
_no_such_backend (int conttype, const char *func)
{
  log_error ("invalid backend %d given in %s - this is most likely a bug\n",
             conttype, func);
  return gpg_error (GPG_ERR_INTERNAL);
}


/* Parse NAME and return the corresponding content type.  If the name
   is not known, a error message is printed and zero returned.  If
   NAME is NULL the supported backend types are listed and 0 is
   returned. */
int
be_parse_conttype_name (const char *name)
{
  static struct { const char *name; int conttype; } names[] = {
    { "encfs",    CONTTYPE_ENCFS },
    { "dm-crypt", CONTTYPE_DM_CRYPT }
  };
  int i;

  if (!name)
    {
      log_info ("Known backend types:\n");
      for (i=0; i < DIM (names); i++)
        log_info ("    %s\n", names[i].name);
      return 0;
    }

  for (i=0; i < DIM (names); i++)
    {
      if (!strcmp (names[i].name, name))
        return names[i].conttype;
    }

  log_error ("invalid backend type '%s' given\n", name);
  return 0;
}


/* Return true if CONTTYPE is supported by us.  */
int
be_is_supported_conttype (int conttype)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
    case CONTTYPE_DM_CRYPT:
      return 1;

    default:
      return 0;
    }
}


/* Create a lock file for the container FNAME and store the lock at
 * R_LOCK and return 0.  On error return an error code and store NULL
 * at R_LOCK.  */
gpg_error_t
be_take_lock_for_create (ctrl_t ctrl, const char *fname, dotlock_t *r_lock)
{
  gpg_error_t err;
  dotlock_t lock = NULL;
  struct stat sb;

  *r_lock = NULL;

  /* A DM-crypt container requires special treatment by using the
     syshelper functions.  */
  if (ctrl->conttype == CONTTYPE_DM_CRYPT)
    {
      /*  */
      err = call_syshelp_set_device (ctrl, fname);
      goto leave;
    }


  /* A quick check to see that no container with that name already
     exists.  */
  if (!gnupg_access (fname, F_OK))
    {
      err = gpg_error (GPG_ERR_EEXIST);
      goto leave;
    }

  /* Take a lock and proceed with the creation.  If there is a lock we
     immediately return an error because for creation it does not make
     sense to wait.  */
  lock = dotlock_create (fname, 0);
  if (!lock)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (dotlock_take (lock, 0))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Check again that the file does not exist.  */
  err = gnupg_stat (fname, &sb)? 0 : gpg_error (GPG_ERR_EEXIST);

 leave:
  if (!err)
    {
      *r_lock = lock;
      lock = NULL;
    }
  dotlock_destroy (lock);
  return err;
}


/* If the backend requires a separate file or directory for the
   container, return its name by computing it from FNAME which gives
   the g13 filename.  The new file name is allocated and stored at
   R_NAME, if this is expected to be a directory true is stored at
   R_ISDIR.  If no detached name is expected or an error occurs NULL
   is stored at R_NAME. The function returns 0 on success or an error
   code.  */
gpg_error_t
be_get_detached_name (int conttype, const char *fname,
                      char **r_name, int *r_isdir)
{
  *r_name = NULL;
  *r_isdir = 0;
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return be_encfs_get_detached_name (fname, r_name, r_isdir);

    case CONTTYPE_DM_CRYPT:
      return 0;

    default:
      return no_such_backend (conttype);
    }
}


gpg_error_t
be_create_new_keys (int conttype, membuf_t *mb)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return be_encfs_create_new_keys (mb);

    case CONTTYPE_TRUECRYPT:
      return be_truecrypt_create_new_keys (mb);

    case CONTTYPE_DM_CRYPT:
      return 0;

    default:
      return no_such_backend (conttype);
    }
}


/* Dispatcher to the backend's create function.  */
gpg_error_t
be_create_container (ctrl_t ctrl, int conttype,
                     const char *fname, int fd, tupledesc_t tuples,
                     unsigned int *r_id)
{
  (void)fd;  /* Not yet used.  */

  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return be_encfs_create_container (ctrl, fname, tuples, r_id);

    case CONTTYPE_DM_CRYPT:
      return be_dmcrypt_create_container (ctrl);

    default:
      return no_such_backend (conttype);
    }
}


/* Dispatcher to the backend's mount function.  */
gpg_error_t
be_mount_container (ctrl_t ctrl, int conttype,
                    const char *fname,  const char *mountpoint,
                    tupledesc_t tuples, unsigned int *r_id)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return be_encfs_mount_container (ctrl, fname, mountpoint, tuples, r_id);

    case CONTTYPE_DM_CRYPT:
      return be_dmcrypt_mount_container (ctrl, fname, mountpoint, tuples);

    default:
      return no_such_backend (conttype);
    }
}


/* Dispatcher to the backend's umount function.  */
gpg_error_t
be_umount_container (ctrl_t ctrl, int conttype, const char *fname)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return gpg_error (GPG_ERR_NOT_SUPPORTED);

    case CONTTYPE_DM_CRYPT:
      return be_dmcrypt_umount_container (ctrl, fname);

    default:
      return no_such_backend (conttype);
    }
}


/* Dispatcher to the backend's suspend function.  */
gpg_error_t
be_suspend_container (ctrl_t ctrl, int conttype, const char *fname)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return gpg_error (GPG_ERR_NOT_SUPPORTED);

    case CONTTYPE_DM_CRYPT:
      return be_dmcrypt_suspend_container (ctrl, fname);

    default:
      return no_such_backend (conttype);
    }
}


/* Dispatcher to the backend's resume function.  */
gpg_error_t
be_resume_container (ctrl_t ctrl, int conttype, const char *fname,
                     tupledesc_t tuples)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return gpg_error (GPG_ERR_NOT_SUPPORTED);

    case CONTTYPE_DM_CRYPT:
      return be_dmcrypt_resume_container (ctrl, fname, tuples);

    default:
      return no_such_backend (conttype);
    }
}
