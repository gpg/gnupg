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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "g13.h"
#include "i18n.h"
#include "keyblob.h"
#include "backend.h"
#include "be-encfs.h"
#include "be-truecrypt.h"


static gpg_error_t
no_such_backend (int conttype)
{
  log_error ("invalid backend %d given - this is most likely a bug\n",
             conttype);
  return gpg_error (GPG_ERR_INTERNAL);
}


/* Return true if CONTTYPE is supported by us.  */
int
be_is_supported_conttype (int conttype)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return 1;

    default:
      return 0;
    }
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

    default:
      return no_such_backend (conttype);
    }
}


/*  Dispatcher to the backend's create function.  */
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

    default:
      return no_such_backend (conttype);
    }
}


/*  Dispatcher to the backend's mount function.  */
gpg_error_t
be_mount_container (ctrl_t ctrl, int conttype,
                    const char *fname,  const char *mountpoint,
                    tupledesc_t tuples, unsigned int *r_id)
{
  switch (conttype)
    {
    case CONTTYPE_ENCFS:
      return be_encfs_mount_container (ctrl, fname, mountpoint, tuples, r_id);

    default:
      return no_such_backend (conttype);
    }
}
