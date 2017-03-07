/* suspend.c - Suspend/Resume a crypto container
 * Copyright (C) 2016 Werner Koch
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
#include "suspend.h"

#include "keyblob.h"
#include "backend.h"
#include "g13tuple.h"
#include "server.h"  /*(g13_keyblob_decrypt)*/



/* Suspend the container with name FILENAME.  */
gpg_error_t
g13_suspend_container (ctrl_t ctrl, const char *filename)
{
  gpg_error_t err;
  int needs_syshelp;

  /* A quick check to see whether the container exists.  */
  if (access (filename, R_OK))
    return gpg_error_from_syserror ();

  /* Decide whether we need to use the g13-syshelp because we can't
     use lock files for them.  This is most likely the case for device
     files; thus we test for this.  FIXME: The correct solution would
     be to call g13-syshelp to match the file against the g13tab.  */
  needs_syshelp = !strncmp (filename, "/dev/", 5);

  if (!needs_syshelp)
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    err = be_suspend_container (ctrl, CONTTYPE_DM_CRYPT, filename);

  return err;
}


/* Resume the container with name FILENAME.  */
gpg_error_t
g13_resume_container (ctrl_t ctrl, const char *filename)
{
  gpg_error_t err;
  int needs_syshelp;
  void *enckeyblob = NULL;
  size_t enckeybloblen;
  void *keyblob = NULL;
  size_t keybloblen;
  tupledesc_t tuples = NULL;
  size_t n;
  const unsigned char *value;
  int conttype;
  char *mountpoint_buffer = NULL;

  /* A quick check to see whether the container exists.  */
  if (access (filename, R_OK))
    return gpg_error_from_syserror ();

  /* Decide whether we need to use the g13-syshelp because we can't
     use lock files for them.  This is most likely the case for device
     files; thus we test for this.  FIXME: The correct solution would
     be to call g13-syshelp to match the file against the g13tab.  */
  needs_syshelp = !strncmp (filename, "/dev/", 5);

  if (!needs_syshelp)
    {
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  /* Read the encrypted keyblob.  */
  /* Fixme: Should we move this to syshelp for dm-crypt or do we
     assume that the encrypted device is world readable?  */
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
  err = be_resume_container (ctrl, conttype, filename, tuples);

 leave:
  destroy_tupledesc (tuples);
  xfree (keyblob);
  xfree (enckeyblob);
  xfree (mountpoint_buffer);
  return err;
}
