/* sh-blockdev.c - Block device functions for g13-syshelp
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
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include "g13-syshelp.h"
#include <assuan.h>
#include "../common/i18n.h"
#include "../common/exectool.h"
#include "keyblob.h"

#ifndef HAVE_STRTOULL
# error building this tool requires strtoull(3)
#endif
#ifndef ULLONG_MAX
# error ULLONG_MAX missing
#endif


/* Return the size measured in the number of 512 byte sectors for the
   block device NAME.  */
gpg_error_t
sh_blockdev_getsz (const char *name, unsigned long long *r_nblocks)
{
  gpg_error_t err;
  const char *argv[3];
  char *result;

  *r_nblocks = 0;
  argv[0] = "--getsz";
  argv[1] = name;
  argv[2] = NULL;
  err = gnupg_exec_tool ("/sbin/blockdev", argv, NULL, &result, NULL);
  if (!err)
    {
      gpg_err_set_errno (0);
      *r_nblocks = strtoull (result, NULL, 10);
      if (*r_nblocks == ULLONG_MAX && errno)
        {
          err = gpg_error_from_syserror ();
          *r_nblocks = 0;
        }
      xfree (result);
    }
  return err;
}


/* Return 0 if the device NAME looks like an empty partition. */
gpg_error_t
sh_is_empty_partition (const char *name)
{
  gpg_error_t err;
  const char *argv[6];
  char *buffer;
  estream_t fp;
  char *p;
  size_t nread;

  argv[0] = "-o";
  argv[1] = "value";
  argv[2] = "-s";
  argv[3] = "UUID";
  argv[4] = name;
  argv[5] = NULL;
  err = gnupg_exec_tool ("/sbin/blkid", argv, NULL, &buffer, NULL);
  if (err)
    return gpg_error (GPG_ERR_FALSE);
  if (*buffer)
    {
      /* There seems to be an UUID - thus we have a file system.  */
      xfree (buffer);
      return gpg_error (GPG_ERR_FALSE);
    }
  xfree (buffer);

  argv[0] = "-o";
  argv[1] = "value";
  argv[2] = "-s";
  argv[3] = "PARTUUID";
  argv[4] = name;
  argv[5] = NULL;
  err = gnupg_exec_tool ("/sbin/blkid", argv, NULL, &buffer, NULL);
  if (err)
    return gpg_error (GPG_ERR_FALSE);
  if (!*buffer)
    {
      /* If there is no PARTUUID we assume that name has already a
         mapped partition.  */
      xfree (buffer);
      return gpg_error (GPG_ERR_FALSE);
    }
  xfree (buffer);

  /* As a safeguard we require that the first 32k of a partition are
     all zero before we assume the partition is empty.  */
  buffer = xtrymalloc (32 * 1024);
  if (!buffer)
    return gpg_error_from_syserror ();
  fp = es_fopen (name, "rb,samethread");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error opening '%s': %s\n", name, gpg_strerror (err));
      xfree (buffer);
      return gpg_error (GPG_ERR_FALSE);
    }
  if (es_read (fp, buffer, 32 * 1024, &nread))
    err = gpg_error_from_syserror ();
  else if (nread != 32 *1024)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else
    err = 0;
  es_fclose (fp);
  if (err)
    {
      log_error ("error reading the first 32 KiB from '%s': %s\n",
                 name, gpg_strerror (err));
      xfree (buffer);
      return err;
    }
  for (p=buffer; nread && !*p; nread--, p++)
    ;
  xfree (buffer);
  if (nread)
    return gpg_error (GPG_ERR_FALSE);  /* No all zeroes.  */

  return 0;
}
