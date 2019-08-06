/* backend-support.c - Supporting functions for the backend.
 * Copyright (C) 2019 g10 Code GmbH
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

#include "keyboxd.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "backend.h"


/* Common definition part of all backend handle.  */
struct backend_handle_s
{
  enum database_types db_type;
};



/* Return a string with the name of the database type T.  */
const char *
strdbtype (enum database_types t)
{
  switch (t)
    {
    case DB_TYPE_NONE: return "none";
    case DB_TYPE_KBX:  return "keybox";
    }
  return "?";
}


/* Return a new backend ID.  Backend IDs are used to identify backends
 * without using the actual object.  The number of backend resources
 * is limited because they are specified in the config file.  Thus an
 * overflow check is not required.  */
unsigned int
be_new_backend_id (void)
{
  static unsigned int last;

  return ++last;
}


/* Release the backend described by HD.  This is a generic function
 * which dispatches to the the actual backend.  */
void
be_generic_release_backend (ctrl_t ctrl, backend_handle_t hd)
{
  if (!hd)
    return;
  switch (hd->db_type)
    {
    case DB_TYPE_NONE:
      xfree (hd);
      break;
    case DB_TYPE_KBX:
      be_kbx_release_resource (ctrl, hd);
      break;
    default:
      log_error ("%s: faulty backend handle of type %d given\n",
                 __func__, hd->db_type);
    }
}


/* Release the request object REQ.  */
void
be_release_request (db_request_t req)
{
  db_request_part_t part, partn;

  if (!req)
    return;

  for (part = req->part; part; part = partn)
    {
      partn = part->next;
      be_kbx_release_kbx_hd (part->kbx_hd);
      xfree (part);
    }
}


/* Return the public key (BUFFER,BUFLEN) which has the type
 * PUBVKEY_TYPE to the caller.  Owenership of BUFFER is taken by thgis
 * function even in the error case.  */
gpg_error_t
be_return_pubkey (ctrl_t ctrl, void *buffer, size_t buflen,
                  enum pubkey_types pubkey_type)
{
  gpg_error_t err;

  err = status_printf (ctrl, "PUBKEY_TYPE", "%d", pubkey_type);
  if (err)
    goto leave;

  if (ctrl->no_data_return)
    err = 0;
  else
    err = kbxd_write_data_line(ctrl, buffer, buflen);

 leave:
  xfree (buffer);
  return err;
}
