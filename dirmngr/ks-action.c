/* ks-action.c - OpenPGP keyserver actions
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <assert.h>

#include "dirmngr.h"
#include "misc.h"
#include "ks-engine.h"
#include "ks-action.h"


/* Copy all data from IN to OUT.  */
static gpg_error_t
copy_stream (estream_t in, estream_t out)
{
  char buffer[512];
  size_t nread;

  while (!es_read (in, buffer, sizeof buffer, &nread))
    {
      if (!nread)
        return 0; /* EOF */
      if (es_write (out, buffer, nread, NULL))
        break;

    }
  return gpg_error_from_syserror ();
}



/* Search all configured keyservers for keys matching PATTERNS and
   write the result to the provided output stream.  */
gpg_error_t
ks_action_search (ctrl_t ctrl, strlist_t patterns, estream_t outfp)
{
  gpg_error_t err = 0;
  int any = 0;
  uri_item_t uri;
  estream_t infp;

  if (!patterns)
    return gpg_error (GPG_ERR_NO_USER_ID);

  /* FIXME: We only take care of the first pattern.  To fully support
     multiple patterns we might either want to run several queries in
     parallel and merge them.  We also need to decide what to do with
     errors - it might not be the best idea to ignore an error from
     one server and silently continue with another server.  For now we
     stop at the first error. */
  for (uri = ctrl->keyservers; !err && uri; uri = uri->next)
    {
      if (uri->parsed_uri->is_http)
        {
          any = 1;
          err = ks_hkp_search (ctrl, uri->parsed_uri, patterns->d, &infp);
          if (!err)
            {
              err = copy_stream (infp, outfp);
              es_fclose (infp);
            }
        }
    }

  if (!any)
    err = gpg_error (GPG_ERR_NO_KEYSERVER);
  return err;
}

