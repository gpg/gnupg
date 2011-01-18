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
              break;
            }
        }
    }

  if (!any)
    err = gpg_error (GPG_ERR_NO_KEYSERVER);
  return err;
}


/* Get the requested keys (macthing PATTERNS) using all configured
   keyservers and write the result to the provided output stream.  */
gpg_error_t
ks_action_get (ctrl_t ctrl, strlist_t patterns, estream_t outfp)
{
  gpg_error_t err = 0;
  gpg_error_t first_err = 0;
  int any = 0;
  strlist_t sl;
  uri_item_t uri;
  estream_t infp;

  if (!patterns)
    return gpg_error (GPG_ERR_NO_USER_ID);

  /* FIXME: We only take care of the first keyserver.  To fully
     support multiple keyservers we need to track the result for each
     pattern and use the next keyserver if one key was not found.  The
     keyservers might not all be fully synced thus it is not clear
     whether the first keyserver has the freshest copy of the key.
     Need to think about a better strategy.  */
  for (uri = ctrl->keyservers; !err && uri; uri = uri->next)
    {
      if (uri->parsed_uri->is_http)
        {
          any = 1;
          for (sl = patterns; !err && sl; sl = sl->next)
            {
              err = ks_hkp_get (ctrl, uri->parsed_uri, sl->d, &infp);
              if (err)
                {
                  /* It is possible that a server does not carry a
                     key, thus we only save the error and continue
                     with the next pattern.  FIXME: It is an open
                     question how to return such an error condition to
                     the caller.  */
                  first_err = err;
                  err = 0;
                }
              else
                {
                  err = copy_stream (infp, outfp);
                  /* Reading from the keyserver should nver fail, thus
                     return this error.  */
                  es_fclose (infp);
                  infp = NULL;
                }
            }
        }
    }

  if (!any)
    err = gpg_error (GPG_ERR_NO_KEYSERVER);
  else if (!err && first_err)
    err = first_err; /* fixme: Do we really want to do that?  */
  return err;
}

