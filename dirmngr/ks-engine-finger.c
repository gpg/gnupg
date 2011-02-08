/* ks-engine-finger.c - HKP keyserver engine
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
#include "userids.h"
#include "ks-engine.h"


/* Get the key from URI which is expected to specify a finger scheme.
   On success R_FP has an open stream to read the data.  */
gpg_error_t
ks_finger_get (ctrl_t ctrl, parsed_uri_t uri, estream_t *r_fp)
{
  gpg_error_t err;
  estream_t fp;
  char *server;
  char *name;
  http_t http;

  (void)ctrl;
  *r_fp = NULL;

  if (strcmp (uri->scheme, "finger") || !uri->opaque || !uri->path)
    return gpg_error (GPG_ERR_INV_ARG);

  name = xtrystrdup (uri->path);
  if (!name)
    return gpg_error_from_syserror ();

  server = strchr (name, '@');
  if (!server)
    {
      err = gpg_error (GPG_ERR_INV_URI);
      xfree (name);
      return err;
    }
  *server++ = 0;

  err = http_raw_connect (&http, server, 79, 0, NULL);
  if (err)
    {
      xfree (name);
      return err;
    }

  fp = http_get_write_ptr (http);
  if (!fp)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      http_close (http, 0);
      xfree (name);
      return err;
    }

  if (es_fputs (name, fp) || es_fputs ("\r\n", fp) || es_fflush (fp))
    {
      err = gpg_error_from_syserror ();
      http_close (http, 0);
      xfree (name);
      return err;
    }
  xfree (name);
  es_fclose (fp);

  fp = http_get_read_ptr (http);
  if (!fp)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      http_close (http, 0);
      return err;
    }

  http_close (http, 1 /* Keep read ptr.  */);

  *r_fp = fp;
  return 0;
}
