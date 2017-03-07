/* ks-engine-kdns.c - KDNS OpenPGP key access
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "dirmngr.h"
#include "misc.h"
#include "../common/userids.h"
#include "ks-engine.h"

/* Print a help output for the schemata supported by this module. */
gpg_error_t
ks_kdns_help (ctrl_t ctrl, parsed_uri_t uri)
{
  const char data[] =
    "This keyserver engine accepts URLs of the form:\n"
    "  kdns://[NAMESERVER]/[ROOT][?at=STRING]\n"
    "with\n"
    "  NAMESERVER  used for queries (default: system standard)\n"
    "  ROOT        a DNS name appended to the query (default: none)\n"
    "  STRING      a string to replace the '@' (default: \".\")\n"
    "If a long answer is expected add the parameter \"usevc=1\".\n"
    "Supported methods: fetch\n"
    "Example:\n"
    "A query for \"hacker@gnupg.org\" with\n"
    "  kdns://10.0.0.1/example.net?at=_key_&usevc=1\n"
    "setup as --auto-key-lookup in gpg does a CERT record query\n"
    "with type PGP on the nameserver 10.0.0.1 for\n"
    "  hacker._key_.gnupg.org.example.net";
  gpg_error_t err;

  if (!uri)
    err = ks_print_help (ctrl, "  kdns");
  else if (!strcmp (uri->scheme, "kdns"))
    err = ks_print_help (ctrl, data);
  else
    err = 0;

  return err;
}


/* Get the key from URI which is expected to specify a kdns scheme.
   On success R_FP has an open stream to read the data.  */
gpg_error_t
ks_kdns_fetch (ctrl_t ctrl, parsed_uri_t uri, estream_t *r_fp)
{
  gpg_error_t err;

  (void)ctrl;
  *r_fp = NULL;

  if (strcmp (uri->scheme, "kdns"))
    return gpg_error (GPG_ERR_INV_ARG);

  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  return err;
}
