/* status.c - status code helper functions
 *	Copyright (C) 2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>

#include "util.h"
#include "status.h"
#include "status-codes.h"


/* Return the status string for code NO. */
const char *
get_status_string ( int no )
{
  int idx = statusstr_msgidxof (no);
  if (idx == -1)
    return "?";
  else
    return statusstr_msgstr + statusstr_msgidx[idx];
}


const char *
get_inv_recpsgnr_code (gpg_error_t err)
{
  const char *errstr;

  switch (gpg_err_code (err))
    {
    case GPG_ERR_NO_PUBKEY:       errstr = "1"; break;
    case GPG_ERR_AMBIGUOUS_NAME:  errstr = "2"; break;
    case GPG_ERR_WRONG_KEY_USAGE: errstr = "3"; break;
    case GPG_ERR_CERT_REVOKED:    errstr = "4"; break;
    case GPG_ERR_CERT_EXPIRED:    errstr = "5"; break;
    case GPG_ERR_NO_CRL_KNOWN:    errstr = "6"; break;
    case GPG_ERR_CRL_TOO_OLD:     errstr = "7"; break;
    case GPG_ERR_NO_POLICY_MATCH: errstr = "8"; break;

    case GPG_ERR_UNUSABLE_SECKEY:
    case GPG_ERR_NO_SECKEY:       errstr = "9"; break;

    case GPG_ERR_NOT_TRUSTED:     errstr = "10"; break;
    case GPG_ERR_MISSING_CERT:    errstr = "11"; break;
    case GPG_ERR_MISSING_ISSUER_CERT: errstr = "12"; break;
    default:                      errstr = "0"; break;
    }

  return errstr;
}
