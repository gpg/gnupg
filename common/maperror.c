/* maperror.c - Error mapping
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <ksba.h>
#include <assuan.h>

#include "util.h"
#include "errors.h"


/* Map Assuan error code ERR to an GPG_ERR_ code.  We need to
   distinguish between genuine (and legacy) Assuan error codes and
   application error codes shared with all GnuPG modules.  The rule is
   simple: All errors with a gpg_err_source of UNKNOWN are genuine
   Assuan codes all others are passed verbatim through. */
gpg_error_t
map_assuan_err (int err)
{
  gpg_err_code_t ec;

  if (gpg_err_source (err))
    return err;

  switch (err)
    {
    case -1:                     ec = GPG_ERR_EOF; break;
    case 0:                      ec = 0; break;

    case ASSUAN_Canceled:        ec = GPG_ERR_CANCELED; break;
    case ASSUAN_Invalid_Index:   ec = GPG_ERR_INV_INDEX; break;

    case ASSUAN_Not_Implemented: ec = GPG_ERR_NOT_IMPLEMENTED; break;
    case ASSUAN_Server_Fault:    ec = GPG_ERR_ASSUAN_SERVER_FAULT; break;
    case ASSUAN_No_Public_Key:   ec = GPG_ERR_NO_PUBKEY; break;
    case ASSUAN_No_Secret_Key:   ec = GPG_ERR_NO_SECKEY; break;

    case ASSUAN_Cert_Revoked:    ec = GPG_ERR_CERT_REVOKED; break;
    case ASSUAN_No_CRL_For_Cert: ec = GPG_ERR_NO_CRL_KNOWN; break;       
    case ASSUAN_CRL_Too_Old:     ec = GPG_ERR_CRL_TOO_OLD; break;        

    case ASSUAN_Not_Trusted:     ec = GPG_ERR_NOT_TRUSTED; break;

    case ASSUAN_Card_Error:      ec = GPG_ERR_CARD; break;
    case ASSUAN_Invalid_Card:    ec = GPG_ERR_INV_CARD; break;
    case ASSUAN_No_PKCS15_App:   ec = GPG_ERR_NO_PKCS15_APP; break;
    case ASSUAN_Card_Not_Present: ec= GPG_ERR_CARD_NOT_PRESENT; break;
    case ASSUAN_Not_Confirmed:   ec = GPG_ERR_NOT_CONFIRMED; break;
    case ASSUAN_Invalid_Id:      ec = GPG_ERR_INV_ID; break;

#if 0 /* FIXME: Enable this after releasing libgpg error 0.7 */
    case ASSUAN_Locale_Problem:  ec = GPG_ERR_LOCALE_PROBLEM; break;
#endif

    default:
      ec = err < 100? GPG_ERR_ASSUAN_SERVER_FAULT : GPG_ERR_ASSUAN;
      break;
    }
  return gpg_err_make (GPG_ERR_SOURCE_UNKNOWN, ec);
}

/* Map GPG_xERR_xx error codes to Assuan status codes */
int
map_to_assuan_status (int rc)
{
  gpg_err_code_t   ec = gpg_err_code (rc);
  gpg_err_source_t es = gpg_err_source (rc);

  if (!rc)
    return 0;
  if (!es)
    {
      es = GPG_ERR_SOURCE_USER_4; /*  This should not happen, but we
                                      need to make sure to pass a new
                                      Assuan errorcode along. */
      log_debug ("map_to_assuan_status called with no error source\n");
    }

  if (ec == -1)
    ec = GPG_ERR_NO_DATA;  /* That used to be ASSUAN_No_Data_Available. */

  return gpg_err_make (es, ec);
}
