/* errors.h - Globally used error codes
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_ERRORS_H
#define GNUPG_COMMON_ERRORS_H

#include "util.h"

/* Status codes - fixme: should go into another file */
enum {
  STATUS_ENTER,
  STATUS_LEAVE,
  STATUS_ABORT,
  STATUS_GOODSIG,
  STATUS_BADSIG,
  STATUS_ERRSIG,
  STATUS_BADARMOR,
  STATUS_RSA_OR_IDEA,
  STATUS_SIGEXPIRED,
  STATUS_KEYREVOKED,
  STATUS_TRUST_UNDEFINED,
  STATUS_TRUST_NEVER,
  STATUS_TRUST_MARGINAL,
  STATUS_TRUST_FULLY,
  STATUS_TRUST_ULTIMATE,
  
  STATUS_SHM_INFO,
  STATUS_SHM_GET,
  STATUS_SHM_GET_BOOL,
  STATUS_SHM_GET_HIDDEN,
  
  STATUS_NEED_PASSPHRASE,
  STATUS_VALIDSIG,
  STATUS_SIG_ID,
  STATUS_ENC_TO,
  STATUS_NODATA,
  STATUS_BAD_PASSPHRASE,
  STATUS_NO_PUBKEY,
  STATUS_NO_SECKEY,
  STATUS_NEED_PASSPHRASE_SYM,
  STATUS_DECRYPTION_FAILED,
  STATUS_DECRYPTION_OKAY,
  STATUS_MISSING_PASSPHRASE,
  STATUS_GOOD_PASSPHRASE,
  STATUS_GOODMDC,
  STATUS_BADMDC,
  STATUS_ERRMDC,
  STATUS_IMPORTED,
  STATUS_IMPORT_OK,
  STATUS_IMPORT_PROBLEM,
  STATUS_IMPORT_RES,
  STATUS_FILE_START,
  STATUS_FILE_DONE,
  STATUS_FILE_ERROR,
  
  STATUS_BEGIN_DECRYPTION,
  STATUS_END_DECRYPTION,
  STATUS_BEGIN_ENCRYPTION,
  STATUS_END_ENCRYPTION,
  
  STATUS_DELETE_PROBLEM,
  STATUS_GET_BOOL,
  STATUS_GET_LINE,
  STATUS_GET_HIDDEN,
  STATUS_GOT_IT,
  STATUS_PROGRESS,
  STATUS_SIG_CREATED,
  STATUS_SESSION_KEY,
  STATUS_NOTATION_NAME,
  STATUS_NOTATION_DATA,
  STATUS_POLICY_URL,
  STATUS_BEGIN_STREAM,
  STATUS_END_STREAM,
  STATUS_KEY_CREATED,
  STATUS_USERID_HIN,
  STATUS_UNEXPECTED,
  STATUS_INV_RECP,
  STATUS_NO_RECP,
  STATUS_ALREADY_SIGNED,

  STATUS_EXPSIG,
  STATUS_EXPKEYSIG,

  STATUS_TRUNCATED,
  STATUS_ERROR,
  STATUS_NEWSIG
};


/*-- errors.c (build by mkerror and mkerrtok) --*/
const char *gnupg_strerror (int err);
const char *gnupg_error_token (int err);


#endif /*GNUPG_COMMON_ERRORS_H*/
