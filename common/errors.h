/* errors.h - Globally used error codes
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_ERRORS_H
#define GNUPG_COMMON_ERRORS_H

#include "util.h"

/* Error numbers */
enum {
  GNUPG_EOF = -1,
  GNUPG_No_Error = 0,
  GNUPG_General_Error = 1, 
  GNUPG_Out_Of_Core = 2,
  GNUPG_Invalid_Value = 3,
  GNUPG_IO_Error = 4,
  GNUPG_Resource_Limit = 5,
  GNUPG_Internal_Error = 6,
  GNUPG_Bad_Certificate = 7,
  GNUPG_Bad_Certificate_Path = 8,
  GNUPG_Missing_Certificate = 9,
  GNUPG_No_Data = 10,
  GNUPG_Bad_Signature = 11,
  GNUPG_Not_Implemented = 12,
  GNUPG_Conflict = 13,
  GNUPG_Bug = 14,
  GNUPG_Read_Error = 15,
  GNUPG_Write_Error = 16,
  GNUPG_Incomplete_Line = 17,
  GNUPG_Invalid_Response = 18,
  GNUPG_No_Agent = 19,
  GNUPG_Agent_Error = 20,
  GNUPG_No_Public_Key = 21,
  GNUPG_No_Secret_Key = 22,
  GNUPG_File_Open_Error = 23,
  GNUPG_File_Create_Error = 24,
  GNUPG_File_Error = 25,
  GNUPG_Not_Supported = 26,
  GNUPG_Invalid_Data = 27,
  GNUPG_Assuan_Server_Fault = 28,
  GNUPG_Assuan_Error = 29, /* catch all assuan error */
  GNUPG_Invalid_Session_Key = 30,
  GNUPG_Invalid_Sexp = 31,
  GNUPG_Unsupported_Algorithm = 32,
  GNUPG_No_PIN_Entry = 33,
  GNUPG_PIN_Entry_Error = 34,
  GNUPG_Bad_PIN = 35,
  GNUPG_Bad_Passphrase = 36,
  GNUPG_Invalid_Name = 37,
  GNUPG_Bad_Public_Key = 38,
  GNUPG_Bad_Secret_Key = 39,
  GNUPG_Bad_Data = 40,
  GNUPG_Invalid_Parameter = 41,
  GNUPG_Tribute_to_D_A = 42,
  GNUPG_No_Dirmngr = 43,
  GNUPG_Dirmngr_Error = 44,
  GNUPG_Certificate_Revoked = 45,
  GNUPG_No_CRL_Known = 46,
  GNUPG_CRL_Too_Old = 47,
  GNUPG_Line_Too_Long = 48,
  GNUPG_Not_Trusted = 49,
  GNUPG_Canceled = 50,
  GNUPG_Bad_CA_Certificate = 51,
  GNUPG_Certificate_Expired = 52,
  GNUPG_Certificate_Too_Young = 53,
  GNUPG_Unsupported_Certificate = 54,
  GNUPG_Unknown_Sexp = 55,
  GNUPG_Unsupported_Protection = 56,
  GNUPG_Corrupted_Protection = 57,
  GNUPG_Ambiguous_Name = 58,
  GNUPG_Card_Error = 59,
  GNUPG_Card_Reset = 60,
  GNUPG_Card_Removed = 61,
  GNUPG_Invalid_Card = 62,
  GNUPG_Card_Not_Present = 63,
  GNUPG_No_PKCS15_App = 64,
  GNUPG_Not_Confirmed = 65,
};

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
};


/*-- errors.c (built) --*/
const char *gnupg_strerror (int err);


#endif /*GNUPG_COMMON_ERRORS_H*/
