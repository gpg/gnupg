/* status.h - Status codes
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

#ifndef GNUPG_COMMON_STATUS_H
#define GNUPG_COMMON_STATUS_H

#include "../common/fwddecl.h"

enum
  {
    STATUS_ENTER,
    STATUS_LEAVE,
    STATUS_ABORT,
    STATUS_CANCELED_BY_USER,

    STATUS_GOODSIG,
    STATUS_BADSIG,
    STATUS_ERRSIG,

    STATUS_BADARMOR,

    STATUS_TRUST_UNDEFINED,
    STATUS_TRUST_NEVER,
    STATUS_TRUST_MARGINAL,
    STATUS_TRUST_FULLY,
    STATUS_TRUST_ULTIMATE,

    STATUS_NEED_PASSPHRASE,
    STATUS_VALIDSIG,
    STATUS_ASSERT_SIGNER,
    STATUS_ASSERT_PUBKEY_ALGO,
    STATUS_SIG_ID,
    STATUS_ENC_TO,
    STATUS_NODATA,
    STATUS_BAD_PASSPHRASE,
    STATUS_NO_PUBKEY,
    STATUS_NO_SECKEY,
    STATUS_NEED_PASSPHRASE_SYM,
    STATUS_DECRYPTION_KEY,
    STATUS_DECRYPTION_INFO,
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
    STATUS_IMPORT_CHECK,

    STATUS_EXPORTED,
    STATUS_EXPORT_RES,

    STATUS_FILE_START,
    STATUS_FILE_DONE,
    STATUS_FILE_ERROR,

    STATUS_BEGIN_DECRYPTION,
    STATUS_END_DECRYPTION,
    STATUS_BEGIN_ENCRYPTION,
    STATUS_END_ENCRYPTION,
    STATUS_BEGIN_SIGNING,

    STATUS_DELETE_PROBLEM,

    STATUS_GET_BOOL,
    STATUS_GET_LINE,
    STATUS_GET_HIDDEN,
    STATUS_GOT_IT,

    STATUS_PROGRESS,
    STATUS_SIG_CREATED,
    STATUS_SESSION_KEY,
    STATUS_NOTATION_NAME,
    STATUS_NOTATION_FLAGS,
    STATUS_NOTATION_DATA,
    STATUS_POLICY_URL,
    STATUS_KEY_CREATED,
    STATUS_USERID_HINT,
    STATUS_UNEXPECTED,
    STATUS_INV_RECP,
    STATUS_INV_SGNR,
    STATUS_NO_RECP,
    STATUS_NO_SGNR,
    STATUS_KEY_CONSIDERED,

    STATUS_ALREADY_SIGNED,
    STATUS_KEYEXPIRED,
    STATUS_KEYREVOKED,
    STATUS_EXPSIG,
    STATUS_EXPKEYSIG,

    STATUS_ATTRIBUTE,

    STATUS_REVKEYSIG,

    STATUS_NEWSIG,
    STATUS_SIG_SUBPACKET,

    STATUS_PLAINTEXT,
    STATUS_PLAINTEXT_LENGTH,
    STATUS_KEY_NOT_CREATED,
    STATUS_NEED_PASSPHRASE_PIN,

    STATUS_CARDCTRL,
    STATUS_SC_OP_FAILURE,
    STATUS_SC_OP_SUCCESS,

    STATUS_BACKUP_KEY_CREATED,

    STATUS_PKA_TRUST_BAD,
    STATUS_PKA_TRUST_GOOD,

    STATUS_TOFU_USER,
    STATUS_TOFU_STATS,
    STATUS_TOFU_STATS_SHORT,
    STATUS_TOFU_STATS_LONG,

    STATUS_ENCRYPTION_COMPLIANCE_MODE,
    STATUS_DECRYPTION_COMPLIANCE_MODE,
    STATUS_VERIFICATION_COMPLIANCE_MODE,

    STATUS_TRUNCATED,
    STATUS_MOUNTPOINT,
    STATUS_BLOCKDEV,
    STATUS_PLAINDEV,           /* The decrypted virtual device.  */

    STATUS_PINENTRY_LAUNCHED,

    STATUS_PLAINTEXT_FOLLOWS,   /* Used by g13-syshelp  */

    STATUS_ERROR,
    STATUS_WARNING,
    STATUS_SUCCESS,
    STATUS_FAILURE,

    STATUS_INQUIRE_MAXLEN
  };


const char *get_status_string (int code);
void gnupg_set_status_fd (int fd);
void gnupg_status_printf (int no, const char *format,
                          ...) GPGRT_ATTR_PRINTF(2,3);
gpg_error_t gnupg_status_strings (ctrl_t dummy, int no,
                                  ...) GPGRT_ATTR_SENTINEL(0);

const char *get_inv_recpsgnr_code (gpg_error_t err);


#endif /*GNUPG_COMMON_STATUS_H*/
