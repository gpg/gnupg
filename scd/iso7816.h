/* iso7816.h - ISO 7816 commands
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef ISO7816_H
#define ISO7816_H

#if GNUPG_MAJOR_VERSION == 1
#include "cardglue.h"
#endif

/* Command codes used by iso7816_check_pinpad. */
#define ISO7816_VERIFY                0x20
#define ISO7816_CHANGE_REFERENCE_DATA 0x24
#define ISO7816_RESET_RETRY_COUNTER   0x2C


/* Information to be passed to pinpad equipped readers.  See
   ccid-driver.c for details. */
struct pininfo_s
{
  int fixedlen;  /*
		  * -1: Variable length input is not supported,
		  *     no information of fixed length yet.
		  *  0: Use variable length input.
		  * >0: Fixed length of PIN.
		  */
  int minlen;
  int maxlen;
};
typedef struct pininfo_s pininfo_t;


gpg_error_t iso7816_map_sw (int sw);

gpg_error_t iso7816_select_application (int slot,
                                        const char *aid, size_t aidlen,
                                        unsigned int flags);
gpg_error_t iso7816_select_file (int slot, int tag, int is_dir);
gpg_error_t iso7816_select_path (int slot,
                                 const unsigned short *path, size_t pathlen);
gpg_error_t iso7816_list_directory (int slot, int list_dirs,
                                    unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_apdu_direct (int slot,
                                 const void *apdudata, size_t apdudatalen,
                                 int handle_more,
                                 unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_check_pinpad (int slot, int command,
                                  pininfo_t *pininfo);
gpg_error_t iso7816_verify (int slot,
                            int chvno, const char *chv, size_t chvlen);
gpg_error_t iso7816_verify_kp (int slot, int chvno, pininfo_t *pininfo);
gpg_error_t iso7816_change_reference_data (int slot, int chvno,
                               const char *oldchv, size_t oldchvlen,
                               const char *newchv, size_t newchvlen);
gpg_error_t iso7816_change_reference_data_kp (int slot, int chvno,
                                              int is_exchange,
                                              pininfo_t *pininfo);
gpg_error_t iso7816_reset_retry_counter (int slot, int chvno,
                                         const char *newchv, size_t newchvlen);
gpg_error_t iso7816_reset_retry_counter_with_rc (int slot, int chvno,
                                                 const char *data,
                                                 size_t datalen);
gpg_error_t iso7816_get_data (int slot, int extended_mode, int tag,
                              unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_put_data (int slot, int extended_mode, int tag,
                              const void *data, size_t datalen);
gpg_error_t iso7816_put_data_odd (int slot, int extended_mode, int tag,
                                  const void *data, size_t datalen);
gpg_error_t iso7816_manage_security_env (int slot, int p1, int p2,
                                         const unsigned char *data,
                                         size_t datalen);
gpg_error_t iso7816_compute_ds (int slot, int extended_mode,
                                const unsigned char *data, size_t datalen,
                                int le,
                                unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_decipher (int slot, int extended_mode,
                              const unsigned char *data, size_t datalen,
                              int le, int padind,
                              unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_internal_authenticate (int slot, int extended_mode,
                                   const unsigned char *data, size_t datalen,
                                   int le,
                                   unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_generate_keypair (int slot, int extended_mode,
                                    const char *data, size_t datalen,
                                    int le,
                                    unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_read_public_key (int slot, int extended_mode,
                                    const char *data, size_t datalen,
                                    int le,
                                    unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_get_challenge (int slot,
                                   int length, unsigned char *buffer);

gpg_error_t iso7816_read_binary (int slot, size_t offset, size_t nmax,
                                 unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_read_record (int slot, int recno, int reccount,
                                 int short_ef,
                                 unsigned char **result, size_t *resultlen);

#endif /*ISO7816_H*/
