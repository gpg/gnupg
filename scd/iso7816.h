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

/* Error codes returned by iso7816_verify_status.  A non-negative
 * number gives the number of left tries.
 * NB: The values are also used by the CHV-STATUS lines and thus are
 * part of the public interface.  Do not change them.  */
#define ISO7816_VERIFY_ERROR        (-1)
#define ISO7816_VERIFY_NO_PIN       (-2)
#define ISO7816_VERIFY_BLOCKED      (-3)
#define ISO7816_VERIFY_NULLPIN      (-4)
#define ISO7816_VERIFY_NOT_NEEDED   (-5)

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
gpg_error_t iso7816_select_application_ext (int slot,
                                            const char *aid, size_t aidlen,
                                            unsigned int flags,
                                            unsigned char **result,
                                            size_t *resultlen);
gpg_error_t iso7816_select_mf (int slot);
gpg_error_t iso7816_select_file (int slot, int tag, int is_dir);
gpg_error_t iso7816_select_path (int slot,
                                 const unsigned short *path, size_t pathlen,
                                 unsigned short top_df);
gpg_error_t iso7816_list_directory (int slot, int list_dirs,
                                    unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_apdu_direct (int slot,
                                 const void *apdudata, size_t apdudatalen,
                                 int handle_more, unsigned int *r_sw,
                                 unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_check_pinpad (int slot, int command,
                                  pininfo_t *pininfo);
gpg_error_t iso7816_verify (int slot,
                            int chvno, const char *chv, size_t chvlen);
gpg_error_t iso7816_verify_kp (int slot, int chvno, pininfo_t *pininfo);
int iso7816_verify_status (int slot, int chvno);
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
gpg_error_t iso7816_select_data (int slot, int occurrence, int tag);
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
gpg_error_t iso7816_pso_csv (int slot, int extended_mode,
                             const unsigned char *data, size_t datalen, int le,
                             unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_internal_authenticate (int slot, int extended_mode,
                                   const unsigned char *data, size_t datalen,
                                   int le,
                                   unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_general_authenticate (int slot, int extended_mode,
                                          int algoref, int keyref,
                                          const unsigned char *data,
                                          size_t datalen,
                                          int le,
                                          unsigned char **result,
                                          size_t *resultlen);
gpg_error_t iso7816_generate_keypair (int slot, int extended_mode,
                                      int p1, int p2,
                                      const char *data, size_t datalen,
                                      int le,
                                      unsigned char **result,
                                      size_t *resultlen);
gpg_error_t iso7816_read_public_key (int slot, int extended_mode,
                                    const char *data, size_t datalen,
                                    int le,
                                    unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_get_challenge (int slot,
                                   int length, unsigned char *buffer);

gpg_error_t iso7816_read_binary_ext (int slot, int extended_mode,
                                     size_t offset, size_t nmax,
                                     unsigned char **result, size_t *resultlen,
                                     int *r_sw);
gpg_error_t iso7816_read_binary (int slot, size_t offset, size_t nmax,
                                 unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_read_record_ext (int slot, int recno, int reccount,
                                     int short_ef,
                                     unsigned char **result, size_t *resultlen,
                                     int *r_sw);
gpg_error_t iso7816_read_record (int slot, int recno, int reccount,
                                 int short_ef,
                                 unsigned char **result, size_t *resultlen);
gpg_error_t iso7816_update_binary (int slot, int extended_mode, size_t offset,
                                   const void *data, size_t datalen);

#endif /*ISO7816_H*/
