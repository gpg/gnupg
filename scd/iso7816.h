/* iso7816.h - ISO 7816 commands
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef ISO7816_H
#define ISO7816_H

int iso7816_select_application (int slot, const char *aid, size_t aidlen);
int iso7816_verify (int slot, int chvno, const char *chv, size_t chvlen);
int iso7816_get_data (int slot, int tag,
                      unsigned char **result, size_t *resultlen);
int iso7816_put_data (int slot, int tag,
                      const unsigned char *data, size_t datalen);
int iso7816_compute_ds (int slot,
                            const unsigned char *data, size_t datalen,
                            unsigned char **result, size_t *resultlen);
int iso7816_decipher (int slot,
                          const unsigned char *data, size_t datalen,
                          unsigned char **result, size_t *resultlen);
int iso7816_internal_authenticate (int slot,
                                   const unsigned char *data, size_t datalen,
                                   unsigned char **result, size_t *resultlen);
int iso7816_generate_keypair (int slot,
                              const unsigned char *data, size_t datalen,
                              unsigned char **result, size_t *resultlen);
int iso7816_read_public_key (int slot,
                             const unsigned char *data, size_t datalen,
                             unsigned char **result, size_t *resultlen);
int iso1816_get_challenge (int slot, int length, unsigned char *buffer);


#endif /*ISO7816_H*/
