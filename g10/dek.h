/* dek.h - The data encryption key structure.
 * Copyright (C) 2014 Werner Koch
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
#ifndef G10_DEK_H
#define G10_DEK_H


typedef struct
{
  /* The algorithm (e.g., CIPHER_ALGO_AES).  */
  int algo;
  /* The length of the key (in bytes).  */
  int keylen;
  /* Whether we've already printed information about this key.  This
     is currently only used in decrypt_data() and only if we are in
     verbose mode.  */
  int algo_info_printed;
  int use_mdc;
  /* This key was read from a SK-ESK packet (see proc_symkey_enc).  */
  int symmetric;
  byte key[32]; /* This is the largest used keylen (256 bit). */
  char s2k_cacheid[1+16+1];
} DEK;


#endif /*G10_DEK_H*/
