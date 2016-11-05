/* minip12.h - Global definitions for the minimal pkcs-12 implementation.
 *	Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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

#ifndef MINIP12_H
#define MINIP12_H

#include <gcrypt.h>

gcry_mpi_t *p12_parse (const unsigned char *buffer, size_t length,
                       const char *pw,
                       void (*certcb)(void*, const unsigned char*, size_t),
                       void *certcbarg, int *r_badpass);

unsigned char *p12_build (gcry_mpi_t *kparms,
                          const void *cert, size_t certlen,
                          const char *pw, const char *charset,
                          size_t *r_length);
unsigned char *p12_raw_build (gcry_mpi_t *kparms,
                              int rawmode,
                              size_t *r_length);


#endif /*MINIP12_H*/
