/* utils.h - Defs for utility fucthe dispatcher to the various backends.ntions
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#ifndef G13_UTILS_H
#define G13_UTILS_H

#include "../common/membuf.h"

/* Append a new tuple to a memory buffer.  */
void append_tuple (membuf_t *membuf,
                   int tag, const void *value, size_t length);

/* The tuple descriptor object. */
struct tupledesc_s;
typedef struct tupledesc_s *tupledesc_t;

gpg_error_t create_tupledesc (tupledesc_t *r_tupledesc,
                              void *data, size_t datalen);
void destroy_tupledesc (tupledesc_t tupledesc);
tupledesc_t ref_tupledesc (tupledesc_t tupledesc);
const void *find_tuple (tupledesc_t tupledesc,
                        unsigned int tag, size_t *r_length);
const void *next_tuple (tupledesc_t tupledesc,
                        unsigned int *r_tag, size_t *r_length);


#endif /*G13_UTILS_H*/
