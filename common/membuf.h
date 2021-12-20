/* membuf.h - A simple implementation of a dynamic buffer
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_MEMBUF_H
#define GNUPG_COMMON_MEMBUF_H

#include "mischelp.h"

/* The definition of the structure is private, we only need it here,
   so it can be allocated on the stack. */
struct private_membuf_s
{
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};

typedef struct private_membuf_s membuf_t;

/* Return the current length of the membuf.  */
#define get_membuf_len(a)  ((a)->len)
#define is_membuf_ready(a) ((a)->buf || (a)->out_of_core)
#define MEMBUF_ZERO        { 0, 0, NULL, 0}

void init_membuf (membuf_t *mb, int initiallen);
void init_membuf_secure (membuf_t *mb, int initiallen);
void clear_membuf (membuf_t *mb, size_t amount);
void put_membuf  (membuf_t *mb, const void *buf, size_t len);
gpg_error_t put_membuf_cb (void *opaque, const void *buf, size_t len);
void put_membuf_str (membuf_t *mb, const char *string);
void put_membuf_printf (membuf_t *mb, const char *format,
                        ...) GPGRT_ATTR_PRINTF(2,3);
void *get_membuf (membuf_t *mb, size_t *len);
void *get_membuf_shrink (membuf_t *mb, size_t *len);
const void *peek_membuf (membuf_t *mb, size_t *len);
void set_membuf_err (membuf_t *mb, gpg_error_t err);

#endif /*GNUPG_COMMON_MEMBUF_H*/
