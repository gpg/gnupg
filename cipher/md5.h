/* md5.h - message digest 5
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_MD5_H
#define G10_MD5_H

#include "types.h"

typedef struct {
    u32 A,B,C,D;	  /* chaining variables */
    u32 total[2];
    u32  buflen;
    char buffer[128];
} MD5_CONTEXT;


void md5_init( MD5_CONTEXT *ctx );
void md5_write( MD5_CONTEXT *ctx, const void *buffer, size_t len);
void md5_final( MD5_CONTEXT *ctx);
#define md5_read(h) ( (h)->buffer )

#endif /*G10_MD5_H*/
