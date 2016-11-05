/* host2net.h - Endian conversion macros
 * Copyright (C) 1998, 2014, 2015  Werner Koch
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

#ifndef GNUPG_COMMON_HOST2NET_H
#define GNUPG_COMMON_HOST2NET_H

#include "types.h"

#define ulongtobuf( p, a ) do { 			  \
			    ((byte*)p)[0] = a >> 24;	\
			    ((byte*)p)[1] = a >> 16;	\
			    ((byte*)p)[2] = a >>  8;	\
			    ((byte*)p)[3] = a	   ;	\
			} while(0)
#define ushorttobuf( p, a ) do {			   \
			    ((byte*)p)[0] = a >>  8;	\
			    ((byte*)p)[1] = a	   ;	\
			} while(0)


static inline unsigned long
buf16_to_ulong (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned long)p[0] << 8) | p[1]);
}

static inline unsigned int
buf16_to_uint (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned int)p[0] << 8) | p[1]);
}

static inline unsigned short
buf16_to_ushort (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned short)p[0] << 8) | p[1]);
}

static inline u16
buf16_to_u16 (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((u16)p[0] << 8) | p[1]);
}

static inline size_t
buf32_to_size_t (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((size_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline unsigned long
buf32_to_ulong (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned long)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline unsigned int
buf32_to_uint (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned int)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline u32
buf32_to_u32 (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((u32)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}


#endif /*GNUPG_COMMON_HOST2NET_H*/
