/* host2net.h - Some macros
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G10_HOST2NET_H
#define G10_HOST2NET_H

#include "types.h"

#define buftoulong( p )  ((*(byte*)(p) << 24) | (*((byte*)(p)+1)<< 16) | \
		       (*((byte*)(p)+2) << 8) | (*((byte*)(p)+3)))
#define buftoushort( p )  ((*((byte*)(p)) << 8) | (*((byte*)(p)+1)))
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
#define buftou32( p)	buftoulong( (p) )
#define u32tobuf( p, a) ulongtobuf( (p), (a) )


#endif /*G10_HOST2NET_H*/
