/* arcfour.h
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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
#ifndef G10_ARCFOUR_H
#define G10_ARCFOUR_H

#include "types.h"

/* NOTE: This is a special get_info function which is different from all
 * others because arcfour is a stream cipher.  We use this hack until
 * we have redesigned the interface.
 */
const char *
arcfour_get_info( int algo, size_t *keylen, size_t *blocksize,
		   size_t *contextsize,
		   int	(**r_setkey)( void *c, byte *key, unsigned keylen ),
		   void (**r_stencrypt)( void *c, byte *outbuf,
                                       byte *inbuf, unsigned int nbytes ),
		   void (**r_stdecrypt)( void *c, byte *outbuf,
                                       byte *inbuf, unsigned int nbytes )
                );


#endif /*G10_ARCFOUR_H*/

