/* sha1.h - SHA1 hash function
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#ifndef G10_SHA1_H
#define G10_SHA1_H


const char *
sha1_get_info( int algo, size_t *contextsize,
	       byte **r_asnoid, int *r_asn_len, int *r_mdlen,
	       void (**r_init)( void *c ),
	       void (**r_write)( void *c, byte *buf, size_t nbytes ),
	       void (**r_final)( void *c ),
	       byte *(**r_read)( void *c )
	     );

#endif /*G10_SHA1_H*/
