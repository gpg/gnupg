/* xmalloc.h
 *	Copyright (C) 1999, 2000, 2001 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_XMALLOC_H
#define LIBJNLIB_XMALLOC_H

void *xmalloc( size_t n );
void *xrealloc( void *a, size_t n );
void *xcalloc( size_t n, size_t m );
char *xstrdup( const char *string );
char *xstrcat2( const char *a, const char *b );


#endif /*LIBJNLIB_XMALLOC_H*/
