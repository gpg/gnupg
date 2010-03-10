/* xmalloc.h
 *	Copyright (C) 1999, 2000, 2001, 2006 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBJNLIB_XMALLOC_H
#define LIBJNLIB_XMALLOC_H

void *xmalloc( size_t n );
void *xrealloc( void *a, size_t n );
void *xcalloc( size_t n, size_t m );
char *xstrdup( const char *string );
char *xstrcat2( const char *a, const char *b );


#endif /*LIBJNLIB_XMALLOC_H*/
