/* xmalloc.h
 *	Copyright (C) 1999, 2000, 2001, 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_XMALLOC_H
#define GNUPG_COMMON_XMALLOC_H

void *xmalloc( size_t n );
void *xrealloc( void *a, size_t n );
void *xcalloc( size_t n, size_t m );
char *xstrdup( const char *string );
char *xstrcat2( const char *a, const char *b );


#endif /*GNUPG_COMMON_XMALLOC_H*/
