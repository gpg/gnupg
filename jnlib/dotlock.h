/* dotlock.h
 *	Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_DOTLOCK_H
#define LIBJNLIB_DOTLOCK_H

struct dotlock_handle;
typedef struct dotlock_handle *DOTLOCK;

DOTLOCK create_dotlock( const char *file_to_lock );
int make_dotlock( DOTLOCK h, long timeout );
int release_dotlock( DOTLOCK h );


#endif /*LIBJNLIB_DOTLOCK_H*/
