/* dotlock.h
 *	Copyright (C) 2000, 2001, 2006 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_DOTLOCK_H
#define LIBJNLIB_DOTLOCK_H

struct dotlock_handle;
typedef struct dotlock_handle *DOTLOCK;

void disable_dotlock (void);
DOTLOCK create_dotlock(const char *file_to_lock);
void destroy_dotlock ( DOTLOCK h );
int make_dotlock (DOTLOCK h, long timeout);
int release_dotlock (DOTLOCK h);
void dotlock_remove_lockfiles (void);

#endif /*LIBJNLIB_DOTLOCK_H*/
