/* dotlock.h - dotfile locking declarations
 * Copyright (C) 2000, 2001, 2006, 2011 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB, which is a subsystem of GnuPG.
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

/* See dotlock.c for a description.  */

struct dotlock_handle;
typedef struct dotlock_handle *dotlock_t;

void dotlock_disable (void);
dotlock_t dotlock_create (const char *file_to_lock, unsigned int flags);
void dotlock_set_fd (dotlock_t h, int fd);
int  dotlock_get_fd (dotlock_t h);
void dotlock_destroy (dotlock_t h);
int dotlock_take (dotlock_t h, long timeout);
int dotlock_release (dotlock_t h);
void dotlock_remove_lockfiles (void);

#endif /*LIBJNLIB_DOTLOCK_H*/
