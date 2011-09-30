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

#ifdef DOTLOCK_EXT_SYM_PREFIX
# ifndef _DOTLOCK_PREFIX
#  define _DOTLOCK_PREFIX1(x,y)  x ## y
#  define _DOTLOCK_PREFIX2(x,y) _DOTLOCK_PREFIX1(x,y)
#  define _DOTLOCK_PREFIX(x)    _DOTLOCK_PREFIX2(DOTLOCK_EXT_SYM_PREFIX,x)
# endif /*_DOTLOCK_PREFIX*/
# define dotlock_disable          _DOTLOCK_PREFIX(dotlock_disable)
# define dotlock_create           _DOTLOCK_PREFIX(dotlock_create)
# define dotlock_set_fd           _DOTLOCK_PREFIX(dotlock_set_fd)
# define dotlock_get_fd           _DOTLOCK_PREFIX(dotlock_get_fd)
# define dotlock_destroy          _DOTLOCK_PREFIX(dotlock_destroy)
# define dotlock_take             _DOTLOCK_PREFIX(dotlock_take)
# define dotlock_release          _DOTLOCK_PREFIX(dotlock_release)
# define dotlock_remove_lockfiles _DOTLOCK_PREFIX(dotlock_remove_lockfiles)
#endif /*DOTLOCK_EXT_SYM_PREFIX*/

#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif


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

#ifdef __cplusplus
}
#endif
#endif /*LIBJNLIB_DOTLOCK_H*/
