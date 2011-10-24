/* dotlock.h - dotfile locking declarations
 * Copyright (C) 2000, 2001, 2006, 2011 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB, which is a subsystem of GnuPG.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
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
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 *
 * ALTERNATIVELY, this file may be distributed under the terms of the
 * following license, in which case the provisions of this license are
 * required INSTEAD OF the GNU Lesser General License or the GNU
 * General Public License. If you wish to allow use of your version of
 * this file only under the terms of the GNU Lesser General License or
 * the GNU General Public License, and not to allow others to use your
 * version of this file under the terms of the following license,
 * indicate your decision by deleting this paragraph and the license
 * below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
