/* keybox-util.c - Utility functions for Keybox 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "keybox-defs.h"


static void *(*alloc_func)(size_t n) = malloc;
static void *(*realloc_func)(void *p, size_t n) = realloc;
static void (*free_func)(void*) = free;



void
keybox_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                          void *(*new_realloc_func)(void *p, size_t n),
                          void (*new_free_func)(void*) )
{
  alloc_func	    = new_alloc_func;
  realloc_func      = new_realloc_func;
  free_func	    = new_free_func;
}

void *
_keybox_malloc (size_t n)
{
  return alloc_func (n);
}

void *
_keybox_realloc (void *a, size_t n)
{
  return realloc_func (a, n);
}

void *
_keybox_calloc (size_t n, size_t m)
{
  void *p = _keybox_malloc (n*m);
  if (p)
    memset (p, 0, n* m);
  return p;
}

void
_keybox_free (void *p)
{
  if (p)
    free_func (p);
}

