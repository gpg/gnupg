/* ccparray.c - A simple dynamic array for character pointer.
 * Copyright (C) 2016 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
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
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_CCPARRAY_H
#define GNUPG_COMMON_CCPARRAY_H

/* The definition of the structure is private, we only need it here,
 * so it can be allocated on the stack.  */
struct _ccparray_private_s
{
  unsigned int count;
  unsigned int size;
  int out_of_core;
  const char **array;
};

typedef struct _ccparray_private_s ccparray_t;


void ccparray_init (ccparray_t *cpa, unsigned int initialsize);
void ccparray_put (ccparray_t *cpa, const char *value);
const char **ccparray_get (ccparray_t *cpa, size_t *r_nelems);


#endif /*GNUPG_COMMON_CCPARRAY_H*/
