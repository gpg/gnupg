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

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

#include "util.h"
#include "ccparray.h"


/* A simple implementation of a dynamic array of const char pointers.
 * The example code:
 *
 *   ccparray_t ccp;
 *   const char **argv;
 *   int i;
 *
 *   ccparray_init (&ccp, 0);
 *   ccparray_put (&ccp, "First arg");
 *   ccparray_put (&ccp, "Second arg");
 *   ccparray_put (&ccp, NULL);
 *   ccparray_put (&ccp, "Fourth arg");
 *   argv = ccparray_get (&ccp, NULL);
 *   if (!argv)
 *     die ("error building array: %s\n", strerror (errno));
 *   for (i=0; argv[i]; i++)
 *     printf ("[%d] = '%s'\n", i, argv[i]);
 *   xfree (argv);
 *
 * will result in this output:
 *
 *   [0] = 'First arg'
 *   [1] = 'Second arg'
 *
 * Note that allocation errors are detected but only returned with the
 * final ccparray_get(); this helps not to clutter the code with out
 * of core checks.
 */

void
ccparray_init (ccparray_t *cpa, unsigned int initialsize)
{
  if (!initialsize)
    cpa->size = 16;
  else if (initialsize < (1<<16))
    cpa->size = initialsize;
  else
    cpa->size = (1<<16);

  cpa->count = 0;
  cpa->out_of_core = 0;
  cpa->array = xtrycalloc (cpa->size, sizeof *cpa->array);
  if (!cpa->array)
    cpa->out_of_core = errno;
}


void
ccparray_put (ccparray_t *cpa, const char *value)
{
  if (cpa->out_of_core)
    return;

  if (cpa->count + 1 >= cpa->size)
    {
      const char **newarray;
      size_t n, newsize;

      if (cpa->size < 8)
        newsize = 16;
      else if (cpa->size < 4096)
        newsize = 2 * cpa->size;
      else if (cpa->size < (1<<16))
        newsize = cpa->size + 2048;
      else
        {
          cpa->out_of_core = ENOMEM;
          return;
        }

      newarray = xtrycalloc (newsize, sizeof *newarray);
      if (!newarray)
        {
          cpa->out_of_core = errno ? errno : ENOMEM;
          return;
        }
      for (n=0; n < cpa->size; n++)
        newarray[n] = cpa->array[n];
      xfree (cpa->array);
      cpa->array = newarray;
      cpa->size = newsize;

    }
  cpa->array[cpa->count++] = value;
}


const char **
ccparray_get (ccparray_t *cpa, size_t *r_count)
{
  const char **result;

  if (cpa->out_of_core)
    {
      if (cpa->array)
        {
          xfree (cpa->array);
          cpa->array = NULL;
        }
      gpg_err_set_errno (cpa->out_of_core);
      return NULL;
    }

  result= cpa->array;
  if (r_count)
    *r_count = cpa->count;
  cpa->array = NULL;
  cpa->out_of_core = ENOMEM; /* hack to make sure it won't get reused. */
  return result;
}
