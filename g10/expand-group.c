/* expand-group.c - expand GPG group definitions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "gpg.h"
#include "options.h"
#include "keydb.h"

int
expand_id (const char *id, strlist_t *into, unsigned int flags)
{
  struct groupitem *groups;
  int count=0;

  for (groups = opt.grouplist; groups; groups=groups->next)
    {
      /* need strcasecmp() here, as this should be localized */
      if (strcasecmp (groups->name,id) == 0)
	 {
	   strlist_t each,sl;

	   /* This maintains the current utf8-ness */
	   for (each = groups->values; each; each=each->next)
	     {
	       sl = add_to_strlist (into, each->d);
	       sl->flags = flags;
	       count++;
	     }

	   break;
	 }
    }

  return count;
}

/* For simplicity, and to avoid potential loops, we only expand once -
 * you can't make an alias that points to an alias.  If PREPEND_INPUT
 * is true each item from INPUT is prepended to the new list; if it is
 * false the original item from INPUT is only added if no group
 * existed for it. */
strlist_t
expand_group (strlist_t input, int prepend_input)
{
  strlist_t output = NULL;
  strlist_t sl, rover;

  for (rover = input; rover; rover = rover->next)
    {
      if ((rover->flags & PK_LIST_FROM_FILE))
        continue;
      if (!expand_id (rover->d, &output, rover->flags))
        {
          /* Didn't find any groups, so use the existing string unless
           * we will anyway add it due to the prepend flag.  */
          if (!prepend_input)
            {
              sl = add_to_strlist (&output, rover->d);
              sl->flags = rover->flags;
            }
        }
      if (prepend_input)
        {
          sl = add_to_strlist (&output, rover->d);
          sl->flags = rover->flags;
        }
    }

  return output;
}
