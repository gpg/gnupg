/* setenv.c - libc replacement function
 * Copyright (C) 2004 Free Software Foundation, Inc.
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

#include <config.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

/* Implement setenv in terms of putenv.  Alas, the nature of setenv is
   to be leaky... */
int
setenv(const char *name, const char *value, int overwrite)
{
  char *item=NULL;

  if (name == NULL || *name == '\0' || strchr (name, '=') != NULL)
    {
      errno=EINVAL;
      return -1;
    }

  item=malloc(strlen(name)+1+strlen(value)+1);
  if(!item)
    {
      errno=ENOMEM;
      return -1;
    }

  strcpy(item,name);
  strcat(item,"=");
  strcat(item,value);

  return putenv(item);
}
