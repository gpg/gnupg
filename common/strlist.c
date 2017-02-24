/* strlist.c -  string helpers
 * Copyright (C) 1998, 2000, 2001, 2006 Free Software Foundation, Inc.
 * Copyright (C) 2015  g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "util.h"
#include "common-defs.h"
#include "strlist.h"
#include "utf8conv.h"
#include "mischelp.h"

void
free_strlist( strlist_t sl )
{
    strlist_t sl2;

    for(; sl; sl = sl2 ) {
	sl2 = sl->next;
	xfree(sl);
    }
}


void
free_strlist_wipe (strlist_t sl)
{
    strlist_t sl2;

    for(; sl; sl = sl2 ) {
	sl2 = sl->next;
        wipememory (sl, sizeof *sl + strlen (sl->d));
	xfree(sl);
    }
}


/* Add STRING to the LIST at the front.  This function terminates the
   process on memory shortage.  */
strlist_t
add_to_strlist( strlist_t *list, const char *string )
{
    strlist_t sl;

    sl = xmalloc( sizeof *sl + strlen(string));
    sl->flags = 0;
    strcpy(sl->d, string);
    sl->next = *list;
    *list = sl;
    return sl;
}


/* Add STRING to the LIST at the front.  This function returns NULL
   and sets ERRNO on memory shortage.  */
strlist_t
add_to_strlist_try (strlist_t *list, const char *string)
{
  strlist_t sl;

  sl = xtrymalloc (sizeof *sl + strlen (string));
  if (sl)
    {
      sl->flags = 0;
      strcpy (sl->d, string);
      sl->next = *list;
      *list = sl;
    }
  return sl;
}


/* Same as add_to_strlist() but if IS_UTF8 is *not* set, a conversion
   to UTF-8 is done.  This function terminates the process on memory
   shortage.  */
strlist_t
add_to_strlist2( strlist_t *list, const char *string, int is_utf8 )
{
  strlist_t sl;

  if (is_utf8)
    sl = add_to_strlist( list, string );
  else
    {
      char *p = native_to_utf8( string );
      sl = add_to_strlist( list, p );
      xfree ( p );
    }
  return sl;
}


/* Add STRING to the LIST at the end.  This function terminates the
   process on memory shortage.  */
strlist_t
append_to_strlist( strlist_t *list, const char *string )
{
  strlist_t sl;
  sl = append_to_strlist_try (list, string);
  if (!sl)
    xoutofcore ();
  return sl;
}


/* Add STRING to the LIST at the end.  */
strlist_t
append_to_strlist_try (strlist_t *list, const char *string)
{
    strlist_t r, sl;

    sl = xtrymalloc( sizeof *sl + strlen(string));
    if (sl == NULL)
      return NULL;

    sl->flags = 0;
    strcpy(sl->d, string);
    sl->next = NULL;
    if( !*list )
	*list = sl;
    else {
	for( r = *list; r->next; r = r->next )
	    ;
	r->next = sl;
    }
    return sl;
}


strlist_t
append_to_strlist2( strlist_t *list, const char *string, int is_utf8 )
{
  strlist_t sl;

  if( is_utf8 )
    sl = append_to_strlist( list, string );
  else
    {
      char *p = native_to_utf8 (string);
      sl = append_to_strlist( list, p );
      xfree( p );
    }
  return sl;
}


/* Return a copy of LIST.  This function terminates the process on
   memory shortage.*/
strlist_t
strlist_copy (strlist_t list)
{
  strlist_t newlist = NULL, sl, *last;

  last = &newlist;
  for (; list; list = list->next)
    {
      sl = xmalloc (sizeof *sl + strlen (list->d));
      sl->flags = list->flags;
      strcpy(sl->d, list->d);
      sl->next = NULL;
      *last = sl;
      last = &sl;
    }
  return newlist;
}



strlist_t
strlist_prev( strlist_t head, strlist_t node )
{
    strlist_t n;

    for(n=NULL; head && head != node; head = head->next )
	n = head;
    return n;
}

strlist_t
strlist_last( strlist_t node )
{
    if( node )
	for( ; node->next ; node = node->next )
	    ;
    return node;
}


/* Remove the first item from LIST and return its content in an
   allocated buffer.  This function terminates the process on memory
   shortage.  */
char *
strlist_pop (strlist_t *list)
{
  char *str=NULL;
  strlist_t sl=*list;

  if(sl)
    {
      str = xmalloc(strlen(sl->d)+1);
      strcpy(str,sl->d);

      *list=sl->next;
      xfree(sl);
    }

  return str;
}

/* Return the first element of the string list HAYSTACK whose string
   matches NEEDLE.  If no elements match, return NULL.  */
strlist_t
strlist_find (strlist_t haystack, const char *needle)
{
  for (;
       haystack;
       haystack = haystack->next)
    if (strcmp (haystack->d, needle) == 0)
      return haystack;
  return NULL;
}

int
strlist_length (strlist_t list)
{
  int i;
  for (i = 0; list; list = list->next)
    i ++;

  return i;
}

/* Reverse the list *LIST in place.  */
strlist_t
strlist_rev (strlist_t *list)
{
  strlist_t l = *list;
  strlist_t lrev = NULL;

  while (l)
    {
      strlist_t tail = l->next;
      l->next = lrev;
      lrev = l;
      l = tail;
    }

  *list = lrev;
  return lrev;
}
