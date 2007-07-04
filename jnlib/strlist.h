/* strlist.h
 *	Copyright (C) 1998, 2000, 2001, 2006 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_STRLIST_H
#define LIBJNLIB_STRLIST_H

struct string_list 
{
  struct string_list *next;
  unsigned int flags;
  char d[1];
};
typedef struct string_list *strlist_t;

void    free_strlist (strlist_t sl);
strlist_t add_to_strlist (strlist_t *list, const char *string);

strlist_t add_to_strlist2( strlist_t *list, const char *string, int is_utf8);

strlist_t append_to_strlist (strlist_t *list, const char *string);
strlist_t append_to_strlist2 (strlist_t *list, const char *string,
                              int is_utf8);

strlist_t strlist_copy (strlist_t list);

strlist_t strlist_prev (strlist_t head, strlist_t node);
strlist_t strlist_last (strlist_t node);
char * strlist_pop (strlist_t *list);

#define FREE_STRLIST(a) do { free_strlist((a)); (a) = NULL ; } while(0)


#endif /*LIBJNLIB_STRLIST_H*/
