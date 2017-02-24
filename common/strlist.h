/* strlist.h
 *	Copyright (C) 1998, 2000, 2001, 2006 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_STRLIST_H
#define GNUPG_COMMON_STRLIST_H

struct string_list
{
  struct string_list *next;
  unsigned int flags;
  char d[1];
};
typedef struct string_list *strlist_t;

void    free_strlist (strlist_t sl);
void	free_strlist_wipe (strlist_t sl);

strlist_t add_to_strlist (strlist_t *list, const char *string);
strlist_t add_to_strlist_try (strlist_t *list, const char *string);

strlist_t add_to_strlist2( strlist_t *list, const char *string, int is_utf8);

strlist_t append_to_strlist (strlist_t *list, const char *string);
strlist_t append_to_strlist_try (strlist_t *list, const char *string);
strlist_t append_to_strlist2 (strlist_t *list, const char *string,
                              int is_utf8);

strlist_t strlist_copy (strlist_t list);

strlist_t strlist_prev (strlist_t head, strlist_t node);
strlist_t strlist_last (strlist_t node);
char * strlist_pop (strlist_t *list);

strlist_t strlist_find (strlist_t haystack, const char *needle);
int strlist_length (strlist_t list);

strlist_t strlist_rev (strlist_t *haystack);

#define FREE_STRLIST(a) do { free_strlist((a)); (a) = NULL ; } while(0)


#endif /*GNUPG_COMMON_STRLIST_H*/
