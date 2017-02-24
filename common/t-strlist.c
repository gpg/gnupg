/* t-strlist.c - Regression tests for strist.c
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
#include <string.h>

#include "strlist.h"

#include "t-support.h"

static void
test_strlist_rev (void)
{
  strlist_t s = NULL;

  /* Reversing an empty list should yield the empty list.  */
  if (! (strlist_rev (&s) == NULL))
    fail (1);

  add_to_strlist (&s, "1");
  add_to_strlist (&s, "2");
  add_to_strlist (&s, "3");

  if (strcmp (s->d, "3") != 0)
    fail (2);
  if (strcmp (s->next->d, "2") != 0)
    fail (2);
  if (strcmp (s->next->next->d, "1") != 0)
    fail (2);
  if (s->next->next->next)
    fail (2);

  strlist_rev (&s);

  if (strcmp (s->d, "1") != 0)
    fail (2);
  if (strcmp (s->next->d, "2") != 0)
    fail (2);
  if (strcmp (s->next->next->d, "3") != 0)
    fail (2);
  if (s->next->next->next)
    fail (2);

  free_strlist (s);
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_strlist_rev ();

  return 0;
}
