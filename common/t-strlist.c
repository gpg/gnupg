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


static void
test_tokenize_to_strlist (void)
{
  struct {
    const char *s;
    const char *delim;
    int error_expected;
    const char *items_expected[10];
  } tv[] = {
    {
      "", ":",
      1, { NULL }
    },
    {
      "a", ":",
      0, { "a", NULL }
    },
    {
      ":", ":",
      1, { NULL }
    },
    {
      "::", ":",
      1, { NULL }
    },
    {
      "a:b:c", ":",
      0, { "a", "b", "c", NULL }
    },
    {
      "a:b:", ":",
      0, { "a", "b", NULL }
    },
    {
      "a:b", ":",
      0, { "a", "b", NULL }
    },
    {
      "aa:b:cd", ":",
      0, { "aa", "b", "cd", NULL }
    },
    {
      "aa::b:cd", ":",
      0, { "aa", "b", "cd", NULL }
    },
    {
      "::b:cd", ":",
      0, { "b", "cd", NULL }
    },
    {
      "aa:   : b:cd ", ":",
      0, { "aa", "b", "cd", NULL }
    },
    {
      "  aa:   : b:  cd ", ":",
      0, { "aa", "b", "cd", NULL }
    },
    {
      "  :", ":",
      1, { NULL }
    },
    {
      "  : ", ":",
      1, { NULL }
    },
    {
      ": ", ":",
      1, { NULL }
    },
    {
      ": x ", ":",
      0, { "x", NULL }
    },
    {
      "a:bc:cde:fghi:jklmn::foo:", ":",
      0, { "a", "bc", "cde", "fghi", "jklmn", "foo", NULL }
    },
    {
      ",a,bc,,def,", ",",
      0, { "a", "bc", "def", NULL }
    },
    {
      " a ", " ",
      0, { "a", NULL }
    },
    {
      " ", " ",
      1, { NULL }
    },
    {
      "a:bc:c de:fg   hi:jklmn::foo :", ":",
      0, { "a", "bc", "c de", "fg   hi", "jklmn", "foo", NULL }
    },
    {
      "", " ",
      1, { NULL }
    }
  };
  const char *prefixes[3] = { "abc", "bcd", "efg" };
  int tidx;
  int nprefixes; /* Number of items in already in the list.  */
  strlist_t list = NULL;

  for (nprefixes = 0; nprefixes < DIM (prefixes); nprefixes++)
    for (tidx = 0; tidx < DIM(tv); tidx++)
      {
        int item_count_expected;
        int i;
        strlist_t sl, newitems;

        for (item_count_expected = 0;
             tv[tidx].items_expected[item_count_expected];
             item_count_expected++)
          ;

        /* printf  ("np=%d testing %d \"%s\" delim=\"%s\"\n", */
        /*          nprefixes, tidx, tv[tidx].s, tv[tidx].delim); */
        for (i=0; i < nprefixes; i++)
          append_to_strlist (&list, prefixes[i]);

        newitems = tokenize_to_strlist (&list, tv[tidx].s, tv[tidx].delim);
        if (!newitems)
          {
            if (gpg_err_code_from_syserror () == GPG_ERR_ENOENT
                && tv[tidx].error_expected)
              {
                /* Good.  But need to check the prefixes.  */
                for (sl=list, i=0; i < nprefixes; i++, sl=sl->next)
                  {
                    if (!sl || strcmp (prefixes[i], sl->d))
                      {
                        printf ("For item %d prefix item %d, expected '%s'\n",
                                tidx, i, prefixes[i]);
                        fail (tidx * 1000 + 40 + i + 1);
                      }
                  }
              }
            else
              fail (tidx * 1000);
          }
        else if (tv[tidx].error_expected)
          {
            printf ("got items");
            for (sl = list; sl; sl = sl->next)
              printf (" \"%s\"", sl->d);
            printf ("\n");
            fail (tidx * 1000);
          }
        else
          {
            if (strlist_length (list) != nprefixes + item_count_expected)
              fail (tidx * 1000);
            else
              {
                for (sl=list, i=0; i < nprefixes; i++, sl=sl->next)
                  {
                    if (!sl || strcmp (prefixes[i], sl->d))
                      {
                        printf ("For item %d prefix item %d, expected '%s'\n",
                                tidx, i, prefixes[i]);
                        fail (tidx * 1000 + 50 + i + 1);
                      }
                  }
                for (i=0; i < item_count_expected; i++, sl=sl->next)
                  {
                    if (!sl)
                      {
                        printf ("No item at item index %d\n", i);
                        fail (tidx * 1000 + i + 0);
                        break;
                      }
                    if (strcmp (tv[tidx].items_expected[i], sl->d))
                      {
                        printf ("For item %d, expected '%s', but got '%s'\n",
                                i, tv[tidx].items_expected[i], sl->d);
                        fail (tidx * 1000 + 10 + i + 1);
                      }
                  }
              }
          }

        free_strlist (list);
        list = NULL;
      }
}



int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_strlist_rev ();
  test_tokenize_to_strlist ();

  return 0;
}
