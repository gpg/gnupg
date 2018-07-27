/* t-mbox-util.c - Module test for mbox-util.c
 * Copyright (C) 2015 Werner Koch
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "mbox-util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                       exit (1);                                 \
                    } while(0)


static void
run_mbox_test (void)
{
  static struct
  {
    const char *userid;
    const char *mbox;
  } testtbl[] =
    {
      { "Werner Koch <wk@gnupg.org>", "wk@gnupg.org" },
      { "<wk@gnupg.org>", "wk@gnupg.org" },
      { "wk@gnupg.org", "wk@gnupg.org" },
      { "wk@gnupg.org ", NULL },
      { " wk@gnupg.org", NULL },
      { "Werner Koch (test) <wk@gnupg.org>", "wk@gnupg.org" },
      { "Werner Koch <wk@gnupg.org> (test)", "wk@gnupg.org" },
      { "Werner Koch <wk@gnupg.org (test)", NULL },
      { "Werner Koch <wk@gnupg.org >", NULL },
      { "Werner Koch <wk@gnupg.org", NULL },
      { "", NULL },
      { "@", NULL },
      { "bar <>", NULL },
      { "<foo@example.org>", "foo@example.org" },
      { "<foo.@example.org>", "foo.@example.org" },
      { "<.foo.@example.org>", ".foo.@example.org" },
      { "<foo..@example.org>", "foo..@example.org" },
      { "<foo..bar@example.org>", "foo..bar@example.org" },
      { "<foo@example.org.>", NULL },
      { "<foo@example..org>", NULL },
      { "<foo@.>", NULL },
      { "<@example.org>", NULL },
      { "<foo@@example.org>", NULL },
      { "<@foo@example.org>", NULL },
      { "<foo@example.org> ()", "foo@example.org" },
      { "<fo()o@example.org> ()", "fo()o@example.org" },
      { "<fo()o@example.org> ()", "fo()o@example.org" },
      { "fo()o@example.org", NULL},
      { "Mr. Foo <foo@example.org><bar@example.net>", "foo@example.org"},
      { NULL, NULL }
    };
  int idx;

  for (idx=0; testtbl[idx].userid; idx++)
    {
      char *mbox = mailbox_from_userid (testtbl[idx].userid);

      if (!testtbl[idx].mbox)
        {
          if (mbox)
            fail (idx);
        }
      else if (!mbox)
        fail (idx);
      else if (strcmp (mbox, testtbl[idx].mbox))
        fail (idx);

      xfree (mbox);
    }
}


static void
run_dns_test (void)
{
  static struct
  {
    const char *name;
    int valid;
  } testtbl[] =
    {
      { "", 0 },
      { ".", 0 },
      { "-", 0 },
      { "a", 1 },
      { "ab", 1 },
      { "a.b", 1 },
      { "a.b.", 1 },
      { ".a.b.", 0 },
      { ".a.b", 0 },
      { "-a.b", 0 },
      { "a-.b", 0 },
      { "a.-b", 0 },
      { "a.b-", 0 },
      { "a.b-.", 0 },
      { "a..b", 0 },
      { "ab.c", 1 },
      { "a-b.c", 1 },
      { "a-b-.c", 0 },
      { "-a-b.c", 0 },
      { "example.org", 1 },
      { "x.example.org", 1 },
      { "xy.example.org", 1 },
      { "Xy.example.org", 1 },
      { "-Xy.example.org", 0 },
      { "Xy.example-.org", 0 },
      { "foo.example.org..", 0 },
      { "foo.example.org.", 1 },
      { ".foo.example.org.", 0 },
      { "..foo.example.org.", 0 },
      { NULL, 0 }
    };
  int idx;

  for (idx=0; testtbl[idx].name; idx++)
    {
      if (is_valid_domain_name (testtbl[idx].name) != testtbl[idx].valid)
        fail (idx);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  run_mbox_test ();
  run_dns_test ();

  return 0;
}
