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

#define PGM "t-mbox-util"


#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                       exit (1);                                 \
                    } while(0)


static int verbose;
static int debug;


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
      { "Surname, Forename | company <foo@example.org>", "foo@example.org"},
      /* The next one is for sure not RFC-822 correct but nevertheless
       * the way gpg does it.  We won't change it because the user-id
       * is only rfc-822 alike and not compliant (think only of our
       * utf-8 requirement).  */
      { "\"<foo@example.org>\" <foo@example.net>", "foo@example.org"},
      { NULL, NULL }
    };
  int idx;

  for (idx=0; testtbl[idx].userid; idx++)
    {
      char *mbox = mailbox_from_userid (testtbl[idx].userid, 0);

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
run_mbox_no_sub_test (void)
{
  static struct
  {
    const char *userid;
    const char *mbox;
  } testtbl[] =
    {
      { "foo+bar@example.org", "foo@example.org" },
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
      { "foo+bar@example.org", "foo@example.org" },
      { "foo++bar@example.org", "foo++bar@example.org" },
      { "foo++@example.org", "foo++@example.org" },
      { "foo+@example.org", "foo+@example.org" },
      { "+foo@example.org", "+foo@example.org" },
      { "++foo@example.org", "++foo@example.org" },
      { "+foo+@example.org", "+foo+@example.org" },
      { "+@example.org", "+@example.org" },
      { "++@example.org", "++@example.org" },
      { "foo+b@example.org", "foo@example.org" },
      { "foo+ba@example.org", "foo@example.org" },
      { "foo+bar@example.org", "foo@example.org" },
      { "foo+barb@example.org", "foo@example.org" },
      { "foo+barba@example.org", "foo@example.org" },
      { "f+b@example.org", "f@example.org" },
      { "fo+b@example.org", "fo@example.org" },

      { NULL, NULL }
    };
  int idx;

  for (idx=0; testtbl[idx].userid; idx++)
    {
      char *mbox = mailbox_from_userid (testtbl[idx].userid, 1);

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


static void
run_filter (int no_sub)
{
  char buf[4096];
  int c;
  char *p, *mbox;
  unsigned int count1 = 0;
  unsigned int count2 = 0;

  while (fgets (buf, sizeof buf, stdin))
    {
      p = strchr (buf, '\n');
      if (p)
        *p = 0;
      else
        {
          /* Skip to the end of the line.  */
          while ((c = getc (stdin)) != EOF && c != '\n')
            ;
        }
      count1++;
      trim_spaces (buf);
      mbox = mailbox_from_userid (buf, no_sub);
      if (mbox)
        {
          printf ("%s\n", mbox);
          xfree (mbox);
          count2++;
        }
    }
  if (verbose)
    fprintf (stderr, PGM ": lines=%u mboxes=%u\n", count1, count2);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  int opt_filter = 0;
  int opt_no_sub = 0;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [FILE]\n"
                 "Options:\n"
                 "  --verbose         Print timings etc.\n"
                 "  --debug           Flyswatter\n"
                 "  --filter          Filter mboxes from input lines\n"
                 "  --no-sub          Ignore '+'-sub-addresses\n"
                 , stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--filter"))
        {
          opt_filter = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-sub"))
        {
          opt_no_sub = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (opt_filter)
    run_filter (opt_no_sub);
  else
    {
      run_mbox_test ();
      run_mbox_no_sub_test ();
      run_dns_test ();
    }

  return 0;
}
