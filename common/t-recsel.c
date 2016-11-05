/* t-recsel.c - Module test for recsel.c
 * Copyright (C) 2016 Werner Koch
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
#include "init.h"
#include "recsel.h"

#define PGM  "t-recsel"

#define pass()  do { ; } while(0)
#define fail(a,e)  do { log_error ("line %d: test %d failed: %s\n",     \
                                   __LINE__, (a), gpg_strerror ((e)));  \
                       exit (1);                                        \
                    } while(0)

static int verbose;
static int debug;


#define FREEEXPR() do { recsel_release (se); se = NULL; } while (0)
#define ADDEXPR(a) do {                         \
    err = recsel_parse_expr (&se, (a));         \
    if (err)                                    \
      fail (0, err);                            \
  } while (0)


static const char *
test_1_getval (void *cookie, const char *name)
{
  if (strcmp (name, "uid"))
    fail (0, 0);
  return cookie;
}

static void
run_test_1 (void)
{
  static const char *expr[] = {
    "uid =~ Alfa",
    "&& uid !~   Test  ",
    "|| uid =~  Alpha",
    " uid  !~ Test"
  };
  gpg_error_t err;
  recsel_expr_t se = NULL;
  int i;

  for (i=0; i < DIM (expr); i++)
    {
      err = recsel_parse_expr (&se, expr[i]);
      if (err)
        fail (i, err);
    }

  if (debug)
    recsel_dump (se);

  /* The example from recsel.c in several variants. */
  if (!recsel_select (se, test_1_getval, "Alfa"))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, "Alpha"))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, "Alfa Test"))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, "Alpha Test"))
    fail (0, 0);

  /* Some modified versions from above.  */
  if (!recsel_select (se, test_1_getval, " AlfA Tes"))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, " AlfA Tes "))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, " Tes  AlfA"))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, "TesAlfA"))
    fail (0, 0);

  /* Simple cases. */
  if (recsel_select (se, NULL, NULL))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, NULL))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, ""))
    fail (0, 0);

  FREEEXPR();
}


/* Same as test1 but using a combined expression.. */
static void
run_test_1b (void)
{
  gpg_error_t err;
  recsel_expr_t se = NULL;

  err = recsel_parse_expr
    (&se, "uid =~ Alfa && uid !~   Test  || uid =~  Alpha && uid  !~ Test" );
  if (err)
    fail (0, err);

  if (debug)
    recsel_dump (se);

  /* The example from recsel.c in several variants. */
  if (!recsel_select (se, test_1_getval, "Alfa"))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, "Alpha"))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, "Alfa Test"))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, "Alpha Test"))
    fail (0, 0);

  /* Some modified versions from above.  */
  if (!recsel_select (se, test_1_getval, " AlfA Tes"))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, " AlfA Tes "))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, " Tes  AlfA"))
    fail (0, 0);
  if (!recsel_select (se, test_1_getval, "TesAlfA"))
    fail (0, 0);

  /* Simple cases. */
  if (recsel_select (se, NULL, NULL))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, NULL))
    fail (0, 0);
  if (recsel_select (se, test_1_getval, ""))
    fail (0, 0);

  FREEEXPR();
}


static const char *
test_2_getval (void *cookie, const char *name)
{
  if (!strcmp (name, "uid"))
    return "foo@example.org";
  else if (!strcmp (name, "keyid"))
    return "0x12345678";
  else if (!strcmp (name, "zero"))
    return "0";
  else if (!strcmp (name, "one"))
    return "1";
  else if (!strcmp (name, "blanks"))
    return "    ";
  else if (!strcmp (name, "letters"))
    return "abcde";
  else if (!strcmp (name, "str1"))
    return "aaa";
  else
    return cookie;
}

static void
run_test_2 (void)
{
  gpg_error_t err;
  recsel_expr_t se = NULL;

  ADDEXPR ("uid = foo@example.org");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("uid = Foo@example.org");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("-c uid = Foo@example.org");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("uid =~ foo@example.org");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("uid =~ Foo@example.org");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("-c uid =~ Foo@example.org");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("uid !~ foo@example.org");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("uid !~ Foo@example.org");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("-c uid !~ Foo@example.org");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("uid =~ @");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("uid =~ @");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("keyid == 0x12345678");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("keyid != 0x12345678");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("keyid >= 0x12345678");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("keyid <= 0x12345678");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("keyid > 0x12345677");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("keyid < 0x12345679");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("keyid > 0x12345678");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("keyid < 0x12345678");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);


  FREEEXPR();
  ADDEXPR ("str1 -gt aa");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("str1 -gt aaa");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("str1 -ge aaa");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("str1 -lt aab");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("str1 -le aaa");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("-c str1 -lt AAB");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("str1 -lt AAB");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);


  FREEEXPR();
  ADDEXPR ("uid -n");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("uid -z");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("nothing -z");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("nothing -n");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("blanks -n");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("blanks -z");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("letters -n");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("letters -z");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);


  FREEEXPR();
  ADDEXPR ("nothing -f");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("nothing -t");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("zero -f");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("zero -t");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("one -t");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("one -f");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("blanks -f");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("blanks -t");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);

  FREEEXPR();
  ADDEXPR ("letter -f");
  if (!recsel_select (se, test_2_getval, NULL))
    fail (0, 0);
  FREEEXPR();
  ADDEXPR ("letters -t");
  if (recsel_select (se, test_2_getval, NULL))
    fail (0, 0);


  FREEEXPR();
}



int
main (int argc, char **argv)
{
  int last_argc = -1;

  log_set_prefix (PGM, GPGRT_LOG_WITH_PREFIX);
  init_common_subsystems (&argc, &argv);

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
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n",
                 stdout);
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
      else if (!strncmp (*argv, "--", 2))
        {
          log_error ("unknown option '%s'\n", *argv);
          exit (2);
        }
    }

  run_test_1 ();
  run_test_1b ();
  run_test_2 ();
  /* Fixme: We should add test for complex conditions.  */

  return 0;
}
