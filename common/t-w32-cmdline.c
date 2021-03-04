/* t-w32-cmdline.c - Test the parser for the Windows command line
 * Copyright (C) 2021 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
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
 * This file is distributed in the hope that it will be useful,
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
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif

#include "t-support.h"
#include "utf8conv.h"
#include "w32help.h"

#define PGM "t-w32-cmdline"

static int verbose;
static int debug;
static int errcount;


static void
test_all (void)
{
  static struct {
    const char *cmdline;
    int argc;        /* Expected number of args.  */
    char *argv[10];  /* Expected results.  */
    int use_glob;
  } tests[] = {
    /* Examples from "Parsing C++ Command-Line Arguments" dated 11/18/2006.
     * https://docs.microsoft.com/en-us/previous-versions/17w5ykft(v=vs.85)
     */
    { "\"abc\" d e", 3,          { "abc",      "d",     "e" }},
    { "a\\\\\\b d\"e f\"g h", 3, { "a\\\\\\b", "de fg", "h" }},
    { "a\\\\\\\"b c d",       3, { "a\\\"b",   "c",     "d" }},
    { "a\\\\\\\\\"b c\" d e", 3, { "a\\\\b c", "d",     "e" }},
    /* Examples from "Parsing C Command-Line Arguments" dated 11/09/2020.
     * https://docs.microsoft.com/en-us/cpp/c-language/\
     * parsing-c-command-line-arguments?view=msvc-160
     */
    { "\"a b c\" d e",          3, { "a b c",    "d",     "e" }},
    { "\"ab\\\"c\" \"\\\\\" d", 3, { "ab\"c",    "\\",    "d" }},
    { "a\\\\\\b d\"e f\"g h",   3, { "a\\\\\\b", "de fg", "h" }},
    { "a\\\\\\\"b c d",         3, { "a\\\"b",   "c",     "d" }},
    { "a\\\\\\\\\"b c\" d e",   3, { "a\\\\b c", "d",     "e" }},
    { "a\"b\"\" c d",           1, { "ab\" c d"               }},
    /* Some arbitrary tests created using mingw.
     * But I am not sure whether their parser is fully correct.
     */
    { "e:a  a b\"c\" ",       3, { "e:a", "a", "bc" }},
    /* { "e:a  a b\"c\"\" d\"\"e \" ", */
    /*   5, { "e:a", "a", "bc\"", "de", " " }}, */
    /* { "e:a  a b\"c\"\" d\"\"e\" f\\gh ", */
    /*   4, { "e:a", "a", "bc\"", "de f\\gh "}}, */
    /* { "e:a  a b\"c\"\" d\"\"e\" f\\\"gh \" ", */
    /*   4, { "e:a", "a", "bc\"", "de f\"gh " }},*/

    { "\"foo bar\"", 1 , { "foo bar" }},

#ifndef HAVE_W32_SYSTEM
    /* We actually don't use this code on Unix but we provide a way to
     * test some of the blobing code. */
    { "foo",  1, { "foo"                 }, 1 },
    { "foo*", 2, { "[* follows]", "foo*" }, 1 },
    { "foo?", 2, { "[? follows]", "foo?" }, 1 },
    { "? \"*\" *", 5, { "[? follows]", "?", "*", "[* follows]", "*" }, 1 },
#endif /*!HAVE_W32_SYSTEM*/
    { "", 1 , { "" }}
  };
  int tidx;
  int i, any, itemsalloced, argc;
  char *cmdline;
  char **argv;

  for (tidx = 0; tidx < DIM(tests); tidx++)
    {
      cmdline = xstrdup (tests[tidx].cmdline);
      if (verbose && tidx)
        putchar ('\n');
      if (verbose)
        printf ("test %d: line    ->%s<-\n", tidx, cmdline);
      argv = w32_parse_commandline (cmdline, tests[tidx].use_glob,
                                    &argc, &itemsalloced);
      if (!argv)
        {
          fail (tidx);
          xfree (cmdline);
          continue;
        }
      if (tests[tidx].argc != argc)
        {
          fprintf (stderr, PGM": test %d: argc wrong (want %d, got %d)\n",
                   tidx, tests[tidx].argc, argc);
          any = 1;
        }
      else
        any = 0;
      for (i=0; i < tests[tidx].argc; i++)
        {
          if (verbose)
            printf ("test %d: argv[%d] ->%s<-\n",
                    tidx, i, tests[tidx].argv[i]);
          if (i < argc && strcmp (tests[tidx].argv[i], argv[i]))
            {
              if (verbose)
                printf ("test %d:  got[%d] ->%s<- ERROR\n",
                        tidx, i, argv[i]);
              any = 1;
            }
        }
      if (any)
        {
          fprintf (stderr, PGM": test %d: error%s\n",
                   tidx, verbose? "":" (use --verbose)");
          errcount++;
        }

      if (itemsalloced)
        {
          for (i=0; i < argc; i++)
            xfree (argv[i]);
        }
      xfree (argv);
      xfree (cmdline);
    }
}



int
main (int argc, char **argv)
{
  int last_argc = -1;

  no_exit_on_fail = 1;

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
          fputs ("usage: " PGM " [test args]\n"
                 "Options:\n"
                 "  --verbose         Print timings etc.\n"
                 "  --debug           Flyswatter\n"
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
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (argc)
    {
#ifdef HAVE_W32_SYSTEM
      const wchar_t *wcmdline;
      char *cmdline;
      int i, myargc;
      char **myargv;

      wcmdline = GetCommandLineW ();
      if (!wcmdline)
        {
          fprintf (stderr, PGM ": GetCommandLine failed\n");
          exit (1);
        }

      cmdline = wchar_to_utf8 (wcmdline);
      if (!cmdline)
        {
          fprintf (stderr, PGM ": wchar_to_utf8 failed\n");
          exit (1);
        }

      printf ("cmdline ->%s<\n", cmdline);
      myargv = w32_parse_commandline (cmdline, 1, &myargc, NULL);
      if (!myargv)
        {
          fprintf (stderr, PGM ": w32_parse_commandline failed\n");
          exit (1);
        }

      for (i=0; i < myargc; i++)
        printf ("argv[%d] ->%s<-\n", i, myargv[i]);
      fflush (stdout);

      xfree (myargv);
      xfree (cmdline);
#else
      fprintf (stderr, PGM ": manual test mode not available on Unix\n");
      errcount++;
#endif
    }
  else
    test_all ();

  return !!errcount;
}
