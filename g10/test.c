/* test.c - Infrastructure for unit tests.
 * Copyright (C) 2015 g10 Code GmbH
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

#define INCLUDED_BY_MAIN_MODULE 1
#include "gpg.h"

/* A unit test consists of one or more tests.  Tests can be broken
   into groups and each group can consist of one or more tests.  */

/* The number of test groups.  */
static int test_groups;
/* The current test group.  */
static char *test_group;

/* Whether there was already a failure in the current test group.  */
static int current_test_group_failed;
/* The number of test groups with a failure.  */
static int test_groups_failed;

/* The total number of tests.  */
static int tests;
/* The total number of tests that failed.  */
static int tests_failed;

/* Flag to request verbose diagnostics.  This is set if the envvar
   "verbose" exists and is not the empty string.  */
static int verbose;

#define TEST_GROUP(description)	     \
  do {				     \
    test_group = (description);	     \
    test_groups ++;		     \
    current_test_group_failed = 0;   \
  } while (0)

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)

/* Execute a test.  */
#define TEST(description, test, expected)	\
  do {						\
    int test_result;				\
    int expected_result;			\
						\
    tests ++;					\
    if (verbose)                                \
      {                                         \
         printf ("%d. Checking %s...",		\
	        tests, (description) ?: "");	\
         fflush (stdout);			\
      }                                         \
    test_result = (test);			\
    expected_result = (expected);		\
						\
    if (test_result == expected_result)		\
      {						\
        if (verbose) printf (" ok.\n");         \
      }						\
    else					\
      {						\
        if (!verbose)                           \
          printf ("%d. Checking %s...",         \
                  tests, (description) ?: "");  \
	printf (" failed.\n");			\
	printf ("  %s == %s failed.\n",		\
		STRINGIFY(test),		\
		STRINGIFY(expected));		\
	tests_failed ++;			\
	if (! current_test_group_failed)	\
	  {					\
	    current_test_group_failed = 1;	\
	    test_groups_failed ++;		\
	  }					\
      }						\
  } while (0)

/* Test that a condition evaluates to true.  */
#define TEST_P(description, test)		\
  TEST(description, !!(test), 1)

/* Like CHECK, but if the test fails, abort the program.  */
#define ASSERT(description, test, expected)		\
  do {							\
    int tests_failed_pre = tests_failed;		\
    CHECK(description, test, expected);			\
    if (tests_failed_pre != tests_failed)		\
      exit_tests (1);					\
  } while (0)

/* Call this if something went wrong.  */
#define ABORT(message)				\
  do {						\
    printf ("aborting...");			\
    if (message)				\
      printf (" %s\n", (message));		\
						\
    exit_tests (1);				\
  } while (0)

/* You need to fill this function in.  */
static void do_test (int argc, char *argv[]);


/* Print stats and call the real exit.  If FORCE is set use
   EXIT_FAILURE even if no test has failed.  */
static void
exit_tests (int force)
{
  if (tests_failed == 0)
    {
      if (verbose)
        printf ("All %d tests passed.\n", tests);
      exit (!!force);
    }
  else
    {
      printf ("%d of %d tests failed",
	      tests_failed, tests);
      if (test_groups > 1)
	printf (" (%d of %d groups)",
		test_groups_failed, test_groups);
      printf ("\n");
      exit (1);
    }
}


/* Prepend FNAME with the srcdir environment variable's value and
   return a malloced filename.  Caller must release the returned
   string using test_free.  */
char *
prepend_srcdir (const char *fname)
{
  static const char *srcdir;
  char *result;

  if (!srcdir && !(srcdir = getenv ("abs_top_srcdir")))
    srcdir = ".";

  result = malloc (strlen (srcdir) + strlen ("/g10/") + strlen (fname) + 1);
  strcpy (result, srcdir);
  strcat (result, "/g10/");
  strcat (result, fname);
  return result;
}


void
test_free (void *a)
{
  if (a)
    free (a);
}


int
main (int argc, char *argv[])
{
  const char *s;

  (void) test_group;

  s = getenv ("verbose");
  if (s && *s)
    verbose = 1;

  do_test (argc, argv);
  exit_tests (0);

  return !!tests_failed;
}
