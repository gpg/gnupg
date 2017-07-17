/* t-stringhelp.c - Regression tests for stringhelp.c
 * Copyright (C) 2007 Free Software Foundation, Inc.
 *               2015  g10 Code GmbH
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>

#include "t-support.h"
#include "stringhelp.h"


static char *home_buffer;


const char *
gethome (void)
{
  if (!home_buffer)
    {
      char *home = getenv("HOME");

      if(home)
        home_buffer = xstrdup (home);
#if defined(HAVE_GETPWUID) && defined(HAVE_PWD_H)
      else
        {
          struct passwd *pwd;

          pwd = getpwuid (getuid());
          if (pwd)
            home_buffer = xstrdup (pwd->pw_dir);
        }
#endif
    }
  return home_buffer;
}


static char *
mygetcwd (void)
{
  char *buffer;
  size_t size = 100;

  for (;;)
    {
      buffer = xmalloc (size+1);
#ifdef HAVE_W32CE_SYSTEM
      strcpy (buffer, "/");  /* Always "/".  */
      return buffer;
#else
      if (getcwd (buffer, size) == buffer)
        return buffer;
      xfree (buffer);
      if (errno != ERANGE)
        {
          fprintf (stderr,"error getting current cwd: %s\n",
                   strerror (errno));
          exit (2);
        }
      size *= 2;
#endif
    }
}


static void
test_percent_escape (void)
{
  char *result;
  static struct {
    const char *extra;
    const char *value;
    const char *expected;
  } tests[] =
    {
      { NULL, "", "" },
      { NULL, "%", "%25" },
      { NULL, "%%", "%25%25" },
      { NULL, " %", " %25" },
      { NULL, ":", "%3a" },
      { NULL, " :", " %3a" },
      { NULL, ": ", "%3a " },
      { NULL, " : ", " %3a " },
      { NULL, "::", "%3a%3a" },
      { NULL, ": :", "%3a %3a" },
      { NULL, "%:", "%25%3a" },
      { NULL, ":%", "%3a%25" },
      { "\\\n:", ":%", "%3a%25" },
      { "\\\n:", "\\:%", "%5c%3a%25" },
      { "\\\n:", "\n:%", "%0a%3a%25" },
      { "\\\n:", "\xff:%", "\xff%3a%25" },
      { "\\\n:", "\xfe:%", "\xfe%3a%25" },
      { "\\\n:", "\x01:%", "\x01%3a%25" },
      { "\x01",  "\x01:%", "%01%3a%25" },
      { "\xfe",  "\xfe:%", "%fe%3a%25" },
      { "\xfe",  "\xff:%", "\xff%3a%25" },

      { NULL, NULL, NULL }
    };
  int testno;

  result = percent_escape (NULL, NULL);
  if (result)
    fail (0);
  for (testno=0; tests[testno].value; testno++)
    {
      result = percent_escape (tests[testno].value, tests[testno].extra);
      if (!result)
        fail (testno);
      else if (strcmp (result, tests[testno].expected))
        fail (testno);
      xfree (result);
    }

}


static void
test_compare_filenames (void)
{
  struct {
    const char *a;
    const char *b;
    int result;
  } tests[] = {
    { "", "", 0 },
    { "", "a", -1 },
    { "a", "", 1 },
    { "a", "a", 0 },
    { "a", "aa", -1 },
    { "aa", "a", 1 },
    { "a",  "b", -1  },

#ifdef HAVE_W32_SYSTEM
    { "a", "A", 0 },
    { "A", "a", 0 },
    { "foo/bar", "foo\\bar", 0 },
    { "foo\\bar", "foo/bar", 0 },
    { "foo\\", "foo/", 0 },
    { "foo/", "foo\\", 0 },
#endif /*HAVE_W32_SYSTEM*/
    { NULL, NULL, 0}
  };
  int testno, result;

  for (testno=0; tests[testno].a; testno++)
    {
      result = compare_filenames (tests[testno].a, tests[testno].b);
      result = result < 0? -1 : result > 0? 1 : 0;
      if (result != tests[testno].result)
        fail (testno);
    }
}


static void
test_strconcat (void)
{
  char *out;

  out = strconcat ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", NULL);
  if (!out)
    fail (0);
  else
    xfree (out);
  out = strconcat ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", NULL);
  if (out)
    fail (0);
  else if (errno != EINVAL)
    fail (0);

  out = strconcat ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", NULL);
  if (out)
    fail (0);
  else if (errno != EINVAL)
    fail (0);
  xfree (out);

#if __GNUC__ < 4 /* gcc 4.0 has a sentinel attribute.  */
  out = strconcat (NULL);
  if (!out || *out)
    fail (1);
#endif
  out = strconcat (NULL, NULL);
  if (!out || *out)
    fail (1);
  xfree (out);

  out = strconcat ("", NULL);
  if (!out || *out)
    fail (1);
  xfree (out);

  out = strconcat ("", "", NULL);
  if (!out || *out)
    fail (2);
  xfree (out);

  out = strconcat ("a", "b", NULL);
  if (!out || strcmp (out, "ab"))
    fail (3);
  xfree (out);
  out = strconcat ("a", "b", "c", NULL);
  if (!out || strcmp (out, "abc"))
    fail (3);
  xfree (out);

  out = strconcat ("a", "b", "cc", NULL);
  if (!out || strcmp (out, "abcc"))
    fail (4);
  xfree (out);
  out = strconcat ("a1", "b1", "c1", NULL);
  if (!out || strcmp (out, "a1b1c1"))
    fail (4);
  xfree (out);

  out = strconcat ("", " long b ", "", "--even-longer--", NULL);
  if (!out || strcmp (out, " long b --even-longer--"))
    fail (5);
  xfree (out);

  out = strconcat ("", " long b ", "", "--even-longer--", NULL);
  if (!out || strcmp (out, " long b --even-longer--"))
    fail (5);
  xfree (out);
}

static void
test_xstrconcat (void)
{
  char *out;

  out = xstrconcat ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                   "1", "2", "3", "4", "5", "6", "7", NULL);
  if (!out)
    fail (0);
  xfree (out);

#if __GNUC__ < 4 /* gcc 4.0 has a sentinel attribute.  */
  out = xstrconcat (NULL);
  if (!out)
    fail (1);
#endif
  out = xstrconcat (NULL, NULL);
  if (!out)
    fail (1);
  xfree (out);

  out = xstrconcat ("", NULL);
  if (!out || *out)
    fail (1);
  xfree (out);

  out = xstrconcat ("", "", NULL);
  if (!out || *out)
    fail (2);
  xfree (out);

  out = xstrconcat ("a", "b", NULL);
  if (!out || strcmp (out, "ab"))
    fail (3);
  xfree (out);
  out = xstrconcat ("a", "b", "c", NULL);
  if (!out || strcmp (out, "abc"))
    fail (3);
  xfree (out);

  out = xstrconcat ("a", "b", "cc", NULL);
  if (!out || strcmp (out, "abcc"))
    fail (4);
  xfree (out);
  out = xstrconcat ("a1", "b1", "c1", NULL);
  if (!out || strcmp (out, "a1b1c1"))
    fail (4);
  xfree (out);

  out = xstrconcat ("", " long b ", "", "--even-longer--", NULL);
  if (!out || strcmp (out, " long b --even-longer--"))
    fail (5);
  xfree (out);

  out = xstrconcat ("", " long b ", "", "--even-longer--", NULL);
  if (!out || strcmp (out, " long b --even-longer--"))
    fail (5);
  xfree (out);
}


static void
test_make_filename_try (void)
{
  char *out;
  const char *home = gethome ();
  size_t homelen = home? strlen (home):0;

  out = make_filename_try ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", NULL);
  if (out)
    fail (0);
  else if (errno != EINVAL)
    fail (0);
  xfree (out);
  out = make_filename_try ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", NULL);
  if (out)
    fail (0);
  else if (errno != EINVAL)
    fail (0);
  xfree (out);

  out = make_filename_try ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                           "1", "2", NULL);
  if (!out || strcmp (out,
                      "1/2/3/4/5/6/7/8/9/10/"
                      "1/2/3/4/5/6/7/8/9/10/"
                      "1/2/3/4/5/6/7/8/9/10/"
                      "1/2"))
    fail (0);
  xfree (out);

  out = make_filename_try ("foo", "~/bar", "baz/cde", NULL);
  if (!out || strcmp (out, "foo/~/bar/baz/cde"))
    fail (1);
  xfree (out);

  out = make_filename_try ("foo", "~/bar", "baz/cde/", NULL);
  if (!out || strcmp (out, "foo/~/bar/baz/cde/"))
    fail (1);
  xfree (out);

  out = make_filename_try ("/foo", "~/bar", "baz/cde/", NULL);
  if (!out || strcmp (out, "/foo/~/bar/baz/cde/"))
    fail (1);
  xfree (out);

  out = make_filename_try ("//foo", "~/bar", "baz/cde/", NULL);
  if (!out || strcmp (out, "//foo/~/bar/baz/cde/"))
    fail (1);
  xfree (out);

  out = make_filename_try ("", "~/bar", "baz/cde", NULL);
  if (!out || strcmp (out, "/~/bar/baz/cde"))
    fail (1);
  xfree (out);


  out = make_filename_try ("~/foo", "bar", NULL);
  if (!out)
    fail (2);
  else if (home)
    {
      if (strlen (out) < homelen + 7)
        fail (2);
      else if (strncmp (out, home, homelen))
        fail (2);
      else if (strcmp (out+homelen, "/foo/bar"))
        fail (2);
    }
  else
    {
      if (strcmp (out, "~/foo/bar"))
        fail (2);
    }
  xfree (out);

  out = make_filename_try ("~", "bar", NULL);
  if (!out)
    fail (2);
  else if (home)
    {
      if (strlen (out) < homelen + 3)
        fail (2);
      else if (strncmp (out, home, homelen))
        fail (2);
      else if (strcmp (out+homelen, "/bar"))
        fail (2);
    }
  else
    {
      if (strcmp (out, "~/bar"))
        fail (2);
    }
  xfree (out);
}


static void
test_make_absfilename_try (void)
{
  char *out;
  char *cwd = mygetcwd ();
  size_t cwdlen = strlen (cwd);

  out = make_absfilename_try ("foo", "bar", NULL);
  if (!out)
    fail (0);
  else if (strlen (out) < cwdlen + 7)
    fail (0);
  else if (strncmp (out, cwd, cwdlen))
    fail (0);
  else if (strcmp (out+cwdlen, "/foo/bar"))
    fail (0);
  xfree (out);

  out = make_absfilename_try ("./foo", NULL);
  if (!out)
    fail (1);
  else if (strlen (out) < cwdlen + 5)
    fail (1);
  else if (strncmp (out, cwd, cwdlen))
    fail (1);
  else if (strcmp (out+cwdlen, "/./foo"))
    fail (1);
  xfree (out);

  out = make_absfilename_try (".", NULL);
  if (!out)
    fail (2);
  else if (strlen (out) < cwdlen)
    fail (2);
  else if (strncmp (out, cwd, cwdlen))
    fail (2);
  else if (strcmp (out+cwdlen, ""))
    fail (2);
  xfree (out);

  xfree (cwd);
}

static void
test_strsplit (void)
{
  struct {
    const char *s;
    char delim;
    char replacement;
    const char *fields_expected[10];
  } tv[] = {
    {
      "a:bc:cde:fghi:jklmn::foo:", ':', '\0',
      { "a", "bc", "cde", "fghi", "jklmn", "", "foo", "", NULL }
    },
    {
      ",a,bc,,def,", ',', '!',
      { "!a!bc!!def!", "a!bc!!def!", "bc!!def!", "!def!", "def!", "", NULL }
    },
    {
      "", ':', ',',
      { "", NULL }
    }
  };

  int tidx;

  for (tidx = 0; tidx < DIM(tv); tidx++)
    {
      char *s2;
      int field_count;
      char **fields;
      int field_count_expected;
      int i;

      /* Count the fields.  */
      for (field_count_expected = 0;
           tv[tidx].fields_expected[field_count_expected];
           field_count_expected ++)
        ;

      /* We need to copy s since strsplit modifies it in place.  */
      s2 = xstrdup (tv[tidx].s);
      fields = strsplit (s2, tv[tidx].delim, tv[tidx].replacement,
                         &field_count);

      if (field_count != field_count_expected)
        fail (tidx * 1000);

      for (i = 0; i < field_count_expected; i ++)
        if (strcmp (tv[tidx].fields_expected[i], fields[i]) != 0)
          {
            printf ("For field %d, expected '%s', but got '%s'\n",
                    i, tv[tidx].fields_expected[i], fields[i]);
            fail (tidx * 1000 + i + 1);
          }

      xfree (fields);
      xfree (s2);
    }
}



static void
test_strtokenize (void)
{
  struct {
    const char *s;
    const char *delim;
    const char *fields_expected[10];
  } tv[] = {
    {
      "", ":",
      { "", NULL }
    },
    {
      "a", ":",
      { "a", NULL }
    },
    {
      ":", ":",
      { "", "", NULL }
    },
    {
      "::", ":",
      { "", "", "", NULL }
    },
    {
      "a:b:c", ":",
      { "a", "b", "c", NULL }
    },
    {
      "a:b:", ":",
      { "a", "b", "", NULL }
    },
    {
      "a:b", ":",
      { "a", "b", NULL }
    },
    {
      "aa:b:cd", ":",
      { "aa", "b", "cd", NULL }
    },
    {
      "aa::b:cd", ":",
      { "aa", "", "b", "cd", NULL }
    },
    {
      "::b:cd", ":",
      { "", "", "b", "cd", NULL }
    },
    {
      "aa:   : b:cd ", ":",
      { "aa", "", "b", "cd", NULL }
    },
    {
      "  aa:   : b:  cd ", ":",
      { "aa", "", "b", "cd", NULL }
    },
    {
      "  ", ":",
      { "", NULL }
    },
    {
      "  :", ":",
      { "", "", NULL }
    },
    {
      "  : ", ":",
      { "", "", NULL }
    },
    {
      ": ", ":",
      { "", "", NULL }
    },
    {
      ": x ", ":",
      { "", "x", NULL }
    },
    {
      "a:bc:cde:fghi:jklmn::foo:", ":",
      { "a", "bc", "cde", "fghi", "jklmn", "", "foo", "", NULL }
    },
    {
      ",a,bc,,def,", ",",
      { "", "a", "bc", "", "def", "", NULL }
    },
    {
      " a ", " ",
      { "", "a", "", NULL }
    },
    {
      " ", " ",
      { "", "", NULL }
    },
    {
      "", " ",
      { "", NULL }
    }
  };

  int tidx;

  for (tidx = 0; tidx < DIM(tv); tidx++)
    {
      char **fields;
      int field_count;
      int field_count_expected;
      int i;

      for (field_count_expected = 0;
           tv[tidx].fields_expected[field_count_expected];
           field_count_expected ++)
        ;

      fields = strtokenize (tv[tidx].s, tv[tidx].delim);
      if (!fields)
        fail (tidx * 1000);
      else
        {
          for (field_count = 0; fields[field_count]; field_count++)
            ;
          if (field_count != field_count_expected)
            fail (tidx * 1000);
          else
            {
              for (i = 0; i < field_count_expected; i++)
                if (strcmp (tv[tidx].fields_expected[i], fields[i]))
                  {
                    printf ("For field %d, expected '%s', but got '%s'\n",
                            i, tv[tidx].fields_expected[i], fields[i]);
                    fail (tidx * 1000 + i + 1);
                  }
            }
          }

      xfree (fields);
    }
}


static void
test_split_fields (void)
{
  struct {
    const char *s;
    int nfields;
    const char *fields_expected[10];
  } tv[] = {
    {
      "a bc cde fghi jklmn   foo ", 6,
      { "a", "bc", "cde", "fghi", "jklmn", "foo", NULL }
    },
    {
      " a bc  def ", 2,
      { "a", "bc", "def", NULL }
    },
    {
      " a bc  def ", 3,
      { "a", "bc", "def", NULL }
    },
    {
      " a bc  def ", 4,
      { "a", "bc", "def", NULL }
    },
    {
      "", 0,
      { NULL }
    }
  };

  int tidx;
  char *fields[10];
  int field_count_expected, nfields, field_count, i;
  char *s2;

  for (tidx = 0; tidx < DIM(tv); tidx++)
    {
      nfields = tv[tidx].nfields;
      assert (nfields <= DIM (fields));

      /* Count the fields.  */
      for (field_count_expected = 0;
           tv[tidx].fields_expected[field_count_expected];
           field_count_expected ++)
        ;
      if (field_count_expected > nfields)
        field_count_expected = nfields;

      /* We need to copy s since split_fields modifies in place.  */
      s2 = xstrdup (tv[tidx].s);
      field_count = split_fields (s2, fields, nfields);

      if (field_count != field_count_expected)
        {
          printf ("%s: tidx %d: expected %d, got %d\n",
                  __func__, tidx, field_count_expected, field_count);
          fail (tidx * 1000);
        }
      else
        {
          for (i = 0; i < field_count_expected; i ++)
            if (strcmp (tv[tidx].fields_expected[i], fields[i]))
              {
                printf ("%s: tidx %d, field %d: expected '%s', got '%s'\n",
                        __func__,
                        tidx, i, tv[tidx].fields_expected[i], fields[i]);
                fail (tidx * 1000 + i + 1);
              }
        }

      xfree (s2);
    }
}


static void
test_split_fields_colon (void)
{
  struct {
    const char *s;
    int nfields;
    const char *fields_expected[10];
  } tv[] = {
    {
      "a:bc:cde:fghi:jklmn:  foo ", 6,
      { "a", "bc", "cde", "fghi", "jklmn", "  foo ", NULL }
    },
    {
      " a:bc: def ", 2,
      { " a", "bc", NULL }
    },
    {
      " a:bc :def ", 3,
      { " a", "bc ", "def ", NULL }
    },
    {
      " a:bc: def ", 4,
      { " a", "bc", " def ", NULL }
    },
    {
      "", 0,
      { NULL }
    }
  };

  int tidx;
  char *fields[10];
  int field_count_expected, nfields, field_count, i;
  char *s2;

  for (tidx = 0; tidx < DIM(tv); tidx++)
    {
      nfields = tv[tidx].nfields;
      assert (nfields <= DIM (fields));

      /* Count the fields.  */
      for (field_count_expected = 0;
           tv[tidx].fields_expected[field_count_expected];
           field_count_expected ++)
        ;
      if (field_count_expected > nfields)
        field_count_expected = nfields;

      /* We need to copy s since split_fields modifies in place.  */
      s2 = xstrdup (tv[tidx].s);
      field_count = split_fields_colon (s2, fields, nfields);

      if (field_count != field_count_expected)
        {
          printf ("%s: tidx %d: expected %d, got %d\n",
                  __func__, tidx, field_count_expected, field_count);
          fail (tidx * 1000);
        }
      else
        {
          for (i = 0; i < field_count_expected; i ++)
            if (strcmp (tv[tidx].fields_expected[i], fields[i]))
              {
                printf ("%s: tidx %d, field %d: expected '%s', got '%s'\n",
                        __func__,
                        tidx, i, tv[tidx].fields_expected[i], fields[i]);
                fail (tidx * 1000 + i + 1);
              }
        }

      xfree (s2);
    }
}


static char *
stresc (char *s)
{
  char *p;
  int l = strlen (s) + 1;

  for (p = s; *p; p ++)
    if (*p == '\n')
      l ++;

  p = xmalloc (l);
  for (l = 0; *s; s ++, l ++)
    {
      if (*s == ' ')
        p[l] = '_';
      else if (*p == '\n')
        {
          p[l ++] = '\\';
          p[l ++] = 'n';
          p[l] = '\n';
        }
      else
        p[l] = *s;
    }
  p[l] = *s;

  return p;
}


static void
test_format_text (void)
{
  struct test
  {
    int target_cols, max_cols;
    char *input;
    char *expected;
  };

  struct test tests[] = {
    {
      10, 12,
      "",
      "",
    },
    {
      10, 12,
      " ",
      "",
    },
    {
      10, 12,
      "  ",
      "",
    },
    {
      10, 12,
      " \n ",
      " \n",
    },
    {
      10, 12,
      " \n  \n ",
      " \n  \n",
    },
    {
      10, 12,
      "0123456789 0123456789 0",
      "0123456789\n0123456789\n0",
    },
    {
      10, 12,
      "   0123456789   0123456789   0  ",
      "   0123456789\n0123456789\n0",
    },
    {
      10, 12,
      "01 34 67 90 23 56  89 12 45 67 89 1",
      "01 34 67\n90 23 56\n89 12 45\n67 89 1"
    },
    {
      10, 12,
      "01 34 67 90 23 56  89 12 45 67 89 1",
      "01 34 67\n90 23 56\n89 12 45\n67 89 1"
    },
    {
      72, 80,
      "Warning: if you think you've seen more than 10 messages "
      "signed by this key, then this key might be a forgery!  "
      "Carefully examine the email address for small variations "
      "(e.g., additional white space).  If the key is suspect, "
      "then use 'gpg --tofu-policy bad \"FINGERPRINT\"' to mark it as being bad.\n",
      "Warning: if you think you've seen more than 10 messages signed by this\n"
      "key, then this key might be a forgery!  Carefully examine the email\n"
      "address for small variations (e.g., additional white space).  If the key\n"
      "is suspect, then use 'gpg --tofu-policy bad \"FINGERPRINT\"' to mark it as\n"
      "being bad.\n"

    },
    {
      72, 80,
      "Normally, there is only a single key associated with an email "
      "address.  However, people sometimes generate a new key if "
      "their key is too old or they think it might be compromised.  "
      "Alternatively, a new key may indicate a man-in-the-middle "
      "attack!  Before accepting this key, you should talk to or "
      "call the person to make sure this new key is legitimate.",
      "Normally, there is only a single key associated with an email "
      "address.\nHowever, people sometimes generate a new key if "
      "their key is too old or\nthey think it might be compromised.  "
      "Alternatively, a new key may indicate\na man-in-the-middle "
      "attack!  Before accepting this key, you should talk\nto or "
      "call the person to make sure this new key is legitimate.",
    }
  };

  int i;
  int failed = 0;

  for (i = 0; i < sizeof (tests) / sizeof (tests[0]); i ++)
    {
      struct test *test = &tests[i];
      char *result =
        format_text (test->input, test->target_cols, test->max_cols);
      if (!result)
        {
          fail (1);
          exit (2);
        }
      if (strcmp (result, test->expected) != 0)
        {
          printf ("%s: Test #%d failed.\nExpected: '%s'\nResult: '%s'\n",
                  __func__, i + 1, stresc (test->expected), stresc (result));
          failed ++;
        }
      xfree (result);
    }

  if (failed)
    fail(0);
}


static void
test_compare_version_strings (void)
{
  struct { const char *a; const char *b; int okay; } tests[] = {
    { "1.0.0",   "1.0.0", 0 },
    { "1.0.0-",  "1.0.0", 1 },
    { "1.0.0-1", "1.0.0", 1 },
    { "1.0.0.1", "1.0.0", 1 },
    { "1.0.0",   "1.0.1", -1 },
    { "1.0.0-",  "1.0.1", -1 },
    { "1.0.0-1", "1.0.1", -1 },
    { "1.0.0.1", "1.0.1", -1 },
    { "1.0.0",   "1.1.0", -1 },
    { "1.0.0-",  "1.1.0", -1 },
    { "1.0.0-1", "1.1.0", -1 },
    { "1.0.0.1", "1.1.0", -1 },

    { "1.0.0",   "1.0.0-", -1 },
    { "1.0.0",   "1.0.0-1", -1 },
    { "1.0.0",   "1.0.0.1", -1 },
    { "1.1.0",   "1.0.0", 1 },
    { "1.1.1",   "1.1.0", 1 },
    { "1.1.2",   "1.1.2", 0 },
    { "1.1.2",   "1.0.2", 1 },
    { "1.1.2",   "0.0.2", 1 },
    { "1.1.2",   "1.1.3", -1 },

    { "0.99.1",  "0.9.9", 1 },
    { "0.9.1",   "0.91.0", -1 },

    { "1.5.3",   "1.5",  1 },
    { "1.5.0",   "1.5",  0 },
    { "1.4.99",  "1.5",  -1 },
    { "1.5",     "1.4.99",  1 },
    { "1.5",     "1.5.0",  0 },
    { "1.5",     "1.5.1",  -1 },

    { "1.5.3-x17",   "1.5-23",  1 },

    { "1.5.3a",   "1.5.3",  1 },
    { "1.5.3a",   "1.5.3b",  -1 },

    { "3.1.4-ab", "3.1.4-ab", 0 },
    { "3.1.4-ab", "3.1.4-ac", -1 },
    { "3.1.4-ac", "3.1.4-ab", 1 },
    { "3.1.4-ab", "3.1.4-abb", -1 },
    { "3.1.4-abb", "3.1.4-ab", 1 },

    { "",       "",   INT_MIN },
    { NULL,     "",   INT_MIN },
    { "1.2.3",  "",   INT_MIN },
    { "1.2.3",  "2",  INT_MIN },

    /* Test cases for validity of A.  */
    { "",      NULL, INT_MIN },
    { "1",     NULL, INT_MIN },
    { "1.",    NULL, 0       },
    { "1.0",   NULL, 0       },
    { "1.0.",  NULL, 0       },
    { "a1.2",  NULL, INT_MIN },
    { NULL,    NULL, INT_MIN }
  };
  int idx;
  int res;

  for (idx=0; idx < DIM(tests); idx++)
    {
      res = compare_version_strings (tests[idx].a, tests[idx].b);
      /* printf ("test %d: '%s'  '%s'  %d  ->  %d\n", */
      /*         idx, tests[idx].a, tests[idx].b, tests[idx].okay, res); */
      if (res != tests[idx].okay)
        fail (idx);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_percent_escape ();
  test_compare_filenames ();
  test_strconcat ();
  test_xstrconcat ();
  test_make_filename_try ();
  test_make_absfilename_try ();
  test_strsplit ();
  test_strtokenize ();
  test_split_fields ();
  test_split_fields_colon ();
  test_compare_version_strings ();
  test_format_text ();

  xfree (home_buffer);
  return !!errcount;
}
