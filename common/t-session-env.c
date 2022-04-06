/* t-session-env.c - Module test for session-env.c
 *	Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <errno.h>
#include <assert.h>

#include "util.h"
#include "session-env.h"

#define pass()  do { ; } while(0)
#define fail(e) do { fprintf (stderr, "%s:%d: function failed: %s\n",  \
                               __FILE__,__LINE__, gpg_strerror (e));  \
                     exit (1);                                        \
                   } while(0)

static int verbose;

static void
listall (session_env_t se)
{
  int iterator = 0;
  const char *name, *value;
  int def;

  if (verbose)
    printf ("environment of %p\n", se);
  while ( (name = session_env_listenv (se, &iterator, &value, &def)) )
    if (verbose)
      printf ("  %s%s=%s\n",  def? "[def] ":"      ", name, value);

}


static void
show_stdnames (void)
{
  const char *name, *assname;
  int iterator = 0;
  int count;

  printf ("    > Known envvars:");
  count = 20;
  while ((name = session_env_list_stdenvnames (&iterator, &assname)))
    {
      if (count > 60)
        {
          printf ("\n    >");
          count = 7;
        }
      printf ( " %s", name);
      count += strlen (name) + 1;
      if (assname)
        {
          printf ( "(%s)", assname);
          count += strlen (assname) + 2;
        }
    }
  putchar('\n');
}


static void
test_all (void)
{
  gpg_error_t err;
  session_env_t se_0, se;
  const char *s, *s2;
  int idx;

  se_0 = session_env_new ();
  if (!se_0)
    fail (gpg_error_from_syserror ());
  se = session_env_new ();
  if (!se)
    fail (gpg_error_from_syserror ());

  err = session_env_putenv (se, NULL);
  if (gpg_err_code (err) != GPG_ERR_INV_VALUE)
    fail (err);
  err = session_env_putenv (se, "");
  if (gpg_err_code (err) != GPG_ERR_INV_VALUE)
    fail (err);
  err = session_env_putenv (se, "=");
  if (gpg_err_code (err) != GPG_ERR_INV_VALUE)
    fail (err);

  /* Delete some nonexistent variables.  */
  err = session_env_putenv (se, "A");
  if (err)
    fail (err);
  err = session_env_putenv (se, "a");
  if (err)
    fail (err);
  err = session_env_putenv (se, "_aaaa aaaaaasssssssssssss\nddd");
  if (err)
    fail (err);

  /* Create a few variables.  */
  err = session_env_putenv (se, "EMPTY=");
  if (err)
    fail (err);
  err = session_env_putenv (se, "foo=value_of_foo");
  if (err)
    fail (err);
  err = session_env_putenv (se, "bar=the value_of_bar");
  if (err)
    fail (err);
  err = session_env_putenv (se, "baz=this-is-baz");
  if (err)
    fail (err);
  err = session_env_putenv (se, "BAZ=this-is-big-baz");
  if (err)
    fail (err);

  listall (se);

  /* Update one.  */
  err = session_env_putenv (se, "baz=this-is-another-baz");
  if (err)
    fail (err);

  listall (se);

  /* Delete one.  */
  err = session_env_putenv (se, "bar");
  if (err)
    fail (err);

  listall (se);

  /* Insert a new one.  */
  err = session_env_putenv (se, "FOO=value_of_foo");
  if (err)
    fail (err);

  listall (se);

#ifndef HAVE_W32_SYSTEM
  /* Retrieve a default one.  */
  s = session_env_getenv_or_default (se, "HOME", NULL);
  if (!s)
    {
      fprintf (stderr, "failed to get default of HOME\n");
      exit (1);
    }
#endif

  s = session_env_getenv (se, "HOME");
  if (s)
    fail(0);  /* This is a default value, thus we should not see it.  */

#ifndef HAVE_W32_SYSTEM
  s = session_env_getenv_or_default (se, "HOME", NULL);
  if (!s)
    fail(0);  /* But here we should see it.  */
#endif

  /* Add a few more.  */
  err = session_env_putenv (se, "X1=A value");
  if (err)
    fail (err);
  err = session_env_putenv (se, "X2=Another value");
  if (err)
    fail (err);
  err = session_env_putenv (se, "X3=A value");
  if (err)
    fail (err);

  listall (se);

  /* Check that we can overwrite a default value.  */
  err = session_env_putenv (se, "HOME=/this/is/my/new/home");
  if (err)
    fail (err);
  /* And that we get this string back.  */
  s = session_env_getenv (se, "HOME");
  if (!s)
    fail (0);
  if (strcmp (s, "/this/is/my/new/home"))
    fail (0);
  /* A new get default should return the very same string.  */
  s2 = session_env_getenv_or_default (se, "HOME", NULL);
  if (!s2)
    fail (0);
  if (s2 != s)
    fail (0);

  listall (se);

  /* Check that the other object is clean.  */
  {
    int iterator = 0;

    if (session_env_listenv (se_0, &iterator, NULL, NULL))
      fail (0);
  }


  session_env_release (se);

  /* Use a new session for quick mass test.  */
  se = session_env_new ();
  if (!se)
    fail (gpg_error_from_syserror ());

  /* Create.  */
  for (idx=0; idx < 500; idx++)
    {
      char buf[100];

      snprintf (buf, sizeof buf, "FOO_%d=Value for %x", idx, idx);
      err = session_env_putenv (se, buf);
      if (err)
        fail (err);
    }
  err = session_env_setenv (se, "TEST1", "value1");
  if (err)
    fail (err);
  err = session_env_setenv (se, "TEST1", "value1-updated");
  if (err)
    fail (err);

  listall (se);

  /* Delete all.  */
  for (idx=0; idx < 500; idx++)
    {
      char buf[100];

      snprintf (buf, sizeof buf, "FOO_%d", idx);
      err = session_env_putenv (se, buf);
      if (err)
        fail (err);
    }
  err = session_env_setenv (se, "TEST1", NULL);
  if (err)
    fail (err);

  /* Check that all are deleted.  */
  {
    int iterator = 0;

    if (session_env_listenv (se, &iterator, NULL, NULL))
      fail (0);
  }

  /* Add a few strings again.  */
  for (idx=0; idx < 500; idx++)
    {
      char buf[100];

      if (!(idx % 10))
        {
          if ( !(idx % 3))
            snprintf (buf, sizeof buf, "FOO_%d=", idx);
          else
            snprintf (buf, sizeof buf, "FOO_%d=new value for %x", idx, idx);
          err = session_env_putenv (se, buf);
          if (err)
            fail (err);
        }
    }

  listall (se);

  session_env_release (se);

  session_env_release (se_0);
}



int
main (int argc, char **argv)
{
  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }


  show_stdnames ();
  test_all ();

  return 0;
}
