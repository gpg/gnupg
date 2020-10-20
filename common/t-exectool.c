/* t-exectool.c - Module test for exectool.c
 * Copyright (C) 2016 g10 Code GmbH
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
#include <unistd.h>

#include "util.h"
#include "exectool.h"

static int verbose;

#define fail(msg, err)                                           \
  do { fprintf (stderr, "%s:%d: %s failed: %s\n",                \
                __FILE__,__LINE__, (msg), gpg_strerror (err));   \
    exit (1);                                                    \
  } while(0)

static void
test_executing_true (void)
{
  gpg_error_t err;
  const char *pgmname     = "/bin/true";
  const char *alt_pgmname = "/usr/bin/true";
  const char *argv[]     = { NULL, NULL };
  char *result;
  size_t len;

  /* Fixme: We should use gpgrt_access here.  */
  if (access (pgmname, X_OK))
    {
      if (access (alt_pgmname, X_OK))
        {
          fprintf (stderr, "skipping test: %s not executable: %s\n",
                   pgmname, strerror (errno));
          return;
        }
      pgmname = alt_pgmname;
    }

  if (verbose)
    fprintf (stderr, "Executing %s...\n", pgmname);

  err = gnupg_exec_tool (pgmname, argv, "", &result, &len);
  if (err)
    fail ("gnupg_exec_tool", err);

  assert (result);
  assert (len == 0);
  free (result);
}

static void
test_executing_false (void)
{
  gpg_error_t err;
  const char *pgmname     = "/bin/false";
  const char *alt_pgmname = "/usr/bin/false";
  const char *argv[]     = { NULL, NULL };
  char *result;
  size_t len;

  if (access (pgmname, X_OK))
    {
      if (access (alt_pgmname, X_OK))
        {
          fprintf (stderr, "skipping test: %s not executable: %s\n",
                   pgmname, strerror (errno));
          return;
        }
      pgmname = alt_pgmname;
    }

  if (verbose)
    fprintf (stderr, "Executing %s...\n", pgmname);

  err = gnupg_exec_tool (pgmname, argv, "", &result, &len);
  assert (err == GPG_ERR_GENERAL);
}


static void
test_executing_cat (const char *vector)
{
  gpg_error_t err;
  const char *argv[] = { "/bin/cat", NULL };
  char *result;
  size_t len;

  if (access (argv[0], X_OK))
    {
      fprintf (stderr, "skipping test: %s not executable: %s\n",
               argv[0], strerror (errno));
      return;
    }

  if (verbose)
    fprintf (stderr, "Executing %s...\n", argv[0]);

  err = gnupg_exec_tool (argv[0], &argv[1], vector, &result, &len);
  if (err)
    fail ("gnupg_exec_tool", err);

  assert (result);

  /* gnupg_exec_tool returns the correct length... */
  assert (len == strlen (vector));
  /* ... but 0-terminates data for ease of use.  */
  assert (result[len] == 0);

  assert (strcmp (result, vector) == 0);
  free (result);
}


static void
test_catting_cat (void)
{
  gpg_error_t err;
  const char *argv[] = { "/bin/cat", "/bin/cat", NULL };
  char *result;
  size_t len;
  estream_t in;
  char *reference, *p;
  size_t reference_len;

  if (access (argv[0], X_OK))
    {
      fprintf (stderr, "skipping test: %s not executable: %s\n",
               argv[0], strerror (errno));
      return;
    }

  in = es_fopen (argv[1], "r");
  if (in == NULL)
    {
      fprintf (stderr, "skipping test: could not open %s: %s\n",
               argv[1], strerror (errno));
      return;
    }

  err = es_fseek (in, 0L, SEEK_END);
  if (err)
    {
      fprintf (stderr, "skipping test: could not seek in %s: %s\n",
               argv[1], gpg_strerror (err));
      return;
    }

  reference_len = es_ftell (in);
  err = es_fseek (in, 0L, SEEK_SET);
  assert (!err || !"rewinding failed");

  reference = malloc (reference_len);
  assert (reference || !"allocating reference buffer failed");

  for (p = reference; p - reference < reference_len; )
    {
      size_t bytes_read, left;
      left = reference_len - (p - reference);
      if (left > 4096)
        left = 4096;
      err = es_read (in, p, left, &bytes_read);
      if (err)
        {
          fprintf (stderr, "error reading %s: %s",
                   argv[1], gpg_strerror (err));
          exit (1);
        }

      p += bytes_read;
    }
  es_fclose (in);

  if (verbose)
    fprintf (stderr, "Executing %s %s...\n", argv[0], argv[1]);

  err = gnupg_exec_tool (argv[0], &argv[1], "", &result, &len);
  if (err)
    fail ("gnupg_exec_tool", err);

  assert (result);

  /* gnupg_exec_tool returns the correct length... */
  assert (len == reference_len);
  assert (memcmp (result, reference, reference_len) == 0);
  free (reference);
  free (result);
}


int
main (int argc, char **argv)
{
  int i;
  char binjunk[256];

  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  test_executing_true ();
  test_executing_false ();
  test_executing_cat ("Talking to myself here...");

  for (i = 0; i < 255 /* one less */; i++)
    binjunk[i] = i + 1;	/* avoid 0 */
  binjunk[255] = 0;

  test_executing_cat (binjunk);
  test_catting_cat ();

  return 0;
}
