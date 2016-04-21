/* t-private-keys.c - Module test for private-keys.c
 *	Copyright (C) 2016 g10 Code GmbH
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "util.h"
#include "private-keys.h"

static int verbose;

void
test_getting_values (pkc_t pk)
{
  pke_t e;

  e = pkc_lookup (pk, "Comment:");
  assert (e);

  /* Names are case-insensitive.  */
  e = pkc_lookup (pk, "comment:");
  assert (e);
  e = pkc_lookup (pk, "COMMENT:");
  assert (e);

  e = pkc_lookup (pk, "SomeOtherName:");
  assert (e);
}


void
test_key_extraction (pkc_t pk)
{
  gpg_error_t err;
  gcry_sexp_t key;

  err = pkc_get_private_key (pk, &key);
  assert (err == 0);
  assert (key);

  if (verbose)
    gcry_sexp_dump (key);

  gcry_sexp_release (key);
}


void
test_iteration (pkc_t pk)
{
  int i;
  pke_t e;

  i = 0;
  for (e = pkc_first (pk); e; e = pke_next (e))
    i++;
  assert (i == 4);

  i = 0;
  for (e = pkc_lookup (pk, "Comment:");
       e;
       e = pke_next_value (e, "Comment:"))
    i++;
  assert (i == 3);
}


void
test_whitespace (pkc_t pk)
{
  pke_t e;

  e = pkc_lookup (pk, "One:");
  assert (e);
  assert (strcmp (pke_value (e), "WithoutWhitespace") == 0);

  e = pkc_lookup (pk, "Two:");
  assert (e);
  assert (strcmp (pke_value (e), "With Whitespace") == 0);

  e = pkc_lookup (pk, "Three:");
  assert (e);
  assert (strcmp (pke_value (e),
                  "Blank lines in continuations encode newlines.\n"
                  "Next paragraph.") == 0);
}


struct
{
  char *value;
  void (*test_func) (pkc_t);
} tests[] =
  {
    {
      "# This is a comment followed by an empty line\n"
      "\n",
      NULL,
    },
    {
      "# This is a comment followed by two empty lines, Windows style\r\n"
      "\r\n"
      "\r\n",
      NULL,
    },
    {
      "# Some name,value pairs\n"
      "Comment: Some comment.\n"
      "SomeOtherName: Some value.\n",
      test_getting_values,
    },
    {
      "  # Whitespace is preserved as much as possible\r\n"
      "Comment:Some comment.\n"
      "SomeOtherName: Some value.   \n",
      test_getting_values,
    },
    {
      "# Values may be continued in the next line as indicated by leading\n"
      "# space\n"
      "Comment: Some rather long\n"
      "  comment that is continued in the next line.\n"
      "\n"
      "  Blank lines with or without whitespace are allowed within\n"
      "  continuations to allow paragraphs.\n"
      "SomeOtherName: Some value.\n",
      test_getting_values,
    },
    {
      "# Names may be given multiple times forming an array of values\n"
      "Comment: Some comment, element 0.\n"
      "Comment: Some comment, element 1.\n"
      "Comment: Some comment, element 2.\n"
      "SomeOtherName: Some value.\n",
      test_iteration,
    },
    {
      "# One whitespace at the beginning of a continuation is swallowed.\n"
      "One: Without\n"
      " Whitespace\n"
      "Two: With\n"
      "  Whitespace\n"
      "Three: Blank lines in continuations encode newlines.\n"
      "\n"
      "  Next paragraph.\n",
      test_whitespace,
    },
    {
      "Description: Key to sign all GnuPG released tarballs.\n"
      "  The key is actually stored on a smart card.\n"
      "Use-for-ssh: yes\n"
      "OpenSSH-cert: long base64 encoded string wrapped so that this\n"
      "  key file can be easily edited with a standard editor.\n"
      "Key: (shadowed-private-key\n"
      "  (rsa\n"
      "  (n #00AA1AD2A55FD8C8FDE9E1941772D9CC903FA43B268CB1B5A1BAFDC900\n"
      "  2961D8AEA153424DC851EF13B83AC64FBE365C59DC1BD3E83017C90D4365B4\n"
      "  83E02859FC13DB5842A00E969480DB96CE6F7D1C03600392B8E08EF0C01FC7\n"
      "  19F9F9086B25AD39B4F1C2A2DF3E2BE317110CFFF21D4A11455508FE407997\n"
      "  601260816C8422297C0637BB291C3A079B9CB38A92CE9E551F80AA0EBF4F0E\n"
      "  72C3F250461E4D31F23A7087857FC8438324A013634563D34EFDDCBF2EA80D\n"
      "  F9662C9CCD4BEF2522D8BDFED24CEF78DC6B309317407EAC576D889F88ADA0\n"
      "  8C4FFB480981FB68C5C6CA27503381D41018E6CDC52AAAE46B166BDC10637A\n"
      "  E186A02BA2497FDC5D1221#)\n"
      "  (e #00010001#)\n"
      "  (shadowed t1-v1\n"
      "   (#D2760001240102000005000011730000# OPENPGP.1)\n"
      "    )))\n",
      test_key_extraction,
    },
  };


static char *
pkc_to_string (pkc_t pk)
{
  gpg_error_t err;
  char *buf;
  size_t len;
  estream_t sink;

  sink = es_fopenmem (0, "rw");
  assert (sink);

  err = pkc_write (pk, sink);
  assert (err == 0);

  len = es_ftell (sink);
  buf = xmalloc (len+1);
  assert (buf);

  es_fseek (sink, 0, SEEK_SET);
  es_read (sink, buf, len, NULL);
  buf[len] = 0;

  es_fclose (sink);
  return buf;
}


void dummy_free (void *p) { (void) p; }
void *dummy_realloc (void *p, size_t s) { (void) s; return p; }

void
run_tests (void)
{
  gpg_error_t err;
  pkc_t pk;

  int i;
  for (i = 0; i < DIM (tests); i++)
    {
      estream_t source;
      char *buf;
      size_t len;

      len = strlen (tests[i].value);
      source = es_mopen (tests[i].value, len, len,
			 0, dummy_realloc, dummy_free, "r");
      assert (source);

      err = pkc_parse (&pk, NULL, source);
      assert (err == 0);
      assert (pk);

      if (verbose)
	{
	  err = pkc_write (pk, es_stderr);
	  assert (err == 0);
	}

      buf = pkc_to_string (pk);
      assert (memcmp (tests[i].value, buf, len) == 0);

      es_fclose (source);
      xfree (buf);

      if (tests[i].test_func)
	tests[i].test_func (pk);

      pkc_release (pk);
    }
}


void
run_modification_tests (void)
{
  gpg_error_t err;
  pkc_t pk;
  gcry_sexp_t key;
  char *buf;

  pk = pkc_new ();
  assert (pk);

  pkc_set (pk, "Foo:", "Bar");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Bar\n") == 0);
  xfree (buf);

  pkc_set (pk, "Foo:", "Baz");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Baz\n") == 0);
  xfree (buf);

  pkc_set (pk, "Bar:", "Bazzel");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Baz\nBar: Bazzel\n") == 0);
  xfree (buf);

  pkc_add (pk, "Foo:", "Bar");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Baz\nFoo: Bar\nBar: Bazzel\n") == 0);
  xfree (buf);

  pkc_add (pk, "DontExistYet:", "Bar");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Baz\nFoo: Bar\nBar: Bazzel\nDontExistYet: Bar\n")
	  == 0);
  xfree (buf);

  pkc_delete (pk, pkc_lookup (pk, "DontExistYet:"));
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Baz\nFoo: Bar\nBar: Bazzel\n") == 0);
  xfree (buf);

  pkc_delete (pk, pke_next_value (pkc_lookup (pk, "Foo:"), "Foo:"));
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Baz\nBar: Bazzel\n") == 0);
  xfree (buf);

  pkc_delete (pk, pkc_lookup (pk, "Foo:"));
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Bar: Bazzel\n") == 0);
  xfree (buf);

  pkc_delete (pk, pkc_first (pk));
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "") == 0);
  xfree (buf);

  pkc_set (pk, "Foo:", "A really long value spanning across multiple lines"
	   " that has to be wrapped at a convenient space.");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: A really long value spanning across multiple"
		  " lines that has to be\n  wrapped at a convenient space.\n")
	  == 0);
  xfree (buf);

  pkc_set (pk, "Foo:", "XA really long value spanning across multiple lines"
	   " that has to be wrapped at a convenient space.");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: XA really long value spanning across multiple"
		  " lines that has to\n  be wrapped at a convenient space.\n")
	  == 0);
  xfree (buf);

  pkc_set (pk, "Foo:", "XXXXA really long value spanning across multiple lines"
	   " that has to be wrapped at a convenient space.");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: XXXXA really long value spanning across multiple"
		  " lines that has\n  to be wrapped at a convenient space.\n")
	  == 0);
  xfree (buf);

  pkc_set (pk, "Foo:", "Areallylongvaluespanningacrossmultiplelines"
	   "thathastobewrappedataconvenientspacethatisnotthere.");
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Foo: Areallylongvaluespanningacrossmultiplelinesthat"
		  "hastobewrappedataco\n nvenientspacethatisnotthere.\n")
	  == 0);
  xfree (buf);
  pkc_release (pk);

  pk = pkc_new ();
  assert (pk);

  err = gcry_sexp_build (&key, NULL, "(hello world)");
  assert (err == 0);
  assert (key);

  err = pkc_set_private_key (pk, key);
  gcry_sexp_release (key);
  assert (err == 0);
  buf = pkc_to_string (pk);
  assert (strcmp (buf, "Key: (hello world)\n") == 0);
  xfree (buf);
  pkc_release (pk);
}


void
convert (const char *fname)
{
  gpg_error_t err;
  estream_t source;
  gcry_sexp_t key;
  char *buf;
  size_t buflen;
  struct stat st;
  pkc_t pk;

  source = es_fopen (fname, "rb");
  if (source == NULL)
    goto leave;

  if (fstat (es_fileno (source), &st))
    goto leave;

  buflen = st.st_size;
  buf = xtrymalloc (buflen+1);
  assert (buf);

  if (es_fread (buf, buflen, 1, source) != 1)
    goto leave;

  err = gcry_sexp_sscan (&key, NULL, buf, buflen);
  if (err)
    {
      fprintf (stderr, "malformed s-expression in %s\n", fname);
      exit (1);
    }

  pk = pkc_new ();
  assert (pk);

  err = pkc_set_private_key (pk, key);
  assert (err == 0);

  err = pkc_write (pk, es_stdout);
  assert (err == 0);

  return;

 leave:
  perror (fname);
  exit (1);
}


void
parse (const char *fname)
{
  gpg_error_t err;
  estream_t source;
  char *buf;
  pkc_t pk_a, pk_b;
  pke_t e;
  int line;

  source = es_fopen (fname, "rb");
  if (source == NULL)
    {
      perror (fname);
      exit (1);
    }

  err = pkc_parse (&pk_a, &line, source);
  if (err)
    {
      fprintf (stderr, "failed to parse %s line %d: %s\n",
	       fname, line, gpg_strerror (err));
      exit (1);
    }

  buf = pkc_to_string (pk_a);
  xfree (buf);

  pk_b = pkc_new ();
  assert (pk_b);

  for (e = pkc_first (pk_a); e; e = pke_next (e))
    {
      gcry_sexp_t key = NULL;

      if (strcasecmp (pke_name (e), "Key:") == 0)
	{
	  err = pkc_get_private_key (pk_a, &key);
	  if (err)
	    key = NULL;
	}

      if (key)
	{
	  err = pkc_set_private_key (pk_b, key);
	  assert (err == 0);
	}
      else
	{
	  err = pkc_add (pk_b, pke_name (e), pke_value (e));
	  assert (err == 0);
	}
    }

    buf = pkc_to_string (pk_b);
    if (verbose)
      fprintf (stdout, "%s", buf);
    xfree (buf);
}


void
print_usage (void)
{
  fprintf (stderr,
	   "usage: t-private-keys [--verbose]"
	   " [--convert <private-key-file>"
	   " || --parse <extended-private-key-file>]\n");
  exit (2);
}


int
main (int argc, char **argv)
{
  enum { TEST, CONVERT, PARSE } command = TEST;

  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  if (argc && !strcmp (argv[0], "--convert"))
    {
      command = CONVERT;
      argc--; argv++;
      if (argc != 1)
	print_usage ();
    }

  if (argc && !strcmp (argv[0], "--parse"))
    {
      command = PARSE;
      argc--; argv++;
      if (argc != 1)
	print_usage ();
    }

  switch (command)
    {
    case TEST:
      run_tests ();
      run_modification_tests ();
      break;

    case CONVERT:
      convert (*argv);
      break;

    case PARSE:
      parse (*argv);
      break;
    }

  return 0;
}
