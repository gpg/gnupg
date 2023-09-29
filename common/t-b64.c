/* t-b64.c - Module tests for b64enc.c and b64dec.c
 * Copyright (C) 2008 Free Software Foundation, Inc.
 * Copyright (C) 2008, 2023 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     errcount++;                                 \
                   } while(0)
#define oops()   do { fprintf (stderr, "%s:%d: ooops\n",         \
                               __FILE__,__LINE__);               \
                      exit (2);                                  \
                   } while(0)

static int verbose;
static int errcount;


/* Convert STRING consisting of hex characters into its binary
 * representation and return it as an allocated buffer. The valid
 * length of the buffer is returned at R_LENGTH.  The string is
 * delimited by end of string.  The function returns NULL on
 * error.  */
static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return NULL;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static void
test_b64decode (void)
{
  static struct {
    const char *string;    /* String to test.  */
    const char *title;     /* title parameter.  */
    gpg_error_t  err;      /* expected error.  */
    const char *datastr;   /* Expected data (hex encoded)  */
  } tests[] = {
    { "YQ==", NULL, 0,
      "61" },
    { "YWE==", NULL, 0,
      "6161" },
    { "YWFh", NULL, 0,
      "616161" },
    { "YWFhYQ==", NULL, 0,
      "61616161" },
    { "YWJjZA==", NULL, 0,
      "61626364" },
    { "AA=", NULL, 0,
      "00" },
    { "AAEA=", NULL, 0,
      "000100" },
    { "/w==", NULL, 0,
      "ff" },
    { "oRQwEqADCgEDoQsGCSqGSIL3EgECAg==", NULL, 0,
      "a1143012a0030a0103a10b06092a864882f712010202" },
    { "oRQwEqADCgEDoQsGCSqGSIL3EgECA-==", NULL, GPG_ERR_BAD_DATA,
      "a1143012a0030a0103a10b06092a864882f712010202" },
    { "oRQwEqADCgEDoQsGCSqGSIL3EgECAg==", "", 0,
      "" },
    { "-----BEGIN PGP\n\n"
      "oRQwEqADCgEDoQsGCSqGSIL3EgECAg==\n"
      "-----END PGP\n", "", 0,
      "a1143012a0030a0103a10b06092a864882f712010202" },

    { "", NULL, 0,
      "" }
  };
  int tidx;
  gpg_error_t err;
  void *data = NULL;
  size_t datalen;
  char *wantdata = NULL;
  size_t wantdatalen;

  for (tidx = 0; tidx < DIM(tests); tidx++)
    {
      xfree (wantdata);
      if (!(wantdata = hex2buffer (tests[tidx].datastr, &wantdatalen)))
        oops ();
      xfree (data);
      err = b64decode (tests[tidx].string, tests[tidx].title, &data, &datalen);
      if (verbose)
        fprintf (stderr, "%s:%d: test %d, err=%d, datalen=%zu\n",
                 __FILE__, __LINE__, tidx, err, datalen);
      if (gpg_err_code (err) != tests[tidx].err)
        fail (tidx);
      else if (err)
        pass ();
      else if (wantdatalen != datalen)
        fail (tidx);
      else if (memcmp (wantdata, data, datalen))
        fail (tidx);
      else
        pass ();
    }
  xfree (wantdata);
  xfree (data);
}


static void
test_b64enc_pgp (const char *string)
{
  gpg_error_t err;
  struct b64state state;

  if (!string)
    string = "a";

  err = b64enc_start (&state, stdout, "PGP MESSAGE");
  if (err)
    fail (1);

  err = b64enc_write (&state, string, strlen (string));
  if (err)
    fail (2);

  err = b64enc_finish (&state);
  if (err)
    fail (3);

  pass ();
}


static void
test_b64enc_file (const char *fname)
{
  gpg_error_t err;
  struct b64state state;
  FILE *fp;
  char buffer[50];
  size_t nread;

  fp = fname ? fopen (fname, "r") : stdin;
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open '%s': %s\n",
               __FILE__, __LINE__, fname? fname:"[stdin]", strerror (errno));
      fail (0);
    }

  err = b64enc_start (&state, stdout, "DATA");
  if (err)
    fail (1);

  while ( (nread = fread (buffer, 1, sizeof buffer, fp)) )
    {
      err = b64enc_write (&state, buffer, nread);
      if (err)
        fail (2);
    }

  err = b64enc_finish (&state);
  if (err)
    fail (3);

  fclose (fp);
  pass ();
}


static void
test_b64dec_file (const char *fname)
{
  gpg_error_t err;
  struct b64state state;
  FILE *fp;
  char buffer[50];
  size_t nread, nbytes;

  fp = fname ? fopen (fname, "r") : stdin;
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open '%s': %s\n",
               __FILE__, __LINE__, fname? fname:"[stdin]", strerror (errno));
      fail (0);
    }

  err = b64dec_start (&state, "");
  if (err)
    fail (1);

  while ( (nread = fread (buffer, 1, sizeof buffer, fp)) )
    {
      err = b64dec_proc (&state, buffer, nread, &nbytes);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EOF)
            break;
          fail (2);
        }
      else if (nbytes)
        fwrite (buffer, 1, nbytes, stdout);
    }

  err = b64dec_finish (&state);
  if (err)
    fail (3);

  fclose (fp);
  pass ();
}



int
main (int argc, char **argv)
{
  int do_encode = 0;
  int do_decode = 0;
  int do_pgpdecode = 0;

  if (argc)
    { argc--; argv++; }
  if (argc && !strcmp (argv[0], "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  if (argc && !strcmp (argv[0], "--encode"))
    {
      do_encode = 1;
      argc--; argv++;
    }
  else if (argc && !strcmp (argv[0], "--decode"))
    {
      do_decode = 1;
      argc--; argv++;
    }
  else if (argc)
    do_pgpdecode = 1;

  if (do_encode)
    test_b64enc_file (argc? *argv: NULL);
  else if (do_decode)
    test_b64dec_file (argc? *argv: NULL);
  else if (do_pgpdecode)
    test_b64enc_pgp (argc? *argv: NULL);
  else
    test_b64decode ();

  return !!errcount;
}
