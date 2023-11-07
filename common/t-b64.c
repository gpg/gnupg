/* t-b64.c - Module tests for b64decodec
 * Copyright (C) 2023 g10 Code GmbH
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

  test_b64decode ();

  return !!errcount;
}
