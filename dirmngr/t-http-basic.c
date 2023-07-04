/* t-http-basic.c - Basic regression tests for http.c
 * Copyright (C) 2018  g10 Code GmbH
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
 * along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdlib.h>

#include "../common/util.h"
#include "t-support.h"
#include "http.h"

#define PGM "t-http-basic"


static void
test_http_prepare_redirect (void)
{
  static struct {
    const char *url;
    const char *location;
    const char *expect_url;
    gpg_error_t expect_err;
  } tests[] = {
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      NULL,
      "",
      GPG_ERR_NO_DATA
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "",
      "",
      GPG_ERR_NO_DATA
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "foo//bla",
      "",
      GPG_ERR_BAD_URI
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://foo.gnupg.org:8080/.not-so-well-known/openpgpkey/hu/12345678",
      "http://foo.gnupg.org:8080/.well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http:///.no-so-well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      GPG_ERR_BAD_URI
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org:8080/.not-so-well-known/openpgpkey/hu/12345678",
      "http://gnupg.org:8080/.not-so-well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org:8/.not-so-well-known/openpgpkey/hu/12345678",
      "http://gnupg.org:8/.not-so-well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org:/.no-so-well-known/openpgpkey/hu/12345678",
      "http://gnupg.org:/.no-so-well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/",
      "http://gnupg.org/",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.net",
      "http://gnupg.net/.well-known/openpgpkey/hu/12345678",
      0
    },
    {
      "http://gnupg.org",
      "http://gnupg.org",
      "http://gnupg.org",
      0
    },
    {
      "http://gnupg.org",
      "http://foo.gnupg.org",
      "http://foo.gnupg.org",
      0
    },
    {
      "http://gnupg.org/",
      "http://foo.gnupg.org",
      "http://foo.gnupg.org/",
      0
    },
    {
      "http://gnupg.org",
      "http://foo.gnupg.org/",
      "http://foo.gnupg.org",
      0
    },
    {
      "http://gnupg.org/.well-known/openpgpkey/hu/12345678",
      "http://gnupg.org/something-else",
      "http://gnupg.org/something-else",
      0
    },
  };
  int tidx;
  http_redir_info_t ri;
  gpg_error_t err;
  char *newurl;

  err = http_prepare_redirect (NULL, 301, tests[0].location, &newurl);
  if (gpg_err_code (err) != GPG_ERR_INV_ARG)
    fail (0);
  memset (&ri, 0, sizeof ri);
  err = http_prepare_redirect (&ri, 301, tests[0].location, &newurl);
  if (gpg_err_code (err) != GPG_ERR_INV_ARG)
    fail (0);
  memset (&ri, 0, sizeof ri);
  ri.silent = 1;
  ri.orig_url = "http://example.org";
  err = http_prepare_redirect (&ri, 301, tests[0].location, &newurl);
  if (gpg_err_code (err) != GPG_ERR_NO_DATA)
    fail (0);

  for (tidx = 0; tidx < DIM (tests); tidx++)
    {
      memset (&ri, 0, sizeof ri);
      ri.silent = 1;
      ri.redirects_left = 1;
      ri.orig_url = tests[tidx].url;
      ri.restrict_redir = 1; /* This is what we used to test here.  */

      err = http_prepare_redirect (&ri, 301, tests[tidx].location, &newurl);
      if (err && newurl)
        fail (tidx);
      if (err && gpg_err_code (err) != tests[tidx].expect_err)
        fail (tidx);
      if (err)
        continue;
      if (!newurl)
        fail (tidx);
      if (strcmp (tests[tidx].expect_url, newurl))
        {
          fprintf (stderr, "want: '%s'\n", tests[tidx].expect_url);
          fprintf (stderr, "got : '%s'\n", newurl);
          fail (tidx);
        }

      xfree (newurl);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_http_prepare_redirect ();

  return 0;
}
