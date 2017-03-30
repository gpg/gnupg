/* t-keydb-get-keyblock.c - Tests for keydb.c.
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

#include "test.c"

#include "keydb.h"

static void
do_test (int argc, char *argv[])
{
  char *fname;
  int rc;
  KEYDB_HANDLE hd1;
  KEYDB_SEARCH_DESC desc1;
  KBNODE kb1;

  (void) argc;
  (void) argv;

  /* t-keydb-get-keyblock.gpg contains two keys: a modern key followed
     by a legacy key.  If we get the keyblock for the modern key, we
     shouldn't get

     - */
  fname = prepend_srcdir ("t-keydb-get-keyblock.gpg");
  rc = keydb_add_resource (fname, 0);
  test_free (fname);
  if (rc)
    ABORT ("Failed to open keyring.");

  hd1 = keydb_new ();
  if (!hd1)
    ABORT ("");

  rc = classify_user_id ("8061 5870 F5BA D690 3336  86D0 F2AD 85AC 1E42 B367",
			 &desc1, 0);
  if (rc)
    ABORT ("Failed to convert fingerprint for 1E42B367");

  rc = keydb_search (hd1, &desc1, 1, NULL);
  if (rc)
    ABORT ("Failed to lookup key associated with 1E42B367");

  rc = keydb_get_keyblock (hd1, &kb1);
  TEST_P ("", ! rc);

  keydb_release (hd1);
  release_kbnode (kb1);
}
