/* t-zb32.c - Module tests for zb32.c
 * Copyright (C) 2014  Werner Koch
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     errcount++;                                 \
                   } while(0)

static int errcount;


static void
test_zb32enc (void)
{
  static struct {
    size_t datalen;
    char *data;
    const char *expected;
  } tests[] = {
    /* From the DESIGN document.  */
    {  1, "\x00", "y" },
    {  1, "\x80", "o" },
    {  2, "\x40", "e" },
    {  2, "\xc0", "a" },
    { 10, "\x00\x00", "yy" },
    { 10, "\x80\x80", "on" },
    { 20, "\x8b\x88\x80", "tqre" },
    { 24, "\xf0\xbf\xc7", "6n9hq" },
    { 24, "\xd4\x7a\x04", "4t7ye" },
    /* The next vector is strange: The DESIGN document from 2007 gives
       "8ik66o" as result, the revision from 2009 gives "6im5sd".  I
       look at it for quite some time and came to the conclusion that
       "6im54d" is the right encoding.  */
    { 30, "\xf5\x57\xbd\x0c", "6im54d" },
    /* From ccrtp's Java code.  */
    { 40, "\x01\x01\x01\x01\x01", "yryonyeb" },
    { 15, "\x01\x01", "yry" },
    { 80, "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", "yryonyebyryonyeb" },
    { 15, "\x81\x81", "ogy" },
    { 16, "\x81\x81", "ogyo" },
    { 20, "\x81\x81\x81", "ogya" },
    { 64, "\x81\x81\x81\x81\x81\x81\x81\x81", "ogyadycbogyan" },
    /* More tests.  */
    { 160, "\x80\x61\x58\x70\xF5\xBA\xD6\x90\x33\x36"
      /* */"\x86\xD0\xF2\xAD\x85\xAC\x1E\x42\xB3\x67",
      /* */"oboioh8izmmjyc3so5exfmcfioxrfc58" },
    { 0,  "", "" }
  };
  int tidx;
  char *output;

  for (tidx = 0; tidx < DIM(tests); tidx++)
    {
      output = zb32_encode (tests[tidx].data, tests[tidx].datalen);
      if (!output)
        {
          fprintf (stderr, "%s:%d: error encoding test %d: %s\n",
                   __FILE__, __LINE__, tidx, strerror (errno));
          exit (1);
        }
      /* puts (output); */
      if (strcmp (output, tests[tidx].expected))
        fail (tidx);
      xfree (output);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_zb32enc ();

  return !!errcount;
}
