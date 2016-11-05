/* t-rmd160.c - Module test for rmd160.c
 *	Copyright (C) 2008 Free Software Foundation, Inc.
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

#include "rmd160.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                       exit (1);                                 \
                    } while(0)

static void
run_test (void)
{
  static struct
  {
    const char *data;
    const char *expect;
  } testtbl[] =
    {
      {	"",
	"\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28"
	"\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31" },
      {	"a",
	"\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae"
	"\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe" },
      {	"abc",
	"\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04"
	"\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc" },
      {	"message digest",
	"\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8"
	"\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36" },
      { "abcdefghijklmnopqrstuvwxyz",
        "\xf7\x1c\x27\x10\x9c\x69\x2c\x1b\x56\xbb"
        "\xdc\xeb\x5b\x9d\x28\x65\xb3\x70\x8d\xbc" },
      { "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789",
        "\xb0\xe2\x0b\x6e\x31\x16\x64\x02\x86\xed"
        "\x3a\x87\xa5\x71\x30\x79\xb2\x1f\x51\x89" },
      { "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890",
        "\x9b\x75\x2e\x45\x57\x3d\x4b\x39\xf4\xdb"
        "\xd3\x32\x3c\xab\x82\xbf\x63\x32\x6b\xfb" },

      { NULL, NULL }
    };
  int idx;
  char digest[20];

  for (idx=0; testtbl[idx].data; idx++)
    {
      rmd160_hash_buffer (digest,
                          testtbl[idx].data, strlen(testtbl[idx].data));
      if (memcmp (digest, testtbl[idx].expect, 20))
        fail (idx);
    }
}


int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  run_test ();

  return 0;
}
