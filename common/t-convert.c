/* t-convert.c - Module test for convert.c
 *	Copyright (C) 2006, 2008 Free Software Foundation, Inc.
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
#include <assert.h>

#include "util.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     exit (1);                                   \
                   } while(0)


static void
test_hex2bin (void)
{
  static const char *valid[] = {
    "00112233445566778899aabbccddeeff11223344",
    "00112233445566778899AABBCCDDEEFF11223344",
    "00112233445566778899AABBCCDDEEFF11223344 blah",
    "00112233445566778899AABBCCDDEEFF11223344\tblah",
    "00112233445566778899AABBCCDDEEFF11223344\nblah",
    NULL
  };
  static const char *invalid[] = {
    "00112233445566778899aabbccddeeff1122334",
    "00112233445566778899AABBCCDDEEFF1122334",
    "00112233445566778899AABBCCDDEEFG11223344",
    "00 112233445566778899aabbccddeeff11223344",
    "00:112233445566778899aabbccddeeff11223344",
    ":00112233445566778899aabbccddeeff11223344",
    "0:0112233445566778899aabbccddeeff11223344",
    "00112233445566778899aabbccddeeff11223344:",
    "00112233445566778899aabbccddeeff112233445",
    "00112233445566778899aabbccddeeff1122334455",
    "00112233445566778899aabbccddeeff11223344blah",
    NULL
  };
  static const char *valid2[] = {
    "00",
    "00 x",
    NULL
  };
  static const char *invalid2[] = {
    "",
    "0",
    "00:",
    "00x",
    " 00",
    NULL
  };
  unsigned char buffer[20];
  int len;
  int i;
  
  
  for (i=0; valid[i]; i++)
    {
      len = hex2bin (valid[i], buffer, sizeof buffer);
      if (len < 0)
        fail (i);
      if (memcmp (buffer, ("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
                           "\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44"), 20))
          fail (i);
    }
  if (hex2bin (valid[0], buffer, sizeof buffer) != 40)
    fail (0);
  if (hex2bin (valid[2], buffer, sizeof buffer) != 41)
    fail (0);
  
  for (i=0; invalid[i]; i++)
    {
      len = hex2bin (invalid[i], buffer, sizeof buffer);
      if (!(len < 0))
        fail (i);
    }

  for (i=0; valid2[i]; i++)
    {
      len = hex2bin (valid2[i], buffer, 1);
      if (len < 0)
        fail (i);
      if (memcmp (buffer, "\x00", 1))
        fail (i);
    }
  if (hex2bin (valid2[0], buffer, 1) != 2)
    fail (0);
  if (hex2bin (valid2[1], buffer, 1) != 3)
    fail (0);
  
  for (i=0; invalid2[i]; i++)
    {
      len = hex2bin (invalid2[i], buffer, 1);
      if (!(len < 0))
        fail (i);
    }
}



static void
test_hexcolon2bin (void)
{
  static const char *valid[] = {
    "00112233445566778899aabbccddeeff11223344",
    "00112233445566778899AABBCCDDEEFF11223344",
    "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44",
    "00112233445566778899AABBCCDDEEFF11223344 blah",
    "00112233445566778899AABBCCDDEEFF11223344\tblah",
    "00112233445566778899AABBCCDDEEFF11223344\nblah",
    NULL
  };
  static const char *invalid[] = {
    "00112233445566778899aabbccddeeff1122334",
    "00112233445566778899AABBCCDDEEFF1122334",
    "00112233445566778899AABBCCDDEEFG11223344",
    ":00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44",
    "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44:",
    "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:3344",
    "00:1122:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44",
    "0011:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44",
    "00 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44",
    "00:11 22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:11:22:33:44",
    "00112233445566778899aabbccddeeff112233445",
    "00112233445566778899aabbccddeeff1122334455",
    "00112233445566778899aabbccddeeff11223344blah",
    NULL
  };
  static const char *valid2[] = {
    "00",
    "00 x",
    NULL
  };
  static const char *invalid2[] = {
    "",
    "0",
    "00:",
    ":00",
    "0:0",
    "00x",
    " 00",
    NULL
  };
  unsigned char buffer[20];
  int len;
  int i;
  
  
  for (i=0; valid[i]; i++)
    {
      len = hexcolon2bin (valid[i], buffer, sizeof buffer);
      if (len < 0)
        fail (i);
      if (memcmp (buffer, ("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
                           "\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44"), 20))
          fail (i);
    }
  if (hexcolon2bin (valid[0], buffer, sizeof buffer) != 40)
    fail (0);
  if (hexcolon2bin (valid[3], buffer, sizeof buffer) != 41)
    fail (0);
  
  for (i=0; invalid[i]; i++)
    {
      len = hexcolon2bin (invalid[i], buffer, sizeof buffer);
      if (!(len < 0))
        fail (i);
    }

  for (i=0; valid2[i]; i++)
    {
      len = hexcolon2bin (valid2[i], buffer, 1);
      if (len < 0)
        fail (i);
      if (memcmp (buffer, "\x00", 1))
        fail (i);
    }
  if (hexcolon2bin (valid2[0], buffer, 1) != 2)
    fail (0);
  if (hexcolon2bin (valid2[1], buffer, 1) != 3)
    fail (0);
  
  for (i=0; invalid2[i]; i++)
    {
      len = hexcolon2bin (invalid2[i], buffer, 1);
      if (!(len < 0))
        fail (i);
    }


}



static void
test_bin2hex (void)
{
  char stuff[20+1] = ("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
                      "\xbb\xcc\xdd\xee\xff\x01\x10\x02\xa3");
  char hexstuff[] = "00112233445566778899AABBCCDDEEFF011002A3";
  char buffer[2*20+1];
  char *p;

  p = bin2hex (stuff, 20, buffer);
  if (!p)
    fail (0);
  if (p != buffer)
    fail (0);
  if (strcmp (buffer, hexstuff))
    fail (0);

  p = bin2hex (stuff, 20, NULL);
  if (!p)
    fail (0);
  if (strcmp (p, hexstuff))
    fail (0);
  
  p = bin2hex (stuff, (size_t)(-1), NULL);
  if (p)
    fail (0); 
  if (errno != ENOMEM)
    fail (1);
}


static void
test_bin2hexcolon (void)
{
  char stuff[20+1] = ("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
                      "\xbb\xcc\xdd\xee\xff\x01\x10\x02\xa3");
  char hexstuff[] = ("00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                     ":01:10:02:A3");
  char buffer[3*20+1];
  char *p;

  p = bin2hexcolon (stuff, 20, buffer);
  if (!p)
    fail (0);
  if (p != buffer)
    fail (0);
  if (strcmp (buffer, hexstuff))
    fail (0);

  p = bin2hexcolon (stuff, 20, NULL);
  if (!p)
    fail (0); 
  if (strcmp (p, hexstuff))
    fail (0);
  
  p = bin2hexcolon (stuff, (size_t)(-1), NULL);
  if (p)
    fail (0); 
  if (errno != ENOMEM)
    fail (1);
}



static void
test_hex2str (void)
{
  static struct {
    const char *hex;
    const char *str;
    int off;
    int no_alloc_test;
  } tests[] = {
    /* Simple tests.  */
    { "112233445566778899aabbccddeeff1122",
      "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
      34 },
    { "112233445566778899aabbccddeeff1122 blah",
      "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
      34 },
    { "112233445566778899aabbccddeeff1122\tblah",
      "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
      34 },
    { "112233445566778899aabbccddeeff1122\nblah",
      "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
      34 },
    /* Valid tests yielding an empty string.  */
    { "00",
      "",
      2 },
    { "00 x",
      "",
      2 },
    { "",
      "",
      0 },
    { " ",
      "",
      0 },
    /* Test trailing Nul feature.  */
    { "112233445566778899aabbccddeeff112200",
      "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
      36 },
    { "112233445566778899aabbccddeeff112200 ",
      "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11\x22",
      36 },
    /* Test buffer size. (buffer is of length 20)  */
    { "6162636465666768696A6b6c6D6e6f70717273",
      "abcdefghijklmnopqrs",
      38 },
    { "6162636465666768696A6b6c6D6e6f7071727300",
      "abcdefghijklmnopqrs",
      40 },
    { "6162636465666768696A6b6c6D6e6f7071727374",
      NULL,
      0, 1 },
    { "6162636465666768696A6b6c6D6e6f707172737400",
      NULL,
      0, 1 },
    { "6162636465666768696A6b6c6D6e6f707172737475",
      NULL,
      0, 1 },

    /* Invalid tests. */
    { "112233445566778899aabbccddeeff1122334",      NULL, 0 },
    { "112233445566778899AABBCCDDEEFF1122334",      NULL, 0 },
    { "112233445566778899AABBCCDDEEFG11223344",     NULL, 0 },
    { "0:0112233445566778899aabbccddeeff11223344",  NULL, 0 },
    { "112233445566778899aabbccddeeff11223344:",    NULL, 0 },
    { "112233445566778899aabbccddeeff112233445",    NULL, 0 },
    { "112233445566778899aabbccddeeff1122334455",   NULL, 0, 1 },
    { "112233445566778899aabbccddeeff11223344blah", NULL, 0 },
    { "0",    NULL, 0 },
    { "00:",  NULL, 0 },
    { "00x",  NULL, 0 },

    { NULL, NULL, 0 }
  };

  int idx;
  char buffer[20];
  const char *tail;
  size_t count;
  char *result;

  for (idx=0; tests[idx].hex; idx++)
    {
      tail = hex2str (tests[idx].hex, buffer, sizeof buffer, &count);
      if (tests[idx].str)
        {
          /* Good case test.  */
          if (!tail)
            fail (idx);
          else if (strcmp (tests[idx].str, buffer))
            fail (idx);
          else if (tail - tests[idx].hex != tests[idx].off)
            fail (idx);
          else if (strlen (buffer) != count)
            fail (idx);
        }
      else
        {
          /* Bad case test.  */
          if (tail)
            fail (idx);
        }
    }

  /* Same tests again using in-place conversion.  */
  for (idx=0; tests[idx].hex; idx++)
    {
      char tmpbuf[100];
      
      assert (strlen (tests[idx].hex)+1 < sizeof tmpbuf);
      strcpy (tmpbuf, tests[idx].hex);
      
      /* Note: we still need to use 20 as buffer length because our
         tests assume that. */
      tail = hex2str (tmpbuf, tmpbuf, 20, &count);
      if (tests[idx].str)
        {
          /* Good case test.  */
          if (!tail)
            fail (idx);
          else if (strcmp (tests[idx].str, tmpbuf))
            fail (idx);
          else if (tail - tmpbuf != tests[idx].off)
            fail (idx);
          else if (strlen (tmpbuf) != count)
            fail (idx);
        }
      else
        {
          /* Bad case test.  */
          if (tail)
            fail (idx);
          if (strcmp (tmpbuf, tests[idx].hex))
            fail (idx); /* Buffer was modified.  */
        }
    }

  /* Test the allocation variant.  */
  for (idx=0; tests[idx].hex; idx++)
    {
      if (tests[idx].no_alloc_test)
        continue;

      result = hex2str_alloc (tests[idx].hex, &count);
      if (tests[idx].str)
        {
          /* Good case test.  */
          if (!result)
            fail (idx);
          else if (strcmp (tests[idx].str, result))
            fail (idx);
          else if (count != tests[idx].off)
            fail (idx);
        }
      else
        {
          /* Bad case test.  */
          if (result)
            fail (idx);
        }
      xfree (result);
    }
}





int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;
  
  test_hex2bin ();
  test_hexcolon2bin ();
  test_bin2hex ();
  test_bin2hexcolon ();
  test_hex2str ();

  return 0;
}

