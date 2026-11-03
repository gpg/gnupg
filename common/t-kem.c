/* t-kem.c - Module tests for kem.c
 * Copyright (C) 2026  g10 Code GmbH
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_DOSISH_SYSTEM
# include <fcntl.h>
#endif

#include "t-support.h"
#include "kemhelp.h"

#define PGM "t-kem"

static int verbose;
static int debug;
static int errcount;


/* Convert STRING consisting of hex characters into its binary
 * representation and return it as an allocated buffer. The valid
 * length of the buffer is returned at R_LENGTH.  The string is
 * delimited by end of string.  The function terminates on error.  */
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
        gpgrt_log_error ("invalid hex digits in \"%s\"\n", string);
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}

static void *
xhex2buffer (const char *string, size_t *r_length)
{
  void *buffer;

  buffer = hex2buffer (string, r_length);
  if (!buffer)
    gpgrt_log_fatal ("error scanning hexstring '%.20s'...\n", string);
  return buffer;
}


static void
t_gnupg_kem_combiner_sha3_256 (void)
{
  struct {
    const char *mlkemss;
    const char *tradss;
    const char *tradct;
    const char *tradpk;
    const char *label;
    const char *combined;
  } tv[] = {
    /* Test vectors from draft-ietf-lamps-pq-composite-kem-22.txt  */
    {
      "ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43",
      "ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0",
      "041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d1917127"
      "0cdefcd4abb682edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5"
      "e7610",
      "04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159f"
      "f73d38d29aa94f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e803"
      "96a3e",
      "MLKEM768-P256",
      "d6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee"
    },
    {
      "461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1",
      "4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843",
      "0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f",
      "1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b",
      "\x5c\x2e\x2f\x2f\x5e\x5c",
      "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98"
    },
    {
      "c0f87f0c53fa8e2ba192a494694d37d1e3cf99c65e0dc5f69b2cc044b3fb205d",
      "4d52b7ef430382f479603207c0b8f7aa5bc35d8758835007e39a2642ad"
      "65e635d674db7a5513889657fb24e4e228a098",
      "0401a5b81dcb51290a0eb142b9032d5a37503164b7a20ac0e3b52dc54f"
      "9b0b7c9fdd2699a59563a0b9ad0e54478846faeab72b92275e1fbb8b963bcc6e80e"
      "30c089fbe4ed8d47ec76951db94aede46e679d5692eeb1d1b150d5b2e6660dc67c4"
      "69",
      "0468cc4acc5dd85edbcbf25bae7ee7dcacec2968ea7ee57fc91311cb9c"
      "47d4a24c3854e5ce3e5d0b309fda493224520f2870496eb16571108b3deafd72c1d"
      "f17edc302fbb8b60bae44d93177e6df5278e4667a090a2d59a2076f41d693975e8d"
      "19",
      "MLKEM1024-P384",
      "eb60f6c80a309ad4158d7b02f2cf8c947faead96ebbd85c3f62a94868ffddca4"
    }

  };
  int idx;
  gpg_error_t err;
  char *mlkemss;
  char *tradss;
  char *tradct;
  char *tradpk;
  const char *label;
  char *combined;
  size_t mlkemss_len;
  size_t tradss_len;
  size_t tradct_len;
  size_t tradpk_len;
  size_t label_len;
  size_t combined_len;
  char output[32];

  for (idx=0; idx < DIM(tv); idx++)
    {
      mlkemss = xhex2buffer (tv[idx].mlkemss, &mlkemss_len);
      tradss  = xhex2buffer (tv[idx].tradss, &tradss_len);
      tradct  = xhex2buffer (tv[idx].tradct, &tradct_len);
      tradpk  = xhex2buffer (tv[idx].tradpk, &tradpk_len);
      label = tv[idx].label; label_len = strlen (label);
      combined = xhex2buffer (tv[idx].combined, &combined_len);

      err = gnupg_kem_combiner_sha3_256 (output, sizeof output,
                                         tradss, tradss_len,
                                         tradct, tradct_len,
                                         tradpk, tradpk_len,
                                         mlkemss, mlkemss_len,
                                         label, label_len);
      if (err)
        gpgrt_log_error ("kem_combiner_sha3_256: test %d failed: %s\n",
                         idx, gpg_strerror (err));

      if (verbose)
        gpgrt_log_printhex (output, sizeof output, "test %d result:", idx);
      if (combined_len != sizeof output)
        gpgrt_log_error ("kem_combiner_sha3_256: test %d: wrong length\n", idx);
      else if (memcmp (combined, output, sizeof output))
        gpgrt_log_error ("kem_combiner_sha3_256: test %d: does not match\n",
                         idx);


      xfree (mlkemss);
      xfree (tradss);
      xfree (tradct);
      xfree (tradpk);
      xfree (combined);
    }
}




int
main (int argc, char **argv)
{
  int last_argc = -1;

  no_exit_on_fail = 1;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [FILE]\n"
                 "Options:\n"
                 "  --verbose         Print timings etc.\n"
                 "  --debug           Flyswatter\n"
                 , stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (argc)
    {
      fprintf (stderr, PGM ": to many arguments given\n");
      exit (1);
    }

  t_gnupg_kem_combiner_sha3_256 ();

  if (gpgrt_get_errorcount (0))
    errcount++;
  return !!errcount;
}
