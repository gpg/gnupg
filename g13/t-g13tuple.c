/* t-g13tuple.c - Module test for g13tuple.c
 * Copyright (C) 2016 Werner Koch
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
#include <assert.h>


#include "../common/util.h"
#include "keyblob.h"
#include "g13tuple.h"

#define PGM "t-g13tuple"

static int verbose;
static int debug;
static int errcount;

/* Test for the functions append_tuple_uint and find_tuple_unit.  */
static void
test_tuple_uint (void)
{
  static struct {
    int tag;
    int len;
    char *data;
    unsigned long long val;
    gpg_err_code_t ec;
  } tv[] = {
    { 1, 0, "",     0, GPG_ERR_ERANGE },
    { 2, 1, "\x00", 0, 0},
    { 3, 1, "\x7f", 127ull, 0},
    { 4, 1, "\x80", 0, GPG_ERR_ERANGE },
    { 5, 1, "\x81", 0, GPG_ERR_ERANGE },
    { 6, 2, "\x80\x01", 0, GPG_ERR_ERANGE },
    { 7, 2, "\x00\x80", 128ull, 0 },
    { 8, 1, "\x01", 1, 0 },
    { 9, 1, "\x40", 64, 0 },
    { 10, 2, "\x40\x00", 16384, 0 },
    { 11, 8, "\x7f\xff\xff\xff\xff\xff\xff\xff", 0x7fffffffffffffffull, 0 },
    { 12, 9, "\x00\xff\xff\xff\xff\xff\xff\xff\xff", 0xffffffffffffffffull, 0},
    { 13, 9, "\x01\xff\xff\xff\xff\xff\xff\xff\xff", 0, GPG_ERR_ERANGE }
  };
  int tidx;
  gpg_error_t err;
  membuf_t mb, mb2;
  void *p;
  const void *s;
  size_t n;
  tupledesc_t tuples;
  tupledesc_t tuples2;
  unsigned long long value;
  int i;

  init_membuf (&mb, 512);
  init_membuf (&mb2, 512);
  append_tuple (&mb, KEYBLOB_TAG_BLOBVERSION, "\x01", 1);
  append_tuple (&mb2, KEYBLOB_TAG_BLOBVERSION, "\x01", 1);
  for (tidx=0; tidx < DIM (tv); tidx++)
    {
      append_tuple (&mb, tv[tidx].tag, tv[tidx].data, tv[tidx].len);
      if (!tv[tidx].ec)
        append_tuple_uint (&mb2, tv[tidx].tag, tv[tidx].val);
    }

  p = get_membuf (&mb, &n);
  if (!p)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, PGM ":%s: get_membuf failed: %s\n",
               __func__, gpg_strerror (err));
      exit (1);
    }
  err = create_tupledesc (&tuples, p, n);
  if (err)
    {
      fprintf (stderr, PGM ":%s: create_tupledesc failed: %s\n",
               __func__, gpg_strerror (err));
      exit (1);
    }
  p = get_membuf (&mb2, &n);
  if (!p)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, PGM ":%s: get_membuf failed: %s\n",
               __func__, gpg_strerror (err));
      exit (1);
    }
  err = create_tupledesc (&tuples2, p, n);
  if (err)
    {
      fprintf (stderr, PGM ":%s: create_tupledesc failed: %s\n",
               __func__, gpg_strerror (err));
      exit (1);
    }

  for (tidx=0; tidx < DIM (tv); tidx++)
    {
      err = find_tuple_uint (tuples, tv[tidx].tag, &value);
      if (tv[tidx].ec != gpg_err_code (err))
        {
          fprintf (stderr, PGM ":%s:tidx=%d: wrong error returned; "
                   "expected(%s) got(%s)\n",
                   __func__, tidx,
                   gpg_strerror (tv[tidx].ec), gpg_strerror (err));
          errcount++;
        }
      else if (!err && tv[tidx].val != value)
        {
          fprintf (stderr, PGM ":%s:tidx=%d: wrong value returned; "
                   "expected(%llx) got(%llx)\n",
                   __func__, tidx, tv[tidx].val, value);
          errcount++;
        }

      err = find_tuple_uint (tuples2, tv[tidx].tag, &value);
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
        {
          if (!tv[tidx].ec)
            {
              fprintf (stderr, PGM ":%s:tidx=%d: find_tuple failed: %s\n",
                       __func__, tidx, gpg_strerror (err));
              errcount++;
            }
        }
      else if (tv[tidx].ec != gpg_err_code (err))
        {
          fprintf (stderr, PGM ":%s:tidx=%d: wrong error returned (2); "
                   "expected(%s) got(%s)\n",
                   __func__, tidx,
                   gpg_strerror (tv[tidx].ec), gpg_strerror (err));
          errcount++;
        }
      else if (!err && tv[tidx].val != value)
        {
          fprintf (stderr, PGM ":%s:tidx=%d: wrong value returned (2); "
                   "expected(%llx) got(%llx)\n",
                   __func__, tidx, tv[tidx].val, value);
          errcount++;
        }

      s = find_tuple (tuples2, tv[tidx].tag, &n);
      if (!s)
        ;
      else if (tv[tidx].len != n)
        {
          fprintf (stderr, PGM ":%s:tidx=%d: wrong string length returned; "
                   "expected(%d) got(%zu)\n",
                   __func__, tidx, tv[tidx].len, n);
          errcount++;
            }
      else if (memcmp (tv[tidx].data, s, n))
        {
          fprintf (stderr, PGM ":%s:tidx=%d: wrong string returned:",
                   __func__, tidx);
          for (i=0; i < n; i++)
            fprintf (stderr, " %02x", ((unsigned char*)s)[i]);
          fputc ('\n', stderr);
          errcount++;
        }
    }

  destroy_tupledesc (tuples);
  destroy_tupledesc (tuples2);
}



int
main (int argc, char **argv)
{
  int last_argc = -1;

  gpgrt_init ();
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

  test_tuple_uint ();

  return !!errcount;
}
