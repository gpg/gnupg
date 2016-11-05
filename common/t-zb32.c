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

#include "zb32.h"
#include "t-support.h"

#define PGM "t-zb32"

static int verbose;
static int debug;
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
          fprintf (stderr, PGM": error encoding test %d: %s\n",
                   tidx, strerror (errno));
          exit (1);
        }
      /* puts (output); */
      if (strcmp (output, tests[tidx].expected))
        fail (tidx);
      xfree (output);
    }
}


/* Read the file FNAME or stdin if FNAME is NULL and return a malloced
   buffer with the content.  R_LENGTH received the length of the file.
   Print a diagnostic and returns NULL on error.  */
static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  char *buf;
  size_t buflen;

  if (!fname)
    {
      size_t nread, bufsize = 0;

      fp = stdin;
#ifdef HAVE_DOSISH_SYSTEM
      setmode (fileno(fp) , O_BINARY );
#endif
      buf = NULL;
      buflen = 0;
#define NCHUNK 8192
      do
        {
          bufsize += NCHUNK;
          if (!buf)
            buf = xmalloc (bufsize);
          else
            buf = xrealloc (buf, bufsize);

          nread = fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && ferror (fp))
            {
              fprintf (stderr, PGM": error reading '[stdin]': %s\n",
                       strerror (errno));
              xfree (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK

    }
  else
    {
      struct stat st;

      fp = fopen (fname, "rb");
      if (!fp)
        {
          fprintf (stderr, PGM": can't open '%s': %s\n",
                   fname, strerror (errno));
          return NULL;
        }

      if (fstat (fileno(fp), &st))
        {
          fprintf (stderr, PGM": can't stat '%s': %s\n",
                   fname, strerror (errno));
          fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = xmalloc (buflen+1);
      if (fread (buf, buflen, 1, fp) != 1)
        {
          fprintf (stderr, PGM": error reading '%s': %s\n",
                   fname, strerror (errno));
          fclose (fp);
          xfree (buf);
          return NULL;
        }
      fclose (fp);
    }

  *r_length = buflen;
  return buf;
}


/* Debug helper to encode or decode to/from zb32.  */
static void
endecode_file (const char *fname, int decode)
{
  char *buffer;
  size_t buflen;
  char *result;

  if (decode)
    {
      fprintf (stderr, PGM": decode mode has not yet been implemented\n");
      errcount++;
      return;
    }

#ifdef HAVE_DOSISH_SYSTEM
  if (decode)
    setmode (fileno (stdout), O_BINARY);
#endif


  buffer = read_file (fname, &buflen);
  if (!buffer)
    {
      errcount++;
      return;
    }

  result = zb32_encode (buffer, 8 * buflen);
  if (!result)
    {
      fprintf (stderr, PGM": error encoding data: %s\n", strerror (errno));
      errcount++;
      xfree (buffer);
      return;
    }

  fputs (result, stdout);
  putchar ('\n');

  xfree (result);
  xfree (buffer);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  int opt_endecode = 0;

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
                 "  --encode          Encode FILE or stdin\n"
                 "  --decode          Decode FILE or stdin\n"
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
      else if (!strcmp (*argv, "--encode"))
        {
          opt_endecode = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--decode"))
        {
          opt_endecode = -1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (argc > 1)
    {
      fprintf (stderr, PGM ": to many arguments given\n");
      exit (1);
    }

  if (opt_endecode)
    {
      endecode_file (argc? *argv : NULL, (opt_endecode < 0));
    }
  else
    test_zb32enc ();

  return !!errcount;
}
