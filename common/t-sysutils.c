/* t-sysutils.c - Module test for sysutils.c
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

#include "util.h"
#include "sysutils.h"

#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     errcount++;                                 \
                   } while(0)

static int verbose;
static int errcount;


static void
test_gnupg_tmpfile (void)
{
  FILE *fparr[10];
  int fparridx;
  int idx;
  FILE *fp;
  char buffer[100];

#define ASTRING "fooooooooooooooo\n"  /* Needs to be shorter than BUFFER.  */

  for (fparridx=0; fparridx < DIM (fparr); fparridx++)
    {
      fp = gnupg_tmpfile ();
      fparr[fparridx] = fp;
      if (!fp)
        fail (fparridx);
      else
        {
          fputs ( ASTRING, fp);
          rewind (fp);
          if (!fgets (buffer, sizeof (buffer), fp))
            fail (fparridx);
          if (strcmp (buffer, ASTRING))
            fail (fparridx);
          if (fgets (buffer, sizeof (buffer), fp))
            fail (fparridx);
        }
    }
  for (idx=0; idx < fparridx; idx++)
    {
      if (fparr[idx])
        fclose (fparr[idx]);
    }
}



int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  test_gnupg_tmpfile ();

  return !!errcount;
}

