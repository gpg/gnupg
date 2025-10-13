/* [argparse.c wk 17.06.97] Argument Parser for option handling
 * Copyright (C) 1998-2001, 2006-2008, 2012 Free Software Foundation, Inc.
 * Copyright (C) 1997-2001, 2006-2008, 2013-2017 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://gnu.org/licenses/>.
 */

/* This is used to be a modified version of gpgrt/src/argparse.c.
 * It now has only a few support functions.  [wk 2025-10-13]
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "util.h"
#include "common-defs.h"
#include "i18n.h"
#include "mischelp.h"
#include "stringhelp.h"
#include "logging.h"
#include "utf8conv.h"
#include "sysutils.h"
#include "argparse.h"


/* Optional handler to write strings.  See gnupg_set_usage_outfnc.  */
static int (*custom_outfnc) (int, const char *);



/* Write STRING and all following const char * arguments either to
   stdout or, if IS_ERROR is set, to stderr.  The list of strings must
   be terminated by a NULL.  */
static int
writestrings (int is_error, const char *string, ...)
{
  va_list arg_ptr;
  const char *s;
  int count = 0;

  if (string)
    {
      s = string;
      va_start (arg_ptr, string);
      do
        {  /* Fixme: Switch to estream?  */
          if (custom_outfnc)
            custom_outfnc (is_error? 2:1, s);
          else
            fputs (s, is_error? stderr : stdout);
          count += strlen (s);
        }
      while ((s = va_arg (arg_ptr, const char *)));
      va_end (arg_ptr);
    }
  return count;
}


static void
flushstrings (int is_error)
{
  if (custom_outfnc)
    custom_outfnc (is_error? 2:1, NULL);
  else
    fflush (is_error? stderr : stdout);
}


void
usage (int level)
{
  const char *p;

  if (!level)
    {
      writestrings (1, strusage(11), " ", strusage(13), "; ",
                    strusage (14), "\n", NULL);
      flushstrings (1);
    }
  else if (level == 1)
    {
      p = strusage (40);
      writestrings (1, p, NULL);
      if (*p && p[strlen(p)] != '\n')
        writestrings (1, "\n", NULL);
      exit (2);
    }
  else if (level == 2)
    {
      p = strusage (42);
      if (p && *p == '1')
        {
          p = strusage (40);
          writestrings (1, p, NULL);
          if (*p && p[strlen(p)] != '\n')
            writestrings (1, "\n", NULL);
        }
      writestrings (0, strusage(41), "\n", NULL);
      exit (0);
    }
}
