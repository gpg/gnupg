/* w32-misc.c - Helper functions needed in Windows
 * Copyright (C) 2021 g10 Code GmbH
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

#include "util.h"
#include "w32help.h"


/* Return the number of backslashes.  */
static unsigned int
count_backslashes (const char *s)
{
  unsigned int count = 0;

  for ( ;*s == '\\'; s++)
    count++;
  return count;
}


static void
strip_one_arg (char *string)
{
  char *s, *d;
  unsigned int n, i;

  for (s=d=string; *s; s++)
    if (*s == '\\')
      {
        n = count_backslashes (s);
        if (s[n] == '"')
          {
            for (i=0; i < n/2; i++)
              *d++ = '\\';
            if ((n&1)) /* Odd number of backslashes.  */
              *d++ = '"';  /* Print the quote.  */
          }
        else /* Print all backslashes.  */
          {
            for (i=0; i < n; i++)
              *d++ = '\\';
            n--; /* Adjust for the increment in the for.  */
          }
        s += n;
      }
    else if (*s == '"' && s[1])
      *d++ = *++s;
    else
      *d++ = *s;
  *d = 0;
}


/* Helper for parse_w32_commandline.  */
static int
parse_cmdstring (char *string, char **argv)
{
  int argc = 0;
  int inquote = 0;
  char *p0, *p;
  unsigned int n;

  p0 = string;
  for (p=string; *p; p++)
    {
      if (inquote)
        {
          if (*p == '\\' && p[1] == '"')
            p++;
          else if (*p == '"')
            {
              if (argv && (p[1] == ' ' || p[1] == '\t' || !p[1]))
                *p = 0;
              inquote = 0;
            }
        }
      else if (*p == '\\' && (n=count_backslashes (p)))
        {
          if (!p0) /* First non-WS; set start.  */
            p0 = p;
          if (p[n] == '"')
            {
              if (!(n&1)) /* Even number.  */
                inquote = 1;
              p++;
            }
          p += n;
        }
      else if (*p == '"')
        {
          inquote = 1;
          if (!p0 || p == string) /* First non-WS or first char; set start.  */
            p0 = p + 1;
        }
      else if (*p == ' ' || *p == '\t')
        {
          if (p0) /* We are in an argument and reached WS.  */
            {
              if (argv)
                {
                  *p = 0;
                  strip_one_arg (p0);
                  argv[argc] = p0;
                }
              argc++;
              p0 = NULL;
            }
        }
      else if (!p0) /* First non-WS; set start.  */
        p0 = p;
    }

  if (inquote || p0)
    {
      /* Closing quote missing (we accept this as argument anyway) or
       * an open argument.  */
      if (argv)
        {
          *p = 0;
          strip_one_arg (p0);
          argv[argc] = p0;
        }
      argc++;
    }

  return argc;
}

/* This is a Windows command line parser, returning an array with
 * strings and its count.  The argument CMDLINE is expected to be
 * utf-8 encoded and may be modified after returning from this
 * function.  The returned array points into CMDLINE, so this should
 * not be freed.  If GLOBING is set to true globing is done for all
 * items.  Returns NULL on error.  The number of items in the array is
 * returned at R_ARGC.  */
char **
w32_parse_commandline (char *cmdline, int globing, int *r_argc)
{
  int argc, i;
  char **argv;

  (void)globing;

  argc = parse_cmdstring (cmdline, NULL);
  if (!argc)
    {
      log_error ("%s failed: %s\n", __func__, "internal error");
      return NULL;  /* Ooops.  */
    }
  argv = xtrycalloc (argc+1, sizeof *argv);
  if (!argv)
    {
      log_error ("%s failed: %s\n", __func__, strerror (errno));
      return NULL;  /* Ooops.  */
    }
  i = parse_cmdstring (cmdline, argv);
  if (argc != i)
    {
      log_error ("%s failed (argc=%d i=%d)\n", __func__, argc, i);
      xfree (argv);
      return NULL;  /* Ooops.  */
    }
  *r_argc = argc;
  return argv;
}
