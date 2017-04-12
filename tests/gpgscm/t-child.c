/* Sanity check for the process and IPC primitives.
 *
 * Copyright (C) 2016 g10 code GmbH
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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
# include <fcntl.h>
# include <io.h>
#endif

int
main (int argc, char **argv)
{
  char buffer[4096];
  memset (buffer, 'A', sizeof buffer);
#if _WIN32
  if (! setmode (fileno (stdin), O_BINARY))
    return 23;
  if (! setmode (fileno (stdout), O_BINARY))
    return 23;
#endif

  if (argc == 1)
    return 2;
  else if (strcmp (argv[1], "return0") == 0)
    return 0;
  else if (strcmp (argv[1], "return1") == 0)
    return 1;
  else if (strcmp (argv[1], "return77") == 0)
    return 77;
  else if (strcmp (argv[1], "hello_stdout") == 0)
    fprintf (stdout, "hello");
  else if (strcmp (argv[1], "hello_stderr") == 0)
    fprintf (stderr, "hello");
  else if (strcmp (argv[1], "stdout4096") == 0)
    fwrite (buffer, 1, sizeof buffer, stdout);
  else if (strcmp (argv[1], "stdout8192") == 0)
    {
      fwrite (buffer, 1, sizeof buffer, stdout);
      fwrite (buffer, 1, sizeof buffer, stdout);
    }
  else if (strcmp (argv[1], "cat") == 0)
    while (! feof (stdin))
      {
        size_t bytes_read;
        bytes_read = fread (buffer, 1, sizeof buffer, stdin);
        fwrite (buffer, 1, bytes_read, stdout);
      }
  else
    {
      fprintf (stderr, "unknown command %s\n", argv[1]);
      return 2;
    }
  return 0;
}
