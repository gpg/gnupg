/* Fake pinentry program for the OpenPGP test suite.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int
main (int argc, char **argv)
{
  static char *passphrase;
  char *p;

  (void) argc, (void) argv;

  setvbuf (stdin, NULL, _IOLBF, BUFSIZ);
  setvbuf (stdout, NULL, _IOLBF, BUFSIZ);

  if (!passphrase)
    {
      passphrase = getenv ("PINENTRY_USER_DATA");
      if (!passphrase)
        passphrase = "";
      for (p=passphrase; *p; p++)
        if (*p == '\r' || *p == '\n')
          *p = '.';
      printf ("# Passphrase='%s'\n", passphrase);
    }

  printf ("OK - what's up?\n");

  while (! feof (stdin))
    {
      char buffer[1024];

      if (fgets (buffer, sizeof buffer, stdin) == NULL)
	break;

      if (strncmp (buffer, "GETPIN", 6) == 0)
	printf ("D %s\nOK\n", passphrase);
      else if (strncmp (buffer, "BYE", 3) == 0)
	{
	  printf ("OK\n");
	  break;
	}
      else
	printf ("OK\n");
    }
  return 0;
}
