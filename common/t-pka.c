/* t-pak.c - Module test for pka.c
 * Copyright (C) 2015 Werner Koch
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
#include "pka.h"


int
main (int argc, char **argv)
{
  unsigned char fpr[20];
  char *url;
  char const *name;
  int i;

  if (argc)
    {
      argc--;
      argv++;
    }

  if (!argc)
    name = "wk@gnupg.org";
  else if (argc == 1)
    name = *argv;
  else
    {
      fputs ("usage: t-pka [userid]\n", stderr);
      return 1;
    }

  printf ("User id ...: %s\n", name);

  url = get_pka_info (name, fpr, sizeof fpr);
  printf ("Fingerprint: ");
  if (url)
    {
      for (i = 0; i < sizeof fpr; i++)
        printf ("%02X", fpr[i]);
    }
  else
    printf ("[not found]");

  putchar ('\n');

  printf ("URL .......: %s\n", (url && *url)? url : "[none]");

  xfree (url);

  return 0;
}
