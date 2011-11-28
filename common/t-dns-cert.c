/* t-dns-cert.c - Module test for dns-cert.c
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include "iobuf.h"
#include "dns-cert.h"


int
main (int argc, char **argv)
{
  unsigned char *fpr;
  size_t fpr_len;
  char *url;
  int rc;
  iobuf_t iobuf;
  char const *name;

  if (argc)
    {
      argc--;
      argv++;
    }

  if (!argc)
    name = "simon.josefsson.org";
  else if (argc == 1)
    name = *argv;
  else
    {
      fputs ("usage: t-dns-cert [name]\n", stderr);
      return 1;
    }

  printf ("CERT lookup on `%s'\n", name);

  rc = get_dns_cert (name, 65536, &iobuf, &fpr, &fpr_len, &url);
  if (rc == -1)
    fputs ("lookup result: error\n", stdout);
  else if (!rc)
    fputs ("lookup result: no answer\n", stdout);
  else if (rc == 1)
    {
      printf ("lookup result: %d bytes\n",
              (int)iobuf_get_temp_length(iobuf));
      iobuf_close (iobuf);
    }
  else if (rc == 2)
    {
      if (fpr)
	{
	  int i;

	  printf ("Fingerprint found (%d bytes): ", (int)fpr_len);
	  for (i = 0; i < fpr_len; i++)
	    printf ("%02X", fpr[i]);
	  putchar ('\n');
	}
      else
	printf ("No fingerprint found\n");

      if (url)
	printf ("URL found: %s\n", url);
      else
	printf ("No URL found\n");

      xfree (fpr);
      xfree (url);
    }

  return 0;
}
