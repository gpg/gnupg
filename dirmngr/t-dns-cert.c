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
#include "dns-cert.h"


int
main (int argc, char **argv)
{
  gpg_error_t err;
  unsigned char *fpr;
  size_t fpr_len;
  char *url;
  void *key;
  size_t keylen;
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

  printf ("CERT lookup on '%s'\n", name);

  err = get_dns_cert (name, DNS_CERTTYPE_ANY, &key, &keylen,
                      &fpr, &fpr_len, &url);
  if (err)
    printf ("get_dns_cert failed: %s <%s>\n",
            gpg_strerror (err), gpg_strsource (err));
  else if (key)
    {
      printf ("Key found (%u bytes)\n", (unsigned int)keylen);
    }
  else
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

    }

  xfree (key);
  xfree (fpr);
  xfree (url);

  return 0;
}
