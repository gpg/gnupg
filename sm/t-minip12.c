/* t-minip12.c - Test driver for minip12.c
 * Copyright (C) 2020 g10 Code GmbH
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
#include <sys/stat.h>
#include <unistd.h>

#include "../common/util.h"
#include "minip12.h"


#define PGM "t-minip12"

static int verbose;
static int debug;



static void
cert_cb (void *opaque, const unsigned char *cert, size_t certlen)
{
  (void)opaque;
  (void)cert;

  if (verbose)
    log_info ("got a certificate of %zu bytes length\n", certlen);
}



int
main (int argc, char **argv)
{
  int last_argc = -1;
  char const *name = NULL;
  char const *pass = NULL;
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen;
  gcry_mpi_t *result;
  int badpass;
  char *curve = NULL;

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
          fputs ("usage: " PGM " <pkcs12file> [<passphrase>]\n"
                 "Options:\n"
                 "  --verbose           print timings etc.\n"
                 "  --debug             flyswatter\n"
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
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (argc == 1)
    {
      name = argv[0];
      pass = "";
    }
  else if (argc == 2)
    {
      name = argv[0];
      pass = argv[1];
    }
  else
    {
      fprintf (stderr, "usage: " PGM " <file> [<passphrase>]\n");
      exit (1);
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, NULL);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL);


  fp = fopen (name, "rb");
  if (!fp)
    {
      fprintf (stderr, PGM": can't open '%s': %s\n", name, strerror (errno));
      return 1;
    }

  if (fstat (fileno(fp), &st))
    {
      fprintf (stderr, PGM": can't stat '%s': %s\n", name, strerror (errno));
      return 1;
    }

  buflen = st.st_size;
  buf = gcry_malloc (buflen+1);
  if (!buf || fread (buf, buflen, 1, fp) != 1)
    {
      fprintf (stderr, "error reading '%s': %s\n", name, strerror (errno));
      return 1;
    }
  fclose (fp);

  result = p12_parse (buf, buflen, pass, cert_cb, NULL, &badpass, &curve);
  if (result)
    {
      int i, rc;
      unsigned char *tmpbuf;

      if (curve)
        log_info ("curve: %s\n", curve);
      for (i=0; result[i]; i++)
        {
          rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &tmpbuf, NULL, result[i]);
          if (rc)
            log_error ("%d: [error printing number: %s]\n",
                       i, gpg_strerror (rc));
          else
            {
              log_info ("%d: %s\n", i, tmpbuf);
              gcry_free (tmpbuf);
            }
        }
    }

  return 0;
}
