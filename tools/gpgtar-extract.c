/* gpgtar-extract.c - Extract from a TAR archive
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include "i18n.h"
#include "../common/sysutils.h"
#include "gpgtar.h"



static gpg_error_t
extract_regular (estream_t stream, const char *dirname,
                 tar_header_t hdr)
{
  gpg_error_t err;
  char record[RECORDSIZE];
  size_t n, nbytes, nwritten;
  char *fname;
  estream_t outfp = NULL;

  fname = strconcat (dirname, "/", hdr->name, NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating filename: %s\n", gpg_strerror (err));
      goto leave;
    }
  else
    err = 0;
  
  outfp = es_fopen (fname, "wb");
  if (!outfp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating `%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  for (n=0; n < hdr->nrecords;)
    {
      err = read_record (stream, record);
      if (err)
        goto leave;
      n++;
      nbytes = (n < hdr->nrecords)? RECORDSIZE : (hdr->size % RECORDSIZE);
      nwritten = es_fwrite (record, 1, nbytes, outfp);
      if (nwritten != nbytes)
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing `%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
    }
  /* Fixme: Set permissions etc.  */

 leave:
  es_fclose (outfp);
  if (err && fname && outfp)
    {
      if (gnupg_remove (fname))
        log_error ("error removing incomplete file `%s': %s\n",
                   fname, gpg_strerror (gpg_error_from_syserror ()));
    }
  xfree (fname);
  return err;
}


static gpg_error_t
extract_directory (const char *dirname, tar_header_t hdr)
{
  gpg_error_t err;
  char *fname;

  fname = strconcat (dirname, "/", hdr->name, NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating filename: %s\n", gpg_strerror (err));
      goto leave;
    }
  else
    err = 0;

  if (gnupg_mkdir (fname, "-rwx------"))
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating directory `%s': %s\n",
                 fname, gpg_strerror (err));
    }

 leave:
  xfree (fname);
  return err;
}


static gpg_error_t
extract (estream_t stream, const char *dirname, tar_header_t hdr)
{
  gpg_error_t err;
  size_t n;

  n = strlen (hdr->name);
#ifdef HAVE_DOSISH_SYSTEM
  if (strchr (hdr->name, '\\'))
    {
      log_error ("filename `%s' contains a backslash - "
                 "can't extract on this system\n", hdr->name);
      return gpg_error (GPG_ERR_INV_NAME);
    }
#endif /*HAVE_DOSISH_SYSTEM*/

  if (!n
      || strstr (hdr->name, "//") 
      || strstr (hdr->name, "/../") 
      || !strncmp (hdr->name, "../", 3)
      || (n >= 3 && !strcmp (hdr->name+n-3, "/.." )))
    {
      log_error ("filename `%s' as suspicious parts - not extracting\n",
                 hdr->name);
      return gpg_error (GPG_ERR_INV_NAME);
    }

  if (hdr->typeflag == TF_REGULAR || hdr->typeflag == TF_UNKNOWN)
    err = extract_regular (stream, dirname, hdr);
  else if (hdr->typeflag == TF_DIRECTORY)
    err = extract_directory (dirname, hdr);
  else
    {
      char record[RECORDSIZE];

      log_info ("unsupported file type for `%s' - skipped\n", hdr->name);
      for (err = 0, n=0; !err && n < hdr->nrecords; n++)
        err = read_record (stream, record);
    }
  return err;
}


/* Create a new directory to be used for extracting the tarball.
   Returns the name of the directory which must be freed by the
   caller.  In case of an error a diagnostic is printed and NULL
   returned.  */
static char *
create_directory (const char *dirprefix)
{
  gpg_error_t err = 0;
  char *dirname = NULL;
  int idx;

  for (idx=1; idx < 5000; idx++)
    {
      xfree (dirname);
      dirname = xtryasprintf ("%s_%d_", dirprefix, idx);
      if (!dirname)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (!gnupg_mkdir (dirname, "-rwx------"))
        goto leave;
      if (errno != EEXIST && errno != ENOTDIR)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  err = gpg_error_from_syserror ();

 leave:
  if (err)
    {
      log_error ("error creating an extract directory: %s\n",
                 gpg_strerror (err));
      xfree (dirname);
      dirname = NULL;
    }
  return dirname;
}



void
gpgtar_extract (const char *filename)
{
  gpg_error_t err;
  estream_t stream;
  tar_header_t header = NULL;
  const char *dirprefix = NULL;
  char *dirname = NULL;

  if (filename)
    {
      dirprefix = strrchr (filename, '/');
      if (dirprefix)
        dirprefix++;
      stream = es_fopen (filename, "rb");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          log_error ("error opening `%s': %s\n", filename, gpg_strerror (err));
          return;
        }
    }
  else
    stream = es_stdin;  /* FIXME:  How can we enforce binary mode?  */

  if (!dirprefix || !*dirprefix)
    dirprefix = "GPGARCH";

  dirname = create_directory (dirprefix);
  if (!dirname)
    {
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (opt.verbose)
    log_info ("extracting to `%s/'\n", dirname);

  for (;;)
    {
      header = gpgtar_read_header (stream);
      if (!header)
        goto leave;
     
      if (extract (stream, dirname, header))
        goto leave;
      xfree (header);
      header = NULL;
    }


 leave:
  xfree (header);
  xfree (dirname);
  if (stream != es_stdin)
    es_fclose (stream);
  return;
}
