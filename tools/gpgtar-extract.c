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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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

#include "../common/i18n.h"
#include "../common/exectool.h"
#include "../common/sysutils.h"
#include "../common/ccparray.h"
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

  if (opt.dry_run)
    outfp = es_fopenmem (0, "wb");
  else
    outfp = es_fopen (fname, "wb");
  if (!outfp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating '%s': %s\n", fname, gpg_strerror (err));
      goto leave;
    }

  for (n=0; n < hdr->nrecords;)
    {
      err = read_record (stream, record);
      if (err)
        goto leave;
      n++;
      if (n < hdr->nrecords || (hdr->size && !(hdr->size % RECORDSIZE)))
        nbytes = RECORDSIZE;
      else
        nbytes = (hdr->size % RECORDSIZE);

      nwritten = es_fwrite (record, 1, nbytes, outfp);
      if (nwritten != nbytes)
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
    }
  /* Fixme: Set permissions etc.  */

 leave:
  if (!err && opt.verbose)
    log_info ("extracted '%s'\n", fname);
  es_fclose (outfp);
  if (err && fname && outfp)
    {
      if (gnupg_remove (fname))
        log_error ("error removing incomplete file '%s': %s\n",
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
  size_t prefixlen;

  prefixlen = strlen (dirname) + 1;
  fname = strconcat (dirname, "/", hdr->name, NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating filename: %s\n", gpg_strerror (err));
      goto leave;
    }
  else
    err = 0;

  if (fname[strlen (fname)-1] == '/')
    fname[strlen (fname)-1] = 0;

  if (! opt.dry_run && gnupg_mkdir (fname, "-rwx------"))
    {
      err = gpg_error_from_syserror ();
      if (gpg_err_code (err) == GPG_ERR_EEXIST)
        {
          /* Ignore existing directories while extracting.  */
          err = 0;
        }

      if (gpg_err_code (err) == GPG_ERR_ENOENT)
        {
          /* Try to create the directory with parents but keep the
             original error code in case of a failure.  */
          char *p;
          int rc = 0;

          for (p = fname+prefixlen; (p = strchr (p, '/')); p++)
            {
              *p = 0;
              rc = gnupg_mkdir (fname, "-rwx------");
              *p = '/';
              if (rc)
                break;
            }
          if (!rc && !gnupg_mkdir (fname, "-rwx------"))
            err = 0;
        }
      if (err)
        log_error ("error creating directory '%s': %s\n",
                   fname, gpg_strerror (err));
    }

 leave:
  if (!err && opt.verbose)
    log_info ("created   '%s/'\n", fname);
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
      log_error ("filename '%s' contains a backslash - "
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
      log_error ("filename '%s' as suspicious parts - not extracting\n",
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

      log_info ("unsupported file type %d for '%s' - skipped\n",
                (int)hdr->typeflag, hdr->name);
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
  char *prefix_buffer = NULL;
  char *dirname = NULL;
  size_t n;
  int idx;

  /* Remove common suffixes.  */
  n = strlen (dirprefix);
  if (n > 4 && (!compare_filenames    (dirprefix + n - 4, EXTSEP_S GPGEXT_GPG)
                || !compare_filenames (dirprefix + n - 4, EXTSEP_S "pgp")
                || !compare_filenames (dirprefix + n - 4, EXTSEP_S "asc")
                || !compare_filenames (dirprefix + n - 4, EXTSEP_S "pem")
                || !compare_filenames (dirprefix + n - 4, EXTSEP_S "p7m")
                || !compare_filenames (dirprefix + n - 4, EXTSEP_S "p7e")))
    {
      prefix_buffer = xtrystrdup (dirprefix);
      if (!prefix_buffer)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      prefix_buffer[n-4] = 0;
      dirprefix = prefix_buffer;
    }



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
        goto leave; /* Ready.  */
      if (errno != EEXIST && errno != ENOTDIR)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  err = gpg_error (GPG_ERR_LIMIT_REACHED);

 leave:
  if (err)
    {
      log_error ("error creating an extract directory: %s\n",
                 gpg_strerror (err));
      xfree (dirname);
      dirname = NULL;
    }
  xfree (prefix_buffer);
  return dirname;
}



gpg_error_t
gpgtar_extract (const char *filename, int decrypt)
{
  gpg_error_t err;
  estream_t stream;
  estream_t cipher_stream = NULL;
  tar_header_t header = NULL;
  const char *dirprefix = NULL;
  char *dirname = NULL;

  if (filename)
    {
      if (!strcmp (filename, "-"))
        stream = es_stdin;
      else
        stream = es_fopen (filename, "rb");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          log_error ("error opening '%s': %s\n", filename, gpg_strerror (err));
          return err;
        }
    }
  else
    stream = es_stdin;

  if (stream == es_stdin)
    es_set_binary (es_stdin);

  if (decrypt)
    {
      strlist_t arg;
      ccparray_t ccp;
      const char **argv;

      cipher_stream = stream;
      stream = es_fopenmem (0, "rwb");
      if (! stream)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      ccparray_init (&ccp, 0);

      ccparray_put (&ccp, "--decrypt");
      for (arg = opt.gpg_arguments; arg; arg = arg->next)
        ccparray_put (&ccp, arg->d);

      ccparray_put (&ccp, NULL);
      argv = ccparray_get (&ccp, NULL);
      if (!argv)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      err = gnupg_exec_tool_stream (opt.gpg_program, argv,
                                    cipher_stream, NULL, stream, NULL, NULL);
      xfree (argv);
      if (err)
        goto leave;

      err = es_fseek (stream, 0, SEEK_SET);
      if (err)
        goto leave;
    }

  if (opt.directory)
    dirname = xtrystrdup (opt.directory);
  else
    {
      if (filename)
        {
          dirprefix = strrchr (filename, '/');
          if (dirprefix)
            dirprefix++;
          else
            dirprefix = filename;
        }
      else if (opt.filename)
        {
          dirprefix = strrchr (opt.filename, '/');
          if (dirprefix)
            dirprefix++;
          else
            dirprefix = opt.filename;
        }

      if (!dirprefix || !*dirprefix)
        dirprefix = "GPGARCH";

      dirname = create_directory (dirprefix);
      if (!dirname)
        {
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
    }

  if (opt.verbose)
    log_info ("extracting to '%s/'\n", dirname);

  for (;;)
    {
      err = gpgtar_read_header (stream, &header);
      if (err || header == NULL)
        goto leave;

      err = extract (stream, dirname, header);
      if (err)
        goto leave;
      xfree (header);
      header = NULL;
    }


 leave:
  xfree (header);
  xfree (dirname);
  if (stream != es_stdin)
    es_fclose (stream);
  if (stream != cipher_stream)
    es_fclose (cipher_stream);
  return err;
}
