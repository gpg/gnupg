/* loadswdb.c - Load the swdb file from versions.gnupg.org
 * Copyright (C) 2016 g10 Code GmbH
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
#include <string.h>

#include "dirmngr.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "misc.h"
#include "ks-engine.h"


/* Get the time from the current swdb file and store it at R_FILEDATE
 * and R_VERIFIED.  If the file does not exist 0 is stored at there.
 * The function returns 0 on success or an error code.  */
static gpg_error_t
time_of_saved_swdb (const char *fname, time_t *r_filedate, time_t *r_verified)
{
  gpg_error_t err;
  estream_t fp = NULL;
  char *line = NULL;
  size_t length_of_line = 0;
  size_t  maxlen;
  ssize_t len;
  char *fields[2];
  gnupg_isotime_t isot;
  time_t filedate = (time_t)(-1);
  time_t verified = (time_t)(-1);

  *r_filedate = 0;
  *r_verified = 0;

  fp = es_fopen (fname, "r");
  err = fp? 0 : gpg_error_from_syserror ();
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_ENOENT)
        err = 0; /* No file - assume time is the year of Unix.  */
      goto leave;
    }

  /* Note that the parser uses the first occurrence of a matching
   * values and ignores possible duplicated values.  */
  maxlen = 2048; /* Set limit.  */
  while ((len = es_read_line (fp, &line, &length_of_line, &maxlen)) > 0)
    {
      if (!maxlen)
        {
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          goto leave;
        }
      /* Strip newline and carriage return, if present.  */
      while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	line[--len] = '\0';

      if (split_fields (line, fields, DIM (fields)) < DIM(fields))
        continue; /* Skip empty lines and names w/o a value.  */
      if (*fields[0] == '#')
        continue; /* Skip comments.  */

      /* Record the meta data.  */
      if (filedate == (time_t)(-1) && !strcmp (fields[0], ".filedate"))
        {
          if (string2isotime (isot, fields[1]))
            filedate = isotime2epoch (isot);
        }
      else if (verified == (time_t)(-1) && !strcmp (fields[0], ".verified"))
        {
          if (string2isotime (isot, fields[1]))
            verified = isotime2epoch (isot);
        }
    }
  if (len < 0 || es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (filedate == (time_t)(-1) || verified == (time_t)(-1))
    {
      err = gpg_error (GPG_ERR_INV_TIME);
      goto leave;
    }

  *r_filedate = filedate;
  *r_verified = verified;

 leave:
  if (err)
    log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
  xfree (line);
  es_fclose (fp);
  return err;
}



/* Read a file from URL and return it as an estream memory buffer at
 * R_FP.  */
static gpg_error_t
fetch_file (ctrl_t ctrl, const char *url, estream_t *r_fp)
{
  gpg_error_t err;
  estream_t fp = NULL;
  estream_t httpfp = NULL;
  size_t nread, nwritten;
  char buffer[1024];

  if ((err = ks_http_fetch (ctrl, url, &httpfp)))
    goto leave;

  /* We now read the data from the web server into a memory buffer.
   * To avoid excessive memory use in case of a ill behaving server we
   * put a 64 k size limit on the buffer.  As of today the actual size
   * of the swdb.lst file is 3k.  */
  fp = es_fopenmem (64*1024, "rw");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  for (;;)
    {
      if (es_read (httpfp, buffer, sizeof buffer, &nread))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n",
                     es_fname_get (httpfp), gpg_strerror (err));
          goto leave;
        }

      if (!nread)
        break; /* Ready.  */
      if (es_write (fp, buffer, nread, &nwritten))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing '%s': %s\n",
                     es_fname_get (fp), gpg_strerror (err));
          goto leave;
        }
      else if (nread != nwritten)
        {
          err = gpg_error (GPG_ERR_EIO);
          log_error ("error writing '%s': %s\n",
                     es_fname_get (fp), "short write");
          goto leave;
        }
    }

  es_rewind (fp);
  *r_fp = fp;
  fp = NULL;

 leave:
  es_fclose (httpfp);
  es_fclose (fp);
  return err;
}


/* Communication object for verify_status_cb.  */
struct verify_status_parm_s
{
  time_t sigtime;
  int anyvalid;
};

static void
verify_status_cb (void *opaque, const char *keyword, char *args)
{
  struct verify_status_parm_s *parm = opaque;

  if (DBG_EXTPROG)
    log_debug ("gpgv status: %s %s\n", keyword, args);

  /* We care only about the first valid signature.  */
  if (!strcmp (keyword, "VALIDSIG") && !parm->anyvalid)
    {
      char *fields[3];

      parm->anyvalid = 1;
      if (split_fields (args, fields, DIM (fields)) >= 3)
        parm->sigtime = parse_timestamp (fields[2], NULL);
    }
}



/* Load the swdb file into the current home directory.  Do this onlky
 * when needed unless FORCE is set which will always get a new
 * copy.  */
gpg_error_t
dirmngr_load_swdb (ctrl_t ctrl, int force)
{
  gpg_error_t err;
  char *fname = NULL;      /* The swdb.lst file.  */
  char *tmp_fname = NULL;  /* The temporary swdb.lst file.  */
  char *keyfile_fname = NULL;
  estream_t swdb = NULL;
  estream_t swdb_sig = NULL;
  ccparray_t ccp;
  const char **argv = NULL;
  struct verify_status_parm_s verify_status_parm = { (time_t)(-1), 0 };
  estream_t outfp = NULL;
  time_t now = gnupg_get_time ();
  time_t filedate = 0;  /* ".filedate" from our swdb.  */
  time_t verified = 0;  /* ".verified" from our swdb.  */
  gnupg_isotime_t isotime;


  fname = make_filename_try (gnupg_homedir (), "swdb.lst", NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Check whether there is a need to get an update.  */
  if (!force)
    {
      static int not_older_than;
      static time_t lastcheck;

      if (!not_older_than)
        {
          /* To balance access to the server we use a random time from
           * 5 to 7 days for update checks.  */
          not_older_than = 5 * 86400;
          not_older_than += (get_uint_nonce () % (2*86400));
        }

      if (now - lastcheck < 3600)
        {
          /* We checked our swdb file in the last hour - don't check
           * again to avoid unnecessary disk access.  */
          err = 0;
          goto leave;
        }
      lastcheck = now;

      err = time_of_saved_swdb (fname, &filedate, &verified);
      if (gpg_err_code (err) == GPG_ERR_INV_TIME)
        err = 0; /* Force reading. */
      if (err)
        goto leave;
      if (filedate >= now)
        goto leave; /* Current or newer.  */
      if (now - filedate < not_older_than)
        goto leave; /* Our copy is pretty new (not older than 7 days).  */
      if (verified > now && now - verified < 3*3600)
        goto leave; /* We downloaded and verified in the last 3 hours.  */
    }

  /* Create the filename of the file with the keys. */
  keyfile_fname = make_filename_try (gnupg_datadir (), "distsigkey.gpg", NULL);
  if (!keyfile_fname)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Fetch the swdb from the web.  */
  err = fetch_file (ctrl, "https://versions.gnupg.org/swdb.lst", &swdb);
  if (err)
    goto leave;
  err = fetch_file (ctrl, "https://versions.gnupg.org/swdb.lst.sig", &swdb_sig);
  if (err)
    goto leave;

  /* Run gpgv.  */
  ccparray_init (&ccp, 0);
  ccparray_put (&ccp, "--enable-special-filenames");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--keyring");
  ccparray_put (&ccp, keyfile_fname);
  ccparray_put (&ccp, "--");
  ccparray_put (&ccp, "-&@INEXTRA@");
  ccparray_put (&ccp, "-");
  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (DBG_EXTPROG)
    log_debug ("starting gpgv\n");
  err = gnupg_exec_tool_stream (gnupg_module_name (GNUPG_MODULE_NAME_GPGV),
                                argv, swdb, swdb_sig, NULL,
                                verify_status_cb, &verify_status_parm);
  if (!err && verify_status_parm.sigtime == (time_t)(-1))
    err = gpg_error (verify_status_parm.anyvalid? GPG_ERR_BAD_SIGNATURE
                     /**/                       : GPG_ERR_INV_TIME      );
  if (DBG_EXTPROG)
    log_debug ("gpgv finished: err=%d\n", err);
  if (err)
    goto leave;

  /* If our swdb is not older than the downloaded one.  We don't
   * bother to update.  */
  if (!force && filedate >= verify_status_parm.sigtime)
    goto leave;

  /* Create a file name for a temporary file in the home directory.
   * We will later rename that file to the real name.  */
  {
    char *tmpstr;

#ifdef HAVE_W32_SYSTEM
    tmpstr = es_bsprintf ("tmp-%u-swdb", (unsigned int)getpid ());
#else
    tmpstr = es_bsprintf (".#%u.swdb", (unsigned int)getpid ());
#endif
    if (!tmpstr)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
    tmp_fname = make_filename_try (gnupg_homedir (), tmpstr, NULL);
    xfree (tmpstr);
    if (!tmp_fname)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
  }

  outfp = es_fopen (tmp_fname, "w");
  if (!outfp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating '%s': %s\n"), tmp_fname, gpg_strerror (err));
      goto leave;
    }

  epoch2isotime (isotime, verify_status_parm.sigtime);
  es_fprintf (outfp, ".filedate %s\n", isotime);
  epoch2isotime (isotime, now);
  es_fprintf (outfp, ".verified %s\n", isotime);

  if (es_fseek (swdb, 0, SEEK_SET))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = copy_stream (swdb, outfp);
  if (err)
    {
      /* Well, it might also be a reading error, but that is pretty
       * unlikely for a memory stream.  */
      log_error (_("error writing '%s': %s\n"), tmp_fname, gpg_strerror (err));
      goto leave;
    }

  if (es_fclose (outfp))
    {
      err = gpg_error_from_syserror ();
      log_error (_("error writing '%s': %s\n"), tmp_fname, gpg_strerror (err));
      goto leave;
    }
  outfp = NULL;

  err = gnupg_rename_file (tmp_fname, fname, NULL);
  if (err)
    goto leave;
  xfree (tmp_fname);
  tmp_fname = NULL;


 leave:
  es_fclose (outfp);
  if (tmp_fname)
    gnupg_remove (tmp_fname);  /* This is a temporary file.  */
  xfree (argv);
  es_fclose (swdb_sig);
  es_fclose (swdb);
  xfree (keyfile_fname);
  xfree (tmp_fname);
  xfree (fname);
  return err;
}
