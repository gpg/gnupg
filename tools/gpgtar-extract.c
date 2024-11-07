/* gpgtar-extract.c - Extract from a TAR archive
 * Copyright (C) 2016-2017, 2019-2022 g10 Code GmbH
 * Copyright (C) 2010, 2012, 2013 Werner Koch
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/i18n.h"
#include <gpg-error.h>
#include "../common/sysutils.h"
#include "../common/ccparray.h"
#include "gpgtar.h"

static gpg_error_t
check_suspicious_name (const char *name, tarinfo_t info)
{
  size_t n;

  n = strlen (name);
#ifdef HAVE_DOSISH_SYSTEM
  if (strchr (name, '\\'))
    {
      log_error ("filename '%s' contains a backslash - "
                 "can't extract on this system\n", name);
      info->skipped_badname++;
      return gpg_error (GPG_ERR_INV_NAME);
    }
#endif /*HAVE_DOSISH_SYSTEM*/

  if (!n
      || strstr (name, "//")
      || strstr (name, "/../")
      || !strncmp (name, "../", 3)
      || (n >= 3 && !strcmp (name+n-3, "/.." )))
    {
      log_error ("filename '%s' has suspicious parts - not extracting\n",
                 name);
      info->skipped_suspicious++;
      return gpg_error (GPG_ERR_INV_NAME);
    }

  return 0;
}


/* This is our version of mkdir -p.  DIRECTORY is the full filename of
 * the directory and PREFIXLEN is the length of an intial directory
 * part which already exists.  If STRIP is set filename is removed.
 * If VERBOSE is set a diagnostic is printed to show the created
 * directory.  */
static gpg_error_t
try_mkdir_p (const char *directory, size_t prefixlen, int strip, int verbose)
{
  gpg_error_t err = 0;
  char *fname;
  char *p;

  fname = xtrystrdup (directory);
  if (!fname)
    return gpg_error_from_syserror ();

  if (strip) /* Strip last file name. */
    {
      p = strrchr (fname, '/');
      if (p)
        *p = 0;
    }
  else /* Remove a possible trailing slash.  */
    {
      if (fname[strlen (fname)-1] == '/')
        fname[strlen (fname)-1] = 0;
    }

  if (prefixlen >= strlen (fname))
    goto leave; /* Nothing to create */

  for (p = fname+prefixlen; (p = strchr (p, '/')); p++)
    {
      *p = 0;
      err = gnupg_mkdir (fname, "-rwx------");
      if (gpg_err_code (err) == GPG_ERR_EEXIST)
        err = 0;
      *p = '/';
      if (err)
        goto leave;
    }
  err = gnupg_mkdir (fname, "-rwx------");
  if (gpg_err_code (err) == GPG_ERR_EEXIST)
    err = 0;
  if (!err && verbose)
    log_info ("created   '%s/'\n", fname);

 leave:
  xfree (fname);
  return err;
}



static gpg_error_t
extract_regular (estream_t stream, const char *dirname,
                 tarinfo_t info, tar_header_t hdr, strlist_t exthdr)
{
  gpg_error_t err;
  char record[RECORDSIZE];
  size_t n, nbytes, nwritten;
  char *fname_buffer = NULL;
  const char *fname;
  estream_t outfp = NULL;
  strlist_t sl;

  fname = hdr->name;
  for (sl = exthdr; sl; sl = sl->next)
    if (sl->flags == 1)
      fname = sl->d;

  err = check_suspicious_name (fname, info);
  if (err)
    goto leave;

  fname_buffer = strconcat (dirname, "/", fname, NULL);
  if (!fname_buffer)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating filename: %s\n", gpg_strerror (err));
      goto leave;
    }
  fname = fname_buffer;

  if (opt.dry_run)
    outfp = es_fopen ("/dev/null", "wb");
  else
    outfp = es_fopen (fname, "wb,sysopen");
  if (!outfp)
    {
      err = gpg_error_from_syserror ();
      /* On ENOENT, try afain after trying to create the directories.  */
      if (!opt.dry_run && gpg_err_code (GPG_ERR_ENOENT)
          && !try_mkdir_p (fname, strlen (dirname) + 1, 1, opt.verbose))
        {
          outfp = es_fopen (fname, "wb,sysopen");
          err = outfp? 0 : gpg_error_from_syserror ();
        }
      if (err)
        {
          log_error ("error creating '%s': %s\n", fname, gpg_strerror (err));
          goto leave;
        }
    }

  for (n=0; n < hdr->nrecords;)
    {
      err = read_record (stream, record);
      if (err)
        goto leave;
      info->nblocks++;
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
  if (!err)
    {
      if (opt.verbose)
        log_info ("extracted '%s'\n", fname);
      info->nextracted++;
    }
  es_fclose (outfp);
  if (err && fname && outfp)
    {
      if (gnupg_remove (fname))
        log_error ("error removing incomplete file '%s': %s\n",
                   fname, gpg_strerror (gpg_error_from_syserror ()));
    }
  xfree (fname_buffer);
  return err;
}


static gpg_error_t
extract_directory (const char *dirname, tarinfo_t info,
                   tar_header_t hdr, strlist_t exthdr)
{
  gpg_error_t err;
  const char *name;
  char *fname = NULL;
  strlist_t sl;

  name = hdr->name;
  for (sl = exthdr; sl; sl = sl->next)
    if (sl->flags == 1)
      name = sl->d;

  err = check_suspicious_name (name, info);
  if (err)
    goto leave;

  fname = strconcat (dirname, "/", name, NULL);
  if (!fname)
    {
      err = gpg_error_from_syserror ();
      log_error ("error creating filename: %s\n", gpg_strerror (err));
      goto leave;
    }
  /* Remove a possible trailing slash.  */
  if (fname[strlen (fname)-1] == '/')
    fname[strlen (fname)-1] = 0;

  if (!opt.dry_run && gnupg_mkdir (fname, "-rwx------"))
    {
      err = gpg_error_from_syserror ();
      /* Ignore existing directories while extracting.  */
      if (gpg_err_code (err) == GPG_ERR_EEXIST)
        err = 0;
      else if (gpg_err_code (err) == GPG_ERR_ENOENT)
        {
          /* Try to create the directory with parents but keep the
             original error code in case of a failure.  */
          if (!try_mkdir_p (fname, strlen (dirname) + 1, 0, 0))
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
extract (estream_t stream, const char *dirname, tarinfo_t info,
         tar_header_t hdr, strlist_t exthdr)
{
  gpg_error_t err;
  size_t n;

  if (hdr->typeflag == TF_REGULAR || hdr->typeflag == TF_UNKNOWN)
    err = extract_regular (stream, dirname, info, hdr, exthdr);
  else if (hdr->typeflag == TF_DIRECTORY)
    err = extract_directory (dirname, info, hdr, exthdr);
  else
    {
      char record[RECORDSIZE];

      log_info ("unsupported file type %d for '%s' - skipped\n",
                (int)hdr->typeflag, hdr->name);
      if (hdr->typeflag == TF_SYMLINK)
        info->skipped_symlinks++;
      else if (hdr->typeflag == TF_HARDLINK)
        info->skipped_hardlinks++;
      else
        info->skipped_other++;
      for (err = 0, n=0; !err && n < hdr->nrecords; n++)
        {
          err = read_record (stream, record);
          if (!err)
            info->nblocks++;
        }
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
  estream_t stream = NULL;
  tar_header_t header = NULL;
  strlist_t extheader = NULL;
  const char *dirprefix = NULL;
  char *dirname = NULL;
  struct tarinfo_s tarinfo_buffer;
  tarinfo_t tarinfo = &tarinfo_buffer;
  gpgrt_process_t proc;
  char *logfilename = NULL;
  unsigned long long notextracted;

  memset (&tarinfo_buffer, 0, sizeof tarinfo_buffer);

  if (opt.directory)
    dirname = xtrystrdup (opt.directory);
  else
    {
      if (opt.filename)
        {
          dirprefix = strrchr (opt.filename, '/');
          if (dirprefix)
            dirprefix++;
          else
            dirprefix = opt.filename;
        }
      else if (filename)
        {
          dirprefix = strrchr (filename, '/');
          if (dirprefix)
            dirprefix++;
          else
            dirprefix = filename;
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

  if (decrypt)
    {
      strlist_t arg;
      ccparray_t ccp;
#ifdef HAVE_W32_SYSTEM
      HANDLE except[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
#else
      int except[2] = { -1, -1 };
#endif
      const char **argv;
      gpgrt_spawn_actions_t act = NULL;

      ccparray_init (&ccp, 0);
      if (opt.batch)
        ccparray_put (&ccp, "--batch");
      if (opt.require_compliance)
        ccparray_put (&ccp, "--require-compliance");
      if (opt.status_fd)
        {
          static char tmpbuf[40];
          es_syshd_t hd;

          snprintf (tmpbuf, sizeof tmpbuf, "--status-fd=%s", opt.status_fd);
          ccparray_put (&ccp, tmpbuf);
          es_syshd (opt.status_stream, &hd);
#ifdef HAVE_W32_SYSTEM
          except[0] = hd.u.handle;
#else
          except[0] = hd.u.fd;
#endif
        }
      if (opt.with_log)
        {
          ccparray_put (&ccp, "--log-file");
          logfilename = xstrconcat (dirname, ".log", NULL);
          ccparray_put (&ccp, logfilename);
        }
      ccparray_put (&ccp, "--output");
      ccparray_put (&ccp, "-");
      ccparray_put (&ccp, "--decrypt");
      for (arg = opt.gpg_arguments; arg; arg = arg->next)
        ccparray_put (&ccp, arg->d);
      if (filename)
        {
          ccparray_put (&ccp, "--");
          ccparray_put (&ccp, filename);
        }

      ccparray_put (&ccp, NULL);
      argv = ccparray_get (&ccp, NULL);
      if (!argv)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      err = gpgrt_spawn_actions_new (&act);
      if (err)
        {
          xfree (argv);
          goto leave;
        }

#ifdef HAVE_W32_SYSTEM
      gpgrt_spawn_actions_set_inherit_handles (act, except);
#else
      gpgrt_spawn_actions_set_inherit_fds (act, except);
#endif
      err = gpgrt_process_spawn (opt.gpg_program, argv,
                                 ((filename ? 0 : GPGRT_PROCESS_STDIN_KEEP)
                                  | GPGRT_PROCESS_STDOUT_PIPE), act, &proc);
      gpgrt_spawn_actions_release (act);
      xfree (argv);
      if (err)
        goto leave;
      gpgrt_process_get_streams (proc, 0, NULL, &stream, NULL);
      es_set_binary (stream);
    }
  else if (filename)
    {
      if (!strcmp (filename, "-"))
        stream = es_stdin;
      else
        stream = es_fopen (filename, "rb,sysopen");
      if (!stream)
        {
          err = gpg_error_from_syserror ();
          log_error ("error opening '%s': %s\n", filename, gpg_strerror (err));
          goto leave;
        }
      if (stream == es_stdin)
        es_set_binary (es_stdin);
    }
  else
    {
      stream = es_stdin;
      es_set_binary (es_stdin);
    }


  for (;;)
    {
      err = gpgtar_read_header (stream, tarinfo, &header, &extheader);
      if (err || header == NULL)
        goto leave;

      err = extract (stream, dirname, tarinfo, header, extheader);
      if (err)
        goto leave;
      free_strlist (extheader);
      extheader = NULL;
      xfree (header);
      header = NULL;
    }

  if (proc)
    {
      err = es_fclose (stream);
      stream = NULL;
      if (err)
        log_error ("error closing pipe: %s\n", gpg_strerror (err));

      err = gpgrt_process_wait (proc, 1);
      if (!err)
        {
          int exitcode;

          gpgrt_process_ctl (proc, GPGRT_PROCESS_GET_EXIT_ID, &exitcode);
          if (exitcode)
            log_error ("running %s failed (exitcode=%d): %s",
                       opt.gpg_program, exitcode, gpg_strerror (err));
        }
      gpgrt_process_release (proc);
      proc = NULL;
    }

 leave:
  notextracted  = tarinfo->skipped_badname;
  notextracted += tarinfo->skipped_suspicious;
  notextracted += tarinfo->skipped_symlinks;
  notextracted += tarinfo->skipped_hardlinks;
  notextracted += tarinfo->skipped_other;
  if (opt.status_stream)
    es_fprintf (opt.status_stream, "[GNUPG:] GPGTAR_EXTRACT"
                " %llu %llu %lu %lu %lu %lu %lu\n",
                tarinfo->nextracted,
                notextracted,
                tarinfo->skipped_badname,
                tarinfo->skipped_suspicious,
                tarinfo->skipped_symlinks,
                tarinfo->skipped_hardlinks,
                tarinfo->skipped_other);
  if (notextracted && !opt.quiet)
    {
      log_info ("Number of files not extracted: %llu\n", notextracted);
      if (tarinfo->skipped_badname)
        log_info ("     invalid name: %lu\n", tarinfo->skipped_badname);
      if (tarinfo->skipped_suspicious)
        log_info ("  suspicious name: %lu\n", tarinfo->skipped_suspicious);
      if (tarinfo->skipped_symlinks)
        log_info ("          symlink: %lu\n", tarinfo->skipped_symlinks);
      if (tarinfo->skipped_hardlinks)
        log_info ("         hardlink: %lu\n", tarinfo->skipped_hardlinks);
      if (tarinfo->skipped_other)
        log_info ("     other reason: %lu\n", tarinfo->skipped_other);
    }

  free_strlist (extheader);
  xfree (header);
  xfree (dirname);
  xfree (logfilename);
  if (stream != es_stdin)
    es_fclose (stream);
  return err;
}
