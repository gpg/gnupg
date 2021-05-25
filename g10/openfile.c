/* openfile.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2009,
 *               2010 Free Software Foundation, Inc.
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "gpg.h"
#include "../common/util.h"
#include "../common/ttyio.h"
#include "options.h"
#include "main.h"
#include "../common/status.h"
#include "../common/i18n.h"

#ifdef HAVE_W32_SYSTEM
#define NAME_OF_DEV_NULL "nul"
#else
#define NAME_OF_DEV_NULL "/dev/null"
#endif


#if defined (HAVE_DRIVE_LETTERS) || defined (__riscos__)
#define CMP_FILENAME(a,b) ascii_strcasecmp( (a), (b) )
#else
#define CMP_FILENAME(a,b) strcmp( (a), (b) )
#endif


/* FIXME:  Implement opt.interactive. */

/*
 * Check whether FNAME exists and ask if it's okay to overwrite an
 * existing one.
 * Returns: True: it's okay to overwrite or the file does not exist
 *	    False: Do not overwrite
 */
int
overwrite_filep( const char *fname )
{
  if ( iobuf_is_pipe_filename (fname) )
    return 1; /* Writing to stdout is always okay.  */

  if ( gnupg_access( fname, F_OK ) )
    return 1; /* Does not exist.  */

  if ( !compare_filenames (fname, NAME_OF_DEV_NULL) )
    return 1; /* Does not do any harm.  */

  if (opt.answer_yes)
    return 1;
  if (opt.answer_no || opt.batch)
    return 0;  /* Do not overwrite.  */

  tty_printf (_("File '%s' exists. "), fname);
  if (cpr_enabled ())
    tty_printf ("\n");
  if (cpr_get_answer_is_yes ("openfile.overwrite.okay",
                             _("Overwrite? (y/N) ")) )
    return 1;
  return 0;
}


/*
 * Strip known extensions from iname and return a newly allocated
 * filename.  Return NULL if we can't do that.
 */
char *
make_outfile_name (const char *iname)
{
  size_t n;

  if (iobuf_is_pipe_filename (iname))
    return xstrdup ("-");

  n = strlen (iname);
  if (n > 4 && (!CMP_FILENAME(iname+n-4, EXTSEP_S GPGEXT_GPG)
                || !CMP_FILENAME(iname+n-4, EXTSEP_S "pgp")
                || !CMP_FILENAME(iname+n-4, EXTSEP_S "sig")
                || !CMP_FILENAME(iname+n-4, EXTSEP_S "asc")))
    {
      char *buf = xstrdup (iname);
      buf[n-4] = 0;
      return buf;
    }
  else if (n > 5 && !CMP_FILENAME(iname+n-5, EXTSEP_S "sign"))
    {
      char *buf = xstrdup (iname);
      buf[n-5] = 0;
      return buf;
    }

  log_info (_("%s: unknown suffix\n"), iname);
  return NULL;
}


/* Ask for an output filename; use the given one as default.  Return
   NULL if no file has been given or if it is not possible to ask the
   user.  NAME is the template len which might contain enbedded Nuls.
   NAMELEN is its actual length.
 */
char *
ask_outfile_name( const char *name, size_t namelen )
{
  size_t n;
  const char *s;
  char *prompt;
  char *fname;
  char *defname;

  if ( opt.batch )
    return NULL;

  defname = name && namelen? make_printable_string (name, namelen, 0) : NULL;

  s = _("Enter new filename");
  n = strlen(s) + (defname?strlen (defname):0) + 10;
  prompt = xmalloc (n);
  if (defname)
    snprintf (prompt, n, "%s [%s]: ", s, defname );
  else
    snprintf (prompt, n, "%s: ", s );
  tty_enable_completion(NULL);
  fname = cpr_get ("openfile.askoutname", prompt );
  cpr_kill_prompt ();
  tty_disable_completion ();
  xfree (prompt);
  if ( !*fname )
    {
      xfree (fname);
      fname = defname;
      defname = NULL;
    }
  xfree (defname);
  if (fname)
    trim_spaces (fname);
  return fname;
}


/*
 * Make an output filename for the inputfile INAME.
 * Returns an IOBUF and an errorcode
 * Mode 0 = use ".gpg"
 *	1 = use ".asc"
 *	2 = use ".sig"
 *      3 = use ".rev"
 *
 * If INP_FD is not -1 the function simply creates an IOBUF for that
 * file descriptor and ignore INAME and MODE.  Note that INP_FD won't
 * be closed if the returned IOBUF is closed.  With RESTRICTEDPERM a
 * file will be created with mode 700 if possible.
 */
int
open_outfile (int inp_fd, const char *iname, int mode, int restrictedperm,
              iobuf_t *a)
{
  int rc = 0;

  *a = NULL;
  if (inp_fd != -1)
    {
      char xname[64];

      *a = iobuf_fdopen_nc (inp_fd, "wb");
      if (!*a)
        {
          rc = gpg_error_from_syserror ();
          snprintf (xname, sizeof xname, "[fd %d]", inp_fd);
          log_error (_("can't open '%s': %s\n"), xname, gpg_strerror (rc));
        }
      else if (opt.verbose)
        {
          snprintf (xname, sizeof xname, "[fd %d]", inp_fd);
          log_info (_("writing to '%s'\n"), xname);
        }
    }
  else if (iobuf_is_pipe_filename (iname) && !opt.outfile)
    {
      *a = iobuf_create (NULL, 0);
      if ( !*a )
        {
          rc = gpg_error_from_syserror ();
          log_error (_("can't open '%s': %s\n"), "[stdout]", strerror(errno) );
        }
      else if ( opt.verbose )
        log_info (_("writing to stdout\n"));
    }
  else
    {
      char *buf = NULL;
      const char *name;

      if (opt.dry_run)
        name = NAME_OF_DEV_NULL;
      else if (opt.outfile)
        name = opt.outfile;
      else
        {
#ifdef USE_ONLY_8DOT3
          if (opt.mangle_dos_filenames)
            {
              /* It is quite common for DOS systems to have only one
                 dot in a filename.  If we have something like this,
                 we simple replace the suffix except in cases where
                 the suffix is larger than 3 characters and not the
                 same as the new one.  We don't map the filenames to
                 8.3 because this is a duty of the file system.  */
              char *dot;
              const char *newsfx;

              newsfx = (mode==1 ? ".asc" :
                        mode==2 ? ".sig" :
                        mode==3 ? ".rev" : ".gpg");

              buf = xmalloc (strlen(iname)+4+1);
              strcpy (buf, iname);
              dot = strchr (buf, '.' );
              if ( dot && dot > buf && dot[1] && strlen(dot) <= 4
                   && CMP_FILENAME (newsfx, dot) )
                strcpy (dot, newsfx);
              else if (dot && !dot[1]) /* Do not duplicate a dot.  */
                strcpy (dot, newsfx+1);
              else
                strcat (buf, newsfx);
            }
          if (!buf)
#endif /* USE_ONLY_8DOT3 */
            {
              buf = xstrconcat (iname,
                                (mode==1 ? EXTSEP_S "asc" :
                                 mode==2 ? EXTSEP_S "sig" :
                                 mode==3 ? EXTSEP_S "rev" :
                                 /*     */ EXTSEP_S GPGEXT_GPG),
                                NULL);
            }
          name = buf;
        }

      rc = 0;
      while ( !overwrite_filep (name) )
        {
          char *tmp = ask_outfile_name (NULL, 0);
          if ( !tmp || !*tmp )
            {
              xfree (tmp);
              rc = gpg_error (GPG_ERR_EEXIST);
              break;
            }
          xfree (buf);
          name = buf = tmp;
        }

      if ( !rc )
        {
          if (is_secured_filename (name) )
            {
              *a = NULL;
              gpg_err_set_errno (EPERM);
            }
          else
            *a = iobuf_create (name, restrictedperm);
          if (!*a)
            {
              rc = gpg_error_from_syserror ();
              log_error(_("can't create '%s': %s\n"), name, strerror(errno) );
            }
          else if( opt.verbose )
            log_info (_("writing to '%s'\n"), name );
        }
      xfree(buf);
    }

  if (*a)
    iobuf_ioctl (*a, IOBUF_IOCTL_NO_CACHE, 1, NULL);

  return rc;
}


/* Find a matching data file for the signature file SIGFILENAME and
   return it as a malloced string.  If no matching data file is found,
   return NULL.  */
char *
get_matching_datafile (const char *sigfilename)
{
  char *fname = NULL;
  size_t len;

  if (iobuf_is_pipe_filename (sigfilename))
    return NULL;

  len = strlen (sigfilename);
  if (len > 4
      && (!strcmp (sigfilename + len - 4, EXTSEP_S "sig")
          || (len > 5 && !strcmp(sigfilename + len - 5, EXTSEP_S "sign"))
          || !strcmp(sigfilename + len - 4, EXTSEP_S "asc")))
    {

      fname = xstrdup (sigfilename);
      fname[len-(fname[len-1]=='n'?5:4)] = 0 ;
      if (gnupg_access (fname, R_OK ))
        {
          /* Not found or other error.  */
          xfree (fname);
          fname = NULL;
        }
    }

  return fname;
}


/*
 * Try to open a file without the extension ".sig" or ".asc"
 * Return NULL if such a file is not available.
 */
iobuf_t
open_sigfile (const char *sigfilename, progress_filter_context_t *pfx)
{
  iobuf_t a = NULL;
  char *buf;

  buf = get_matching_datafile (sigfilename);
  if (buf)
    {
      a = iobuf_open (buf);
      if (a && is_secured_file (iobuf_get_fd (a)))
        {
          iobuf_close (a);
          a = NULL;
          gpg_err_set_errno (EPERM);
        }
      if (a)
        log_info (_("assuming signed data in '%s'\n"), buf);
      if (a && pfx)
        handle_progress (pfx, a, buf);
      xfree (buf);
    }

  return a;
}


/* Create the directory only if the supplied directory name is the
   same as the default one.  This way we avoid to create arbitrary
   directories when a non-default home directory is used.  To cope
   with HOME, we do compare only the suffix if we see that the default
   homedir does start with a tilde.  */
void
try_make_homedir (const char *fname)
{
  if ( opt.dry_run || opt.no_homedir_creation )
    return;

  gnupg_maybe_make_homedir (fname, opt.quiet);
}


/* Get and if needed create a string with the directory used to store
   openpgp revocations.  */
char *
get_openpgp_revocdir (const char *home)
{
  char *fname;
  struct stat statbuf;

  fname = make_filename (home, GNUPG_OPENPGP_REVOC_DIR, NULL);
  if (gnupg_stat (fname, &statbuf) && errno == ENOENT)
    {
      if (gnupg_mkdir (fname, "-rwx"))
        log_error (_("can't create directory '%s': %s\n"),
                   fname, strerror (errno) );
      else if (!opt.quiet)
        log_info (_("directory '%s' created\n"), fname);
    }
  return fname;
}
