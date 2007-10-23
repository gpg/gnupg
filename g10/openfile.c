/* openfile.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005 Free Software Foundation, Inc.
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
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"
#include "options.h"
#include "main.h"
#include "status.h"
#include "i18n.h"

#ifdef USE_ONLY_8DOT3
#define SKELEXT ".skl"
#else
#define SKELEXT EXTSEP_S "skel"
#endif

#if defined (HAVE_DRIVE_LETTERS) || defined (__riscos__)
#define CMP_FILENAME(a,b) ascii_strcasecmp( (a), (b) )
#else
#define CMP_FILENAME(a,b) strcmp( (a), (b) )
#endif

#ifdef MKDIR_TAKES_ONE_ARG
#undef mkdir
#define mkdir(a,b) mkdir(a)
#endif

/* FIXME:  Implement opt.interactive. */

/****************
 * Check whether FNAME exists and ask if it's okay to overwrite an
 * existing one.
 * Returns: True: it's okay to overwrite or the file does not exist
 *	    False: Do not overwrite
 */
int
overwrite_filep( const char *fname )
{
    if( iobuf_is_pipe_filename (fname) )
	return 1; /* Writing to stdout is always okay */

    if( access( fname, F_OK ) )
	return 1; /* does not exist */

#ifndef HAVE_DOSISH_SYSTEM
    if ( !strcmp ( fname, "/dev/null" ) )
        return 1; /* does not do any harm */
#endif
#ifdef HAVE_W32_SYSTEM
    if ( !strcmp ( fname, "nul" ) )
        return 1;
#endif

    /* fixme: add some backup stuff in case of overwrite */
    if( opt.answer_yes )
	return 1;
    if( opt.answer_no || opt.batch )
	return 0;  /* do not overwrite */

    tty_printf(_("File `%s' exists. "), fname);
    if( cpr_enabled () )
        tty_printf ("\n");
    if( cpr_get_answer_is_yes("openfile.overwrite.okay",
			       _("Overwrite? (y/N) ")) )
	return 1;
    return 0;
}


/****************
 * Strip know extensions from iname and return a newly allocated
 * filename.  Return NULL if we can't do that.
 */
char *
make_outfile_name( const char *iname )
{
    size_t n;

    if ( iobuf_is_pipe_filename (iname) )
	return xstrdup("-");

    n = strlen(iname);
    if( n > 4 && (    !CMP_FILENAME(iname+n-4, EXTSEP_S "gpg")
		   || !CMP_FILENAME(iname+n-4, EXTSEP_S "pgp")
		   || !CMP_FILENAME(iname+n-4, EXTSEP_S "sig")
		   || !CMP_FILENAME(iname+n-4, EXTSEP_S "asc") ) ) {
	char *buf = xstrdup( iname );
	buf[n-4] = 0;
	return buf;
    }
    else if( n > 5 && !CMP_FILENAME(iname+n-5, EXTSEP_S "sign") ) {
	char *buf = xstrdup( iname );
	buf[n-5] = 0;
	return buf;
    }

    log_info(_("%s: unknown suffix\n"), iname );
    return NULL;
}


/****************
 * Ask for a outputfilename and use the given one as default.
 * Return NULL if no file has been given or it is not possible to
 * ask the user.
 */
char *
ask_outfile_name( const char *name, size_t namelen )
{
    size_t n;
    const char *s;
    char *prompt;
    char *fname;
    char *defname;

    if( opt.batch )
	return NULL;

    s = _("Enter new filename");

    defname = name && namelen? make_printable_string( name, namelen, 0): NULL;
    n = strlen(s) + (defname?strlen (defname):0) + 10;
    prompt = xmalloc(n);
    if( defname )
	sprintf(prompt, "%s [%s]: ", s, defname );
    else
	sprintf(prompt, "%s: ", s );
    tty_enable_completion(NULL);
    fname = cpr_get("openfile.askoutname", prompt );
    cpr_kill_prompt();
    tty_disable_completion();
    xfree(prompt);
    if( !*fname ) {
	xfree( fname ); fname = NULL;
	fname = defname; defname = NULL;
    }
    xfree(defname);
    if (fname)
        trim_spaces (fname);
    return fname;
}


/****************
 * Make an output filename for the inputfile INAME.
 * Returns an IOBUF and an errorcode
 * Mode 0 = use ".gpg"
 *	1 = use ".asc"
 *	2 = use ".sig"
 */
int
open_outfile( const char *iname, int mode, IOBUF *a )
{
  int rc = 0;

  *a = NULL;
  if( iobuf_is_pipe_filename (iname) && !opt.outfile ) {
    *a = iobuf_create(NULL);
    if( !*a ) {
      log_error(_("can't open `%s': %s\n"), "[stdout]", strerror(errno) );
      rc = G10ERR_CREATE_FILE;
    }
    else if( opt.verbose )
      log_info(_("writing to stdout\n"));
  }
  else {
    char *buf = NULL;
    const char *name;
    
    if ( opt.dry_run )
      {
#ifdef HAVE_W32_SYSTEM
        name = "nul";
#else
        name = "/dev/null";
#endif
      }
    else if( opt.outfile )
      name = opt.outfile;
    else {
#ifdef USE_ONLY_8DOT3
      if (opt.mangle_dos_filenames)
        {
          /* It is quite common for DOS system to have only one dot in a
           * a filename So if we have something like this, we simple
           * replace the suffix except in cases where the suffix is
           * larger than 3 characters and not identlically to the new one.
           * We should really map the filenames to 8.3 but this tends to
           * be more complicated and is probaly a duty of the filesystem
           */
          char *dot;
          const char *newsfx = mode==1 ? ".asc" :
                               mode==2 ? ".sig" : ".gpg";
          
          buf = xmalloc(strlen(iname)+4+1);
          strcpy(buf,iname);
          dot = strrchr(buf, '.' );
          if ( dot && dot > buf && dot[1] && strlen(dot) <= 4
               && CMP_FILENAME(newsfx, dot) 
               && !(strchr (dot, '/') || strchr (dot, '\\')))
            {
              /* There is a dot, the dot is not the first character,
                 the suffix is not longer than 3, the suffix is not
                 equal to the new suffix and tehre is no path delimter
                 after the dot (e.g. foo.1/bar): Replace the
                 suffix. */
              strcpy (dot, newsfx );
            }
          else if ( dot && !dot[1] ) /* Don't duplicate a trailing dot. */
            strcpy ( dot, newsfx+1 );
          else
            strcat ( buf, newsfx ); /* Just append the new suffix. */
        }
      if (!buf)
#endif /* USE_ONLY_8DOT3 */
        {
          buf = xmalloc(strlen(iname)+4+1);
          strcpy(stpcpy(buf,iname), mode==1 ? EXTSEP_S "asc" :
		                   mode==2 ? EXTSEP_S "sig" : EXTSEP_S "gpg");
        }
      name = buf;
    }

    rc = 0;
    while( !overwrite_filep (name) )
      {
        char *tmp = ask_outfile_name (NULL, 0);
        if ( !tmp || !*tmp )
          {
            xfree (tmp);
            rc = G10ERR_FILE_EXISTS;
            break;
          }
        xfree (buf);
        name = buf = tmp;
      }
    
    if( !rc )
      {
        if (is_secured_filename (name) )
          {
            *a = NULL;
            errno = EPERM;
          }
        else
          *a = iobuf_create( name );
        if( !*a )
          {
            log_error(_("can't create `%s': %s\n"), name, strerror(errno) );
            rc = G10ERR_CREATE_FILE;
          }
        else if( opt.verbose )
          log_info(_("writing to `%s'\n"), name );
      }
    xfree(buf);
  }

  if (*a)
    iobuf_ioctl (*a,3,1,NULL); /* disable fd caching */

  return rc;
}


/****************
 * Try to open a file without the extension ".sig" or ".asc"
 * Return NULL if such a file is not available.
 */
IOBUF
open_sigfile( const char *iname, progress_filter_context_t *pfx )
{
    IOBUF a = NULL;
    size_t len;

    if( !iobuf_is_pipe_filename (iname) ) {
	len = strlen(iname);
	if( len > 4 && ( !strcmp(iname + len - 4, EXTSEP_S "sig")
                        || ( len > 5 && !strcmp(iname + len - 5, EXTSEP_S "sign") )
                        || !strcmp(iname + len - 4, EXTSEP_S "asc")) ) {
	    char *buf;
	    buf = xstrdup(iname);
	    buf[len-(buf[len-1]=='n'?5:4)] = 0 ;
	    a = iobuf_open( buf );
            if (a && is_secured_file (iobuf_get_fd (a)))
              {
                iobuf_close (a);
                a = NULL;
                errno = EPERM;
              }
	    if( a && opt.verbose )
		log_info(_("assuming signed data in `%s'\n"), buf );
	    if (a && pfx)
	      handle_progress (pfx, a, buf);
            xfree(buf);
	}
    }
    return a;
}

/****************
 * Copy the option file skeleton to the given directory.
 */
static void
copy_options_file( const char *destdir )
{
    const char *datadir = GNUPG_DATADIR;
    char *fname;
    FILE *src, *dst;
    int linefeeds=0;
    int c;
    mode_t oldmask;
    int esc = 0;
    int any_option = 0;

    if( opt.dry_run )
	return;

    fname = xmalloc( strlen(datadir) + strlen(destdir) + 15 );
    strcpy(stpcpy(fname, datadir), DIRSEP_S "options" SKELEXT );
    src = fopen( fname, "r" );
    if (src && is_secured_file (fileno (src)))
      {
        fclose (src);
        src = NULL;
        errno = EPERM;
      }
    if( !src ) {
	log_info (_("can't open `%s': %s\n"), fname, strerror(errno) );
	xfree(fname);
	return;
    }
    strcpy(stpcpy(fname, destdir), DIRSEP_S "gpg" EXTSEP_S "conf" );
    oldmask=umask(077);
    if ( is_secured_filename (fname) )
      {
        dst = NULL;
        errno = EPERM;
      }
    else
      dst = fopen( fname, "w" );
    umask(oldmask);
    if( !dst ) {
	log_info (_("can't create `%s': %s\n"), fname, strerror(errno) );
	fclose( src );
	xfree(fname);
	return;
    }

    while( (c=getc(src)) != EOF ) {
	if( linefeeds < 3 ) {
	    if( c == '\n' )
		linefeeds++;
	}
	else {
	    putc( c, dst );
            if (c== '\n')
                esc = 1;
            else if (esc == 1) {
                if (c == ' ' || c == '\t')
                    ;
                else if (c == '#')
                    esc = 2;
                else 
                    any_option = 1;
            }
        }
    }
    fclose( dst );
    fclose( src );
    log_info(_("new configuration file `%s' created\n"), fname );
    if (any_option)
        log_info (_("WARNING: options in `%s'"
                    " are not yet active during this run\n"),
                  fname);
    xfree(fname);
}


void
try_make_homedir( const char *fname )
{
    const char *defhome = GNUPG_HOMEDIR;

    /* Create the directory only if the supplied directory name
     * is the same as the default one.  This way we avoid to create
     * arbitrary directories when a non-default homedirectory is used.
     * To cope with HOME, we do compare only the suffix if we see that
     * the default homedir does start with a tilde.
     */
    if( opt.dry_run || opt.no_homedir_creation )
	return;

    if ( ( *defhome == '~'
           && ( strlen(fname) >= strlen (defhome+1)
                && !strcmp(fname+strlen(fname)-strlen(defhome+1),
                           defhome+1 ) ))
         || ( *defhome != '~'
              && !compare_filenames( fname, defhome ) )
        ) {
	if( mkdir( fname, S_IRUSR|S_IWUSR|S_IXUSR ) )
	    log_fatal( _("can't create directory `%s': %s\n"),
					fname,	strerror(errno) );
	else if( !opt.quiet )
	    log_info( _("directory `%s' created\n"), fname );
	copy_options_file( fname );
/*  	log_info(_("you have to start GnuPG again, " */
/*  		   "so it can read the new configuration file\n") ); */
/*  	g10_exit(1); */
    }
}
