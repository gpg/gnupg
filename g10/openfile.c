/* openfile.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
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
  #define SKELEXT ".skel"
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
    if( !fname || (*fname == '-' && !fname[1]) )
	return 1; /* writing to stdout is always okay */

    if( access( fname, F_OK ) )
	return 1; /* does not exist */

    /* fixme: add some backup stuff in case of overwrite */
    if( opt.answer_yes )
	return 1;
    if( opt.answer_no || opt.batch )
	return 0;  /* do not overwrite */

    tty_printf(_("File `%s' exists. "), fname);
    if( cpr_get_answer_is_yes("openfile.overwrite.okay",
			       _("Overwrite (y/N)? ")) )
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

    if( (!iname || (*iname=='-' && !iname[1]) ))
	return m_strdup("-");

  #ifdef HAVE_DRIVE_LETTERS
    #warning add case insensitive compare
  #endif
    n = strlen(iname);
    if( n > 4 && (    !strcmp(iname+n-4,".gpg")
		   || !strcmp(iname+n-4,".sig")
		   || !strcmp(iname+n-4,".asc") ) ) {
	char *buf = m_strdup( iname );
	buf[n-4] = 0;
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

    n = strlen(s) + namelen + 10;
    defname = name && namelen? make_printable_string( name, namelen, 0): NULL;
    prompt = m_alloc(n);
    if( defname )
	sprintf(prompt, "%s [%s]: ", s, defname );
    else
	sprintf(prompt, "%s: ", s );
    fname = cpr_get("openfile.askoutname", prompt );
    cpr_kill_prompt();
    m_free(prompt);
    if( !*fname ) {
	m_free( fname ); fname = NULL;
	fname = defname; defname = NULL;
    }
    m_free(defname);
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
    if( (!iname || (*iname=='-' && !iname[1])) && !opt.outfile ) {
	if( !(*a = iobuf_create(NULL)) ) {
	    log_error(_("%s: can't open: %s\n"), "[stdout]", strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	}
	else if( opt.verbose )
	    log_info(_("writing to stdout\n"));
    }
    else {
	char *buf=NULL;
	const char *name;

	if( opt.dry_run )
	    name = "/dev/null";
	else if( opt.outfile )
	    name = opt.outfile;
	else {
	  #ifdef USE_ONLY_8DOT3
	    #warning please implement 8.3 files
	  #endif
	    buf = m_alloc(strlen(iname)+4+1);
	    strcpy(stpcpy(buf,iname), mode==1 ? ".asc" :
				      mode==2 ? ".sig" : ".gpg");
	    name = buf;
	}

	if( overwrite_filep( name ) ) {
	    if( !(*a = iobuf_create( name )) ) {
		log_error(_("%s: can't create: %s\n"), name, strerror(errno) );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( opt.verbose )
		log_info(_("writing to `%s'\n"), name );
	}
	else
	    rc = G10ERR_FILE_EXISTS;
	m_free(buf);
    }
    return rc;
}



/****************
 * Try to open a file without the extension ".sig" or ".asc"
 * Return NULL if such a file is not available.
 */
IOBUF
open_sigfile( const char *iname )
{
    IOBUF a = NULL;
    size_t len;

  #ifdef USE_ONLY_8DOT3
    #warning please implement 8.3 files
  #endif
    if( iname && !(*iname == '-' && !iname[1]) ) {
	len = strlen(iname);
	if( len > 4 && ( !strcmp(iname + len - 4, ".sig")
			|| !strcmp(iname + len - 4, ".asc")) ) {
	    char *buf;
	    buf = m_strdup(iname);
	    buf[len-4] = 0 ;
	    a = iobuf_open( buf );
	    if( opt.verbose )
		log_info(_("assuming signed data in `%s'\n"), buf );
	    m_free(buf);
	}
    }
    return a;
}


/****************
 * Copy the option file skeleton to the given directory.
 */
void
copy_options_file( const char *destdir )
{
    const char *datadir = GNUPG_DATADIR;
    char *fname;
    FILE *src, *dst;
    int linefeeds=0;
    int c;

    if( opt.dry_run )
	return;

    fname = m_alloc( strlen(datadir) + strlen(destdir) + 15 );
    strcpy(stpcpy(fname, datadir), "/options" SKELEXT );
    src = fopen( fname, "r" );
    if( !src ) {
	log_error(_("%s: can't open: %s\n"), fname, strerror(errno) );
	m_free(fname);
	return;
    }
    strcpy(stpcpy(fname, destdir), "/options" );
    dst = fopen( fname, "w" );
    if( !dst ) {
	log_error(_("%s: can't create: %s\n"), fname, strerror(errno) );
	fclose( src );
	m_free(fname);
	return;
    }

    while( (c=getc(src)) != EOF ) {
	if( linefeeds < 3 ) {
	    if( c == '\n' )
		linefeeds++;
	}
	else
	    putc( c, dst );
    }
    fclose( dst );
    fclose( src );
    log_info(_("%s: new options file created\n"), fname );
    m_free(fname);
}

