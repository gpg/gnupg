/* openfile.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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

    tty_printf(_("File '%s' exists. "), fname);
    if( cpr_get_answer_is_yes(N_("openfile.overwrite.okay"),
			       _("Overwrite (y/N)? ")) )
	return 1;
    return 0;
}


/****************
 * Make an output filename for the inputfile INAME.
 * Returns an IOBUF
 * Mode 0 = use ".gpg"
 *	1 = use ".asc"
 *	2 = use ".sig"
 */
IOBUF
open_outfile( const char *iname, int mode )
{
    IOBUF a = NULL;

    if( (!iname || (*iname=='-' && !iname[1])) && !opt.outfile ) {
	if( !(a = iobuf_create(NULL)) )
	    log_error("can't open [stdout]: %s\n", strerror(errno) );
	else if( opt.verbose )
	    log_info("writing to stdout\n");
    }
    else {
	char *buf=NULL;
	const char *name;

	if( opt.outfile )
	    name = opt.outfile;
	else {
	    buf = m_alloc(strlen(iname)+4+1);
	    strcpy(stpcpy(buf,iname), mode==1 ? ".asc" :
				      mode==2 ? ".sig" : ".gpg");
	    name = buf;
	}
	if( overwrite_filep( name ) ) {
	    if( !(a = iobuf_create( name )) )
		log_error("can't create %s: %s\n", name, strerror(errno) );
	    else if( opt.verbose )
		log_info("writing to '%s'\n", name );
	}
	m_free(buf);
    }
    return a;
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

    if( iname && !(*iname == '-' && !iname[1]) ) {
	len = strlen(iname);
	if( len > 4 && ( !strcmp(iname + len - 4, ".sig")
			|| !strcmp(iname + len - 4, ".asc")) ) {
	    char *buf;
	    buf = m_strdup(iname);
	    buf[len-4] = 0 ;
	    a = iobuf_open( buf );
	    if( opt.verbose )
		log_info("assuming signed data in '%s'\n", buf );
	    m_free(buf);
	}
    }
    return a;
}

