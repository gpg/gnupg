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


/****************
 * Check wether FNAME exists and ask if it's okay to overwrite an
 * existing one.
 * Returns: -1 : Do not overwrite
 *	    0 : it's okay to overwrite or the file does not exist
 *	    >0 : other error
 */
int
overwrite_filep( const char *fname )
{
    if( !access( fname, F_OK ) ) {
	char *p;
	int okay;
	int first = 1;

	if( opt.answer_yes )
	    okay = 1;
	else if( opt.answer_no || opt.batch )
	    okay = 2;
	else
	    okay = 0;

	while( !okay ) {
	if( !okay )
	    if( first ) {
		tty_printf("File '%s' exists. ", fname);
		first = 0;
	    }
	    p = tty_get("Overwrite (y/N)? ");
	    tty_kill_prompt();
	    if( (*p == 'y' || *p == 'Y') && !p[1] )
		okay = 1;
	    else if( !*p || ((*p == 'n' || *p == 'N') && !p[1]) )
		okay = 2;
	    else
		okay = 0;
	    m_free(p);
	}
	if( okay == 2 )
	    return -1;
	/* fixme: add some backup stuff */
    }
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
    int rc;

    if( !iname && !opt.outfile ) {
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
	if( !(rc=overwrite_filep( name )) ) {
	    if( !(a = iobuf_create( name )) )
		log_error("can't create %s: %s\n", name, strerror(errno) );
	    else if( opt.verbose )
		log_info("writing to '%s'\n", name );
	}
	else if( rc != -1 )
	    log_error("oops: overwrite_filep(%s): %s\n", name, g10_errstr(rc) );
	m_free(buf);
    }
    return a;
}


/****************
 * Try to open a file without the extension ".sig"
 * Return NULL if such a file is not available.
 */
IOBUF
open_sigfile( const char *iname )
{
    IOBUF a = NULL;
    size_t len;

    if( iname ) {
	len = strlen(iname);
	if( len > 4 && !strcmp(iname + len - 4, ".sig") ) {
	    char *buf;
	    buf = m_strdup(iname);
	    buf[len-4] = 0 ;
	    a = iobuf_open( buf );
	    m_free(buf);
	}
    }
    return a;
}

