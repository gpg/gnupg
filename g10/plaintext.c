/* plaintext.c -  process an plaintext packet
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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
#include <errno.h>
#include "util.h"
#include "memory.h"
#include "options.h"
#include "packet.h"
#include "ttyio.h"
#include "filter.h"


/****************
 * Handle a plaintext packet.  If MFX is not NULL, update the MDs
 * Note: we should use the filter stuff here, but we have to add some
 *	 easy mimic to set a read limit, so we calculate only the
 *	 bytes from the plaintext.
 */
int
handle_plaintext( PKT_plaintext *pt, md_filter_context_t *mfx )
{
    char *fname;
    FILE *fp = NULL;
    int rc = 0;
    int c;

    /* create the filename as C string */
    if( opt.outfile ) {
	fname = m_alloc( strlen( opt.outfile ) + 1);
	strcpy(fname, opt.outfile );
    }
    else {
	fname = m_alloc( pt->namelen +1 );
	memcpy( fname, pt->name, pt->namelen );
	fname[pt->namelen] = 0;
    }

    if( !*fname ) { /* no filename given; write to stdout */
	fp = stdout;
    }
    else if( overwrite_filep( fname ) )
	goto leave;

    if( fp )
	;
    else if( !(fp = fopen(fname,"wb")) ) {
	log_error("Error creating '%s': %s\n", fname, strerror(errno) );
	rc = G10ERR_WRITE_FILE;
	goto leave;
    }

    if( pt->len ) {
	for( ; pt->len; pt->len-- ) {
	    if( (c = iobuf_get(pt->buf)) == -1 ) {
		log_error("Problem reading source\n");
		rc = G10ERR_READ_FILE;
		goto leave;
	    }
	    if( mfx->md )
		md_putchar(mfx->md, c );
	    if( mfx->rmd160 )
		rmd160_putchar(mfx->rmd160, c );
	    if( mfx->md5 )
		md5_putchar(mfx->md5, c );
	    if( putc( c, fp ) == EOF ) {
		log_error("Error writing to '%s': %s\n", fname, strerror(errno) );
		rc = G10ERR_WRITE_FILE;
		goto leave;
	    }
	}
    }
    else {
	while( (c = iobuf_get(pt->buf)) != -1 ) {
	    if( mfx->rmd160 )
		rmd160_putchar(mfx->rmd160, c );
	    if( mfx->md5 )
		md5_putchar(mfx->md5, c );
	    if( putc( c, fp ) == EOF ) {
		log_error("Error writing to '%s': %s\n",
					    fname, strerror(errno) );
		rc = G10ERR_WRITE_FILE;
		goto leave;
	    }
	}
	iobuf_clear_eof(pt->buf);
    }

    if( fp && fp != stdout && fclose(fp) ) {
	log_error("Error closing '%s': %s\n", fname, strerror(errno) );
	fp = NULL;
	rc = G10ERR_WRITE_FILE;
	goto leave;
    }
    fp = NULL;

  leave:
    if( fp && fp != stdout )
	fclose(fp);
    m_free(fname);
    return rc;
}


/****************
 * Ask for the detached datafile and calculate the digest from it.
 */
int
ask_for_detached_datafile( md_filter_context_t *mfx )
{
    char *answer;
    FILE *fp;
    int rc = 0;
    int c;

    tty_printf("Detached signature.\n");
    answer = tty_get("Please enter name of data file: ");
    tty_kill_prompt();

    fp = fopen(answer,"rb");
    if( !fp ) {
	log_error("can't open '%s': %s\n", answer, strerror(errno) );
	rc = G10ERR_READ_FILE;
	goto leave;
    }

    while( (c = getc(fp)) != EOF ) {
	if( mfx->md )
	    md_putchar(mfx->md, c );
	if( mfx->rmd160 )
	    rmd160_putchar(mfx->rmd160, c );
	if( mfx->md5 )
	    md5_putchar(mfx->md5, c );
    }
    fclose(fp);

  leave:
    m_free(answer);
    return rc;
}


