/* plaintext.c -  process an plaintext packet
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
#include <errno.h>
#include "util.h"
#include "memory.h"
#include "options.h"
#include "packet.h"
#include "ttyio.h"
#include "filter.h"
#include "main.h"
#include "status.h"
#include "i18n.h"


/****************
 * Defer the last CR,LF
 */
static void
special_md_putc( MD_HANDLE md, int c, int *state )
{
    if( c == -1 ) { /* flush */
	if( *state == 1 ) {
	    md_putc(md, '\r');
	}
	*state = 0;
	return;
    }
  again:
    switch( *state ) {
      case 0:
	if( c == '\r' )
	    *state = 1;
	else
	    md_putc(md, c );
	break;
      case 1:
	if( c == '\n' )
	    *state = 2;
	else {
	    md_putc(md, '\r');
	    *state = 0;
	    goto again;
	}
	break;
      case 2:
	md_putc(md, '\r');
	md_putc(md, '\n');
	*state = 0;
	goto again;
      default: BUG();
    }
}


/****************
 * Handle a plaintext packet.  If MFX is not NULL, update the MDs
 * Note: we should use the filter stuff here, but we have to add some
 *	 easy mimic to set a read limit, so we calculate only the
 *	 bytes from the plaintext.
 */
int
handle_plaintext( PKT_plaintext *pt, md_filter_context_t *mfx,
		  int nooutput, int clearsig )
{
    char *fname = NULL;
    FILE *fp = NULL;
    int rc = 0;
    int c;
    int convert = pt->mode == 't';
    int special_state = 0;

    /* create the filename as C string */
    if( nooutput )
	;
    else if( opt.outfile ) {
	fname = m_alloc( strlen( opt.outfile ) + 1);
	strcpy(fname, opt.outfile );
    }
    else if( pt->namelen == 8 && !memcmp( pt->name, "_CONSOLE", 8 ) ) {
	log_info(_("data not saved; use option \"--output\" to save it\n"));
	nooutput = 1;
    }
    else {
	fname = m_alloc( pt->namelen +1 );
	memcpy( fname, pt->name, pt->namelen );
	fname[pt->namelen] = 0;
    }

    if( nooutput )
	;
    else if( !*fname || (*fname=='-' && !fname[1])) {
	/* no filename or "-" given; write to stdout */
	fp = stdout;
    }
    else if( !overwrite_filep( fname ) ) {
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }

    if( fp || nooutput )
	;
    else if( !(fp = fopen(fname,"wb")) ) {
	log_error("Error creating '%s': %s\n", fname, strerror(errno) );
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }

    if( pt->len ) {
	for( ; pt->len; pt->len-- ) {
	    if( (c = iobuf_get(pt->buf)) == -1 ) {
		log_error("Problem reading source (%u bytes remaining)\n",
							 (unsigned)pt->len);
		rc = G10ERR_READ_FILE;
		goto leave;
	    }
	    if( mfx->md ) {
		if( convert && clearsig )
		    special_md_putc(mfx->md, c, &special_state );
		else
		    md_putc(mfx->md, c );
	    }
	    if( convert && !clearsig && c == '\r' )
		continue; /* fixme: this hack might be too simple */
	    if( fp ) {
		if( putc( c, fp ) == EOF ) {
		    log_error("Error writing to '%s': %s\n",
					    fname, strerror(errno) );
		    rc = G10ERR_WRITE_FILE;
		    goto leave;
		}
	    }
	}
    }
    else {
	while( (c = iobuf_get(pt->buf)) != -1 ) {
	    if( mfx->md ) {
		if( convert && clearsig )
		    special_md_putc(mfx->md, c, &special_state	);
		else
		    md_putc(mfx->md, c );
	    }
	    if( convert && !clearsig && c == '\r' )
		continue; /* fixme: this hack might be too simple */
	    if( fp ) {
		if( putc( c, fp ) == EOF ) {
		    log_error("Error writing to '%s': %s\n",
						fname, strerror(errno) );
		    rc = G10ERR_WRITE_FILE;
		    goto leave;
		}
	    }
	}
	iobuf_clear_eof(pt->buf);
    }
    if( mfx->md && convert && clearsig )
	special_md_putc(mfx->md, -1, &special_state  ); /* flush */

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
 * INFILE is the name of the input file.
 */
int
ask_for_detached_datafile( md_filter_context_t *mfx, const char *inname )
{
    char *answer = NULL;
    IOBUF fp;
    int rc = 0;
    int c;

    fp = open_sigfile( inname ); /* open default file */
    if( !fp && !opt.batch ) {
	int any=0;
	tty_printf("Detached signature.\n");
	do {
	    m_free(answer);
	    answer = cpr_get("detached_signature.filename",
			   _("Please enter name of data file: "));
	    cpr_kill_prompt();
	    if( any && !*answer ) {
		rc = G10ERR_READ_FILE;
		goto leave;
	    }
	    fp = iobuf_open(answer);
	    if( !fp && errno == ENOENT ) {
		tty_printf("No such file, try again or hit enter to quit.\n");
		any++;
	    }
	    else if( !fp ) {
		log_error("can't open '%s': %s\n", answer, strerror(errno) );
		rc = G10ERR_READ_FILE;
		goto leave;
	    }
	} while( !fp );
    }

    if( !fp ) {
	if( opt.verbose )
	    log_info(_("reading stdin ...\n"));
	while( (c = getchar()) != EOF ) {
	    if( mfx->md )
		md_putc(mfx->md, c );
	}
    }
    else {
	while( (c = iobuf_get(fp)) != -1 ) {
	    if( mfx->md )
		md_putc(mfx->md, c );
	}
	iobuf_close(fp);
    }

  leave:
    m_free(answer);
    return rc;
}


static void
do_hash( MD_HANDLE md, IOBUF fp, int textmode )
{
    text_filter_context_t tfx;
    int c;

    if( textmode ) {
	memset( &tfx, 0, sizeof tfx);
	iobuf_push_filter( fp, text_filter, &tfx );
    }
    while( (c = iobuf_get(fp)) != -1 )
	md_putc(md, c );
}


/****************
 * Hash the given files and append the hash to hash context md.
 * If FILES is NULL, hash stdin.
 */
int
hash_datafiles( MD_HANDLE md, STRLIST files,
		const char *sigfilename, int textmode )
{
    IOBUF fp;
    STRLIST sl=NULL;

    if( !files ) {
	/* check whether we can opne the signed material */
	fp = open_sigfile( sigfilename );
	if( fp ) {
	    do_hash( md, fp, textmode );
	    iobuf_close(fp);
	    return 0;
	}
	/* no we can't (no sigfile) - read signed stuff from stdin */
	add_to_strlist( &sl, "-");
    }
    else
	sl = files;

    for( ; sl; sl = sl->next ) {
	fp = iobuf_open( sl->d );
	if( !fp ) {
	    log_error(_("can't open signed data '%s'\n"),
						print_fname_stdin(sl->d));
	    if( !files )
		free_strlist(sl);
	    return G10ERR_OPEN_FILE;
	}
	do_hash( md, fp, textmode );
	iobuf_close(fp);
    }

    if( !files )
	free_strlist(sl);
    return 0;
}


