/* plaintext.c -  process plaintext packets
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <errno.h>
#include <assert.h>
#ifdef HAVE_DOSISH_SYSTEM
  #include <fcntl.h> /* for setmode() */
#endif

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
    else if( !opt.use_embedded_filename ) {
	fname = make_outfile_name( iobuf_get_real_fname(pt->buf) );
	if( !fname )
	    fname = ask_outfile_name( pt->name, pt->namelen );
	if( !fname ) {
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	}
    }
    else {
	fname = make_printable_string( pt->name, pt->namelen, 0 );
    }

    if( nooutput )
	;
    else if( !*fname || (*fname=='-' && !fname[1])) {
	/* no filename or "-" given; write to stdout */
	fp = stdout;
      #ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
      #endif
    }
    else {
	while( !overwrite_filep (fname) ) {
            char *tmp = ask_outfile_name (NULL, 0);
            if ( !tmp || !*tmp ) {
                m_free (tmp);
                rc = G10ERR_CREATE_FILE;
                goto leave;
            }
            m_free (fname);
            fname = tmp;
        }
    }

    if( fp || nooutput )
	;
    else if( !(fp = fopen(fname,"wb")) ) {
	log_error("Error creating `%s': %s\n", fname, strerror(errno) );
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }

    if( pt->len ) {
	assert( !clearsig );
	if( convert ) { /* text mode */
	    for( ; pt->len; pt->len-- ) {
		if( (c = iobuf_get(pt->buf)) == -1 ) {
		    log_error("Problem reading source (%u bytes remaining)\n",
			      (unsigned)pt->len);
		    rc = G10ERR_READ_FILE;
		    goto leave;
		}
		if( mfx->md )
		    md_putc(mfx->md, c );
	      #ifndef HAVE_DOSISH_SYSTEM
		if( c == '\r' )  /* convert to native line ending */
		    continue;	 /* fixme: this hack might be too simple */
	      #endif
		if( fp ) {
		    if( putc( c, fp ) == EOF ) {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			goto leave;
		    }
		}
	    }
	}
	else { /* binary mode */
	    byte *buffer = m_alloc( 32768 );
	    while( pt->len ) {
		int len = pt->len > 32768 ? 32768 : pt->len;
		len = iobuf_read( pt->buf, buffer, len );
		if( len == -1 ) {
		    log_error("Problem reading source (%u bytes remaining)\n",
			      (unsigned)pt->len);
		    rc = G10ERR_READ_FILE;
		    m_free( buffer );
		    goto leave;
		}
		if( mfx->md )
		    md_write( mfx->md, buffer, len );
		if( fp ) {
		    if( fwrite( buffer, 1, len, fp ) != len ) {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			m_free( buffer );
			goto leave;
		    }
		}
		pt->len -= len;
	    }
	    m_free( buffer );
	}
    }
    else if( !clearsig ) {
	if( convert ) { /* text mode */
	    while( (c = iobuf_get(pt->buf)) != -1 ) {
		if( mfx->md )
		    md_putc(mfx->md, c );
	      #ifndef HAVE_DOSISH_SYSTEM
		if( convert && c == '\r' )
		    continue; /* fixme: this hack might be too simple */
	      #endif
		if( fp ) {
		    if( putc( c, fp ) == EOF ) {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			goto leave;
		    }
		}
	    }
	}
	else { /* binary mode */
	    byte *buffer = m_alloc( 32768 );
	    int eof;
	    for( eof=0; !eof; ) {
		/* Why do we check for len < 32768:
		 * If we won't, we would practically read 2 EOFs but
		 * the first one has already popped the block_filter
		 * off and therefore we don't catch the boundary.
		 * So, always assume EOF if iobuf_read returns less bytes
		 * then requested */
		int len = iobuf_read( pt->buf, buffer, 32768 );
		if( len == -1 )
		    break;
		if( len < 32768 )
		    eof = 1;
		if( mfx->md )
		    md_write( mfx->md, buffer, len );
		if( fp ) {
		    if( fwrite( buffer, 1, len, fp ) != len ) {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			m_free( buffer );
			goto leave;
		    }
		}
	    }
	    m_free( buffer );
	}
	pt->buf = NULL;
    }
    else {  /* clear text signature - don't hash the last cr,lf  */
	int state = 0;

	while( (c = iobuf_get(pt->buf)) != -1 ) {
	    if( fp ) {
		if( putc( c, fp ) == EOF ) {
		    log_error("Error writing to `%s': %s\n",
						fname, strerror(errno) );
		    rc = G10ERR_WRITE_FILE;
		    goto leave;
		}
	    }
	    if( !mfx->md )
		continue;
	    if( state == 2 ) {
		md_putc(mfx->md, '\r' );
		md_putc(mfx->md, '\n' );
		state = 0;
	    }
	    if( !state ) {
		if( c == '\r'  )
		    state = 1;
		else if( c == '\n'  )
		    state = 2;
		else
		    md_putc(mfx->md, c );
	    }
	    else if( state == 1 ) {
		if( c == '\n'  )
		    state = 2;
		else {
		    md_putc(mfx->md, '\r' );
		    if( c == '\r'  )
			state = 1;
		    else {
			state = 0;
			md_putc(mfx->md, c );
		    }
		}
	    }
	}
	pt->buf = NULL;
    }

    if( fp && fp != stdout && fclose(fp) ) {
	log_error("Error closing `%s': %s\n", fname, strerror(errno) );
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

static void
do_hash( MD_HANDLE md, MD_HANDLE md2, IOBUF fp, int textmode )
{
    text_filter_context_t tfx;
    int c;

    if( textmode ) {
	memset( &tfx, 0, sizeof tfx);
	iobuf_push_filter( fp, text_filter, &tfx );
    }
    if( md2 ) { /* work around a strange behaviour in pgp2 */
	/* It seems that at least PGP5 converts a single CR to a CR,LF too */
	int lc = -1;
	while( (c = iobuf_get(fp)) != -1 ) {
	    if( c == '\n' && lc == '\r' )
		md_putc(md2, c);
	    else if( c == '\n' ) {
		md_putc(md2, '\r');
		md_putc(md2, c);
	    }
	    else if( c != '\n' && lc == '\r' ) {
		md_putc(md2, '\n');
		md_putc(md2, c);
	    }
	    else
		md_putc(md2, c);

	    if( md )
		md_putc(md, c );
	    lc = c;
	}
    }
    else {
	while( (c = iobuf_get(fp)) != -1 ) {
	    if( md )
		md_putc(md, c );
	}
    }
}


/****************
 * Ask for the detached datafile and calculate the digest from it.
 * INFILE is the name of the input file.
 */
int
ask_for_detached_datafile( MD_HANDLE md, MD_HANDLE md2,
			   const char *inname, int textmode )
{
    char *answer = NULL;
    IOBUF fp;
    int rc = 0;

    fp = open_sigfile( inname ); /* open default file */
    if( !fp && !opt.batch ) {
	int any=0;
	tty_printf(_("Detached signature.\n"));
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
		log_error("can't open `%s': %s\n", answer, strerror(errno) );
		rc = G10ERR_READ_FILE;
		goto leave;
	    }
	} while( !fp );
    }

    if( !fp ) {
	if( opt.verbose )
	    log_info(_("reading stdin ...\n"));
	fp = iobuf_open( NULL );
	assert(fp);
    }
    do_hash( md, md2, fp, textmode );
    iobuf_close(fp);


  leave:
    m_free(answer);
    return rc;
}



/****************
 * Hash the given files and append the hash to hash context md.
 * If FILES is NULL, hash stdin.
 */
int
hash_datafiles( MD_HANDLE md, MD_HANDLE md2, STRLIST files,
		const char *sigfilename, int textmode )
{
    IOBUF fp;
    STRLIST sl;

    if( !files ) {
	/* check whether we can open the signed material */
	fp = open_sigfile( sigfilename );
	if( fp ) {
	    do_hash( md, md2, fp, textmode );
	    iobuf_close(fp);
	    return 0;
	}
        log_error (_("no signed data\n"));
        return G10ERR_OPEN_FILE;
    }


    for (sl=files; sl; sl = sl->next ) {
	fp = iobuf_open( sl->d );
	if( !fp ) {
	    log_error(_("can't open signed data `%s'\n"),
						print_fname_stdin(sl->d));
	    return G10ERR_OPEN_FILE;
	}
	do_hash( md, md2, fp, textmode );
	iobuf_close(fp);
    }

    return 0;
}





