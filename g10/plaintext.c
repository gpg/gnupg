/* plaintext.c -  process plaintext packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006 Free Software Foundation, Inc.
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
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
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
    static off_t count=0;
    int rc = 0;
    int c;
    int convert = (pt->mode == 't' || pt->mode == 'u');
#ifdef __riscos__
    int filetype = 0xfff;
#endif

    /* Let people know what the plaintext info is. This allows the
       receiving program to try and do something different based on
       the format code (say, recode UTF-8 to local). */
    if(!nooutput && is_status_enabled())
      {
	char status[50];

        /* Better make sure that stdout has been flushed in case the
           output will be written to it.  This is to make sure that no
           not-yet-flushed stuff will be written after the plaintext
           status message.  */
        fflush (stdout);

	sprintf(status,"%X %lu ",(byte)pt->mode,(ulong)pt->timestamp);
	write_status_text_and_buffer(STATUS_PLAINTEXT,
				     status,pt->name,pt->namelen,0);

	if(!pt->is_partial)
	  {
	    sprintf(status,"%lu",(ulong)pt->len);
	    write_status_text(STATUS_PLAINTEXT_LENGTH,status);
	  }
      }

    /* create the filename as C string */
    if( nooutput )
	;
    else if( opt.outfile ) {
	fname = xmalloc( strlen( opt.outfile ) + 1);
	strcpy(fname, opt.outfile );
    }
    else if( pt->namelen == 8 && !memcmp( pt->name, "_CONSOLE", 8 ) ) {
	log_info(_("data not saved; use option \"--output\" to save it\n"));
	nooutput = 1;
    }
    else if( !opt.flags.use_embedded_filename ) {
	fname = make_outfile_name( iobuf_get_real_fname(pt->buf) );
	if( !fname )
	    fname = ask_outfile_name( pt->name, pt->namelen );
	if( !fname ) {
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	}
    }
    else
      fname=utf8_to_native(pt->name,pt->namelen,0);

    if( nooutput )
	;
    else if ( iobuf_is_pipe_filename (fname) || !*fname)
      {
	/* No filename or "-" given; write to stdout. */
	fp = stdout;
#ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
#endif
      }
    else {
	while( !overwrite_filep (fname) ) {
            char *tmp = ask_outfile_name (NULL, 0);
            if ( !tmp || !*tmp ) {
                xfree (tmp);
                rc = G10ERR_CREATE_FILE;
                goto leave;
            }
            xfree (fname);
            fname = tmp;
        }
    }

#ifndef __riscos__
    if( fp || nooutput )
	;
    else if (is_secured_filename (fname))
      {
        errno = EPERM;
	log_error(_("error creating `%s': %s\n"), fname, strerror(errno) );
	rc = G10ERR_CREATE_FILE;
	goto leave;
      }
    else if( !(fp = fopen(fname,"wb")) ) {
	log_error(_("error creating `%s': %s\n"), fname, strerror(errno) );
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }
#else /* __riscos__ */
    /* If no output filename was given, i.e. we constructed it,
       convert all '.' in fname to '/' but not vice versa as
       we don't create directories! */
    if( !opt.outfile )
        for( c=0; fname[c]; ++c )
            if( fname[c] == '.' )
                fname[c] = '/';

    if( fp || nooutput )
	;
    else {
        fp = fopen(fname,"wb");
        if( !fp ) {
            log_error(_("error creating `%s': %s\n"), fname, strerror(errno) );
            rc = G10ERR_CREATE_FILE;
            if (errno == 106)
                log_info("Do output file and input file have the same name?\n");
            goto leave;
	}

        /* If there's a ,xxx extension in the embedded filename,
           use that, else check whether the user input (in fname)
           has a ,xxx appended, then use that in preference */
        if( (c = riscos_get_filetype_from_string( pt->name,
                                                  pt->namelen )) != -1 )
            filetype = c;
        if( (c = riscos_get_filetype_from_string( fname,
                                                  strlen(fname) )) != -1 )
            filetype = c;
        riscos_set_filetype_by_number(fname, filetype);
    }
#endif /* __riscos__ */

    if( !pt->is_partial ) {
        /* We have an actual length (which might be zero). */

        if (clearsig) {
            log_error ("clearsig encountered while not expected\n");
            rc = G10ERR_UNEXPECTED;
            goto leave;
        }

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
		if( fp )
		  {
		    if(opt.max_output && (++count)>opt.max_output)
		      {
			log_error("Error writing to `%s': %s\n",
				  fname,"exceeded --max-output limit\n");
			rc = G10ERR_WRITE_FILE;
			goto leave;
		      }
		    else if( putc( c, fp ) == EOF )
		      {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			goto leave;
		      }
		  }
	    }
	}
	else { /* binary mode */
	    byte *buffer = xmalloc( 32768 );
	    while( pt->len ) {
		int len = pt->len > 32768 ? 32768 : pt->len;
		len = iobuf_read( pt->buf, buffer, len );
		if( len == -1 ) {
		    log_error("Problem reading source (%u bytes remaining)\n",
			      (unsigned)pt->len);
		    rc = G10ERR_READ_FILE;
		    xfree( buffer );
		    goto leave;
		}
		if( mfx->md )
		    md_write( mfx->md, buffer, len );
		if( fp )
		  {
		    if(opt.max_output && (count+=len)>opt.max_output)
		      {
			log_error("Error writing to `%s': %s\n",
				  fname,"exceeded --max-output limit\n");
			rc = G10ERR_WRITE_FILE;
			xfree( buffer );
			goto leave;
		      }
		    else if( fwrite( buffer, 1, len, fp ) != len )
		      {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			xfree( buffer );
			goto leave;
		      }
		  }
		pt->len -= len;
	    }
	    xfree( buffer );
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
		if( fp )
		  {
		    if(opt.max_output && (++count)>opt.max_output)
		      {
			log_error("Error writing to `%s': %s\n",
				  fname,"exceeded --max-output limit\n");
			rc = G10ERR_WRITE_FILE;
			goto leave;
		      }
		    else if( putc( c, fp ) == EOF )
		      {
			log_error("Error writing to `%s': %s\n",
				  fname, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			goto leave;
		      }
		  }
	    }
	}
	else { /* binary mode */
	    byte *buffer = xmalloc( 32768 );
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
		if( fp )
		  {
		    if(opt.max_output && (count+=len)>opt.max_output)
		      {
			log_error("Error writing to `%s': %s\n",
				  fname,"exceeded --max-output limit\n");
			rc = G10ERR_WRITE_FILE;
			xfree( buffer );
			goto leave;
		      }
		    else if( fwrite( buffer, 1, len, fp ) != len ) {
		      log_error("Error writing to `%s': %s\n",
				fname, strerror(errno) );
		      rc = G10ERR_WRITE_FILE;
		      xfree( buffer );
		      goto leave;
		    }
		  }
	    }
	    xfree( buffer );
	}
	pt->buf = NULL;
    }
    else {  /* clear text signature - don't hash the last cr,lf  */
	int state = 0;

	while( (c = iobuf_get(pt->buf)) != -1 ) {
	    if( fp )
	      {
		if(opt.max_output && (++count)>opt.max_output)
		  {
		    log_error("Error writing to `%s': %s\n",
			      fname,"exceeded --max-output limit\n");
		    rc = G10ERR_WRITE_FILE;
		    goto leave;
		  }
		else if( putc( c, fp ) == EOF )
		  {
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
    /* Make sure that stdout gets flushed after the plaintext has
       been handled.  This is for extra security as we do a
       flush anyway before checking the signature.  */
    fflush (stdout);

    if( fp && fp != stdout )
	fclose(fp);
    xfree(fname);
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
    progress_filter_context_t pfx;
    char *answer = NULL;
    IOBUF fp;
    int rc = 0;

    fp = open_sigfile( inname, &pfx ); /* open default file */

    if( !fp && !opt.batch ) {
	int any=0;
	tty_printf(_("Detached signature.\n"));
	do {
	    char *name;
	    xfree(answer);
	    tty_enable_completion(NULL);
	    name = cpr_get("detached_signature.filename",
			   _("Please enter name of data file: "));
	    tty_disable_completion();
	    cpr_kill_prompt();
	    answer=make_filename(name,(void *)NULL);
	    xfree(name);

	    if( any && !*answer ) {
		rc = G10ERR_READ_FILE;
		goto leave;
	    }
	    fp = iobuf_open(answer);
            if (fp && is_secured_file (iobuf_get_fd (fp)))
              {
                iobuf_close (fp);
                fp = NULL;
                errno = EPERM;
              }
	    if( !fp && errno == ENOENT ) {
		tty_printf("No such file, try again or hit enter to quit.\n");
		any++;
	    }
	    else if( !fp )
	      {
		log_error(_("can't open `%s': %s\n"), answer, strerror(errno));
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
    xfree(answer);
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
    progress_filter_context_t pfx;
    IOBUF fp;
    STRLIST sl;

    if( !files ) {
	/* check whether we can open the signed material */
	fp = open_sigfile( sigfilename, &pfx );
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
        if (fp && is_secured_file (iobuf_get_fd (fp)))
          {
            iobuf_close (fp);
            fp = NULL;
            errno = EPERM;
          }
	if( !fp ) {
	    log_error(_("can't open signed data `%s'\n"),
						print_fname_stdin(sl->d));
	    return G10ERR_OPEN_FILE;
	}
        handle_progress (&pfx, fp, sl->d);
	do_hash( md, md2, fp, textmode );
	iobuf_close(fp);
    }

    return 0;
}


/* Set up a plaintext packet with the appropriate filename.  If there
   is a --set-filename, use it (it's already UTF8).  If there is a
   regular filename, UTF8-ize it if necessary.  If there is no
   filenames at all, set the field empty. */

PKT_plaintext *
setup_plaintext_name(const char *filename,IOBUF iobuf)
{
  PKT_plaintext *pt;

  if(filename || opt.set_filename)
    {
      char *s;

      if(opt.set_filename)
	s=make_basename(opt.set_filename,iobuf_get_real_fname(iobuf));
      else if(filename && !opt.flags.utf8_filename)
	{
	  char *tmp=native_to_utf8(filename);
	  s=make_basename(tmp,iobuf_get_real_fname(iobuf));
	  xfree(tmp);
	}
      else
	s=make_basename(filename,iobuf_get_real_fname(iobuf));

      pt = xmalloc (sizeof *pt + strlen(s) - 1);
      pt->namelen = strlen (s);
      memcpy (pt->name, s, pt->namelen);
      xfree (s);
    }
  else
    {
      /* no filename */
      pt = xmalloc (sizeof *pt - 1);
      pt->namelen = 0;
    }

  return pt;
}
