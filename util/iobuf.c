/* iobuf.c  -  file handling
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_DOSISH_SYSTEM
  #include <fcntl.h> /* for setmode() */
#endif

#include "memory.h"
#include "util.h"
#include "iobuf.h"

#if defined (HAVE_FOPEN64) && defined (HAVE_FSTAT64)
  #define fopen(a,b)  fopen64 ((a),(b))
  #define fstat(a,b)  fstat64 ((a),(b))
#endif


typedef struct {
    FILE *fp;	   /* open file handle */
    int  print_only_name; /* flags indicating that fname is not a real file*/
    char fname[1]; /* name of the file */
} file_filter_ctx_t ;


/* The first partial length header block must be of size 512
 * to make it easier (and efficienter) we use a min. block size of 512
 * for all chunks (but the last one) */
#define OP_MIN_PARTIAL_CHUNK	  512
#define OP_MIN_PARTIAL_CHUNK_2POW 9

typedef struct {
    int use;
    size_t size;
    size_t count;
    int partial;  /* 1 = partial header, 2 in last partial packet */
    char *buffer;    /* used for partial header */
    size_t buflen;   /* used size of buffer */
    int first_c;     /* of partial header (which is > 0)*/
    int eof;
} block_filter_ctx_t;


static int underflow(IOBUF a);

/****************
 * Read data from a file into buf which has an allocated length of *LEN.
 * return the number of read bytes in *LEN. OPAQUE is the FILE * of
 * the stream. A is not used.
 * control may be:
 * IOBUFCTRL_INIT: called just before the function is linked into the
 *		   list of function. This can be used to prepare internal
 *		   data structures of the function.
 * IOBUFCTRL_FREE: called just before the function is removed from the
 *		    list of functions and can be used to release internal
 *		    data structures or close a file etc.
 * IOBUFCTRL_UNDERFLOW: called by iobuf_underflow to fill the buffer
 *		    with new stuff. *RET_LEN is the available size of the
 *		    buffer, and should be set to the number of bytes
 *		    which were put into the buffer. The function
 *		    returns 0 to indicate success, -1 on EOF and
 *		    G10ERR_xxxxx for other errors.
 *
 * IOBUFCTRL_FLUSH: called by iobuf_flush() to write out the collected stuff.
 *		    *RET_LAN is the number of bytes in BUF.
 *
 * IOBUFCTRL_CANCEL: send to all filters on behalf of iobuf_cancel.  The
 *		    filter may take appropriate action on this message.
 */
static int
file_filter(void *opaque, int control, IOBUF chain, byte *buf, size_t *ret_len)
{
    file_filter_ctx_t *a = opaque;
    FILE *fp = a->fp;
    size_t size = *ret_len;
    size_t nbytes = 0;
    int rc = 0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert( size ); /* need a buffer */
	if ( feof(fp)) {	/* On terminals you could easiely read as many EOFs as you call 	*/
	    rc = -1;		/* fread() or fgetc() repeatly. Every call will block until you press	*/
	    *ret_len = 0;	/* CTRL-D. So we catch this case before we call fread() again.		*/
	}
	else {
	    clearerr( fp );
	    nbytes = fread( buf, 1, size, fp );
	    if( feof(fp) && !nbytes )
		rc = -1; /* okay: we can return EOF now. */
	    else if( ferror(fp) && errno != EPIPE  ) {
		log_error("%s: read error: %s\n",
			  a->fname, strerror(errno));
		rc = G10ERR_READ_FILE;
	    }
	    *ret_len = nbytes;
	}
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( size ) {
	    clearerr( fp );
	    nbytes = fwrite( buf, 1, size, fp );
	    if( ferror(fp) ) {
		log_error("%s: write error: %s\n", a->fname, strerror(errno));
		rc = G10ERR_WRITE_FILE;
	    }
	}
	*ret_len = nbytes;
    }
    else if( control == IOBUFCTRL_INIT ) {
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "file_filter";
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( fp != stdin && fp != stdout ) {
	    if( DBG_IOBUF )
		log_debug("%s: close fd %d\n", a->fname, fileno(fp) );
	    fclose(fp);
	}
	fp = NULL;
	m_free(a); /* we can free our context now */
    }

    return rc;
}


/****************
 * This is used to implement the block write mode.
 * Block reading is done on a byte by byte basis in readbyte(),
 * without a filter
 */
static int
block_filter(void *opaque, int control, IOBUF chain, byte *buf, size_t *ret_len)
{
    block_filter_ctx_t *a = opaque;
    size_t size = *ret_len;
    int c, needed, rc = 0;
    char *p;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	size_t n=0;

	p = buf;
	assert( size ); /* need a buffer */
	if( a->eof ) /* don't read any further */
	    rc = -1;
	while( !rc && size ) {
	    if( !a->size ) { /* get the length bytes */
		if( a->partial == 2 ) {
		    a->eof = 1;
		    if( !n )
			rc = -1;
		    break;
		}
		else if( a->partial ) {
		    /* These OpenPGP introduced huffman like encoded length
		     * bytes are really a mess :-( */
		    if( a->first_c ) {
			c = a->first_c;
			a->first_c = 0;
			assert( c >= 224 && c < 255 );
		    }
		    else if( (c = iobuf_get(chain)) == -1 ) {
			log_error("block_filter: 1st length byte missing\n");
			rc = G10ERR_READ_FILE;
			break;
		    }
		    if( c < 192 ) {
			a->size = c;
			a->partial = 2;
			if( !a->size ) {
			    a->eof = 1;
			    if( !n )
				rc = -1;
			    break;
			}
		    }
		    else if( c < 224 ) {
			a->size = (c - 192) * 256;
			if( (c = iobuf_get(chain)) == -1 ) {
			    log_error("block_filter: 2nd length byte missing\n");
			    rc = G10ERR_READ_FILE;
			    break;
			}
			a->size += c + 192;
			a->partial = 2;
			if( !a->size ) {
			    a->eof = 1;
			    if( !n )
				rc = -1;
			    break;
			}
		    }
		    else if( c == 255 ) {
			a->size  = iobuf_get(chain) << 24;
			a->size |= iobuf_get(chain) << 16;
			a->size |= iobuf_get(chain) << 8;
			if( (c = iobuf_get(chain)) == -1 ) {
			    log_error("block_filter: invalid 4 byte length\n");
			    rc = G10ERR_READ_FILE;
			    break;
			}
			a->size |= c;
		    }
		    else { /* next partial body length */
			a->size = 1 << (c & 0x1f);
		    }
	    /*	log_debug("partial: ctx=%p c=%02x size=%u\n", a, c, a->size);*/
		}
		else { /* the gnupg partial length scheme - much better :-) */
		    c = iobuf_get(chain);
		    a->size = c << 8;
		    c = iobuf_get(chain);
		    a->size |= c;
		    if( c == -1 ) {
			log_error("block_filter: error reading length info\n");
			rc = G10ERR_READ_FILE;
		    }
		    if( !a->size ) {
			a->eof = 1;
			if( !n )
			    rc = -1;
			break;
		    }
		}
	    }

	    while( !rc && size && a->size ) {
		needed = size < a->size ? size : a->size;
		c = iobuf_read( chain, p, needed );
		if( c < needed ) {
		    if( c == -1 ) c = 0;
		    log_error("block_filter %p: read error (size=%lu,a->size=%lu)\n",
			      a,  (ulong)size+c, (ulong)a->size+c);
		    rc = G10ERR_READ_FILE;
		}
		else {
		    size -= c;
		    a->size -= c;
		    p += c;
		    n += c;
		}
	    }
	}
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( a->partial ) { /* the complicated openpgp scheme */
	    size_t blen, n, nbytes = size + a->buflen;

	    assert( a->buflen <= OP_MIN_PARTIAL_CHUNK );
	    if( nbytes < OP_MIN_PARTIAL_CHUNK ) {
		/* not enough to write a partial block out; so we store it*/
		if( !a->buffer )
		    a->buffer = m_alloc( OP_MIN_PARTIAL_CHUNK );
		memcpy( a->buffer + a->buflen, buf, size );
		a->buflen += size;
	    }
	    else { /* okay, we can write out something */
		/* do this in a loop to use the most efficient block lengths */
		p = buf;
		do {
		    /* find the best matching block length - this is limited
		     * by the size of the internal buffering */
		    for( blen=OP_MIN_PARTIAL_CHUNK*2,
			    c=OP_MIN_PARTIAL_CHUNK_2POW+1; blen <= nbytes;
							    blen *=2, c++ )
			;
		    blen /= 2; c--;
		    /* write the partial length header */
		    assert( c <= 0x1f ); /*;-)*/
		    c |= 0xe0;
		    iobuf_put( chain, c );
		    if( (n=a->buflen) ) { /* write stuff from the buffer */
			assert( n == OP_MIN_PARTIAL_CHUNK);
			if( iobuf_write(chain, a->buffer, n ) )
			    rc = G10ERR_WRITE_FILE;
			a->buflen = 0;
			nbytes -= n;
		    }
		    if( (n = nbytes) > blen )
			n = blen;
		    if( n && iobuf_write(chain, p, n ) )
			rc = G10ERR_WRITE_FILE;
		    p += n;
		    nbytes -= n;
		} while( !rc && nbytes >= OP_MIN_PARTIAL_CHUNK );
		/* store the rest in the buffer */
		if( !rc && nbytes ) {
		    assert( !a->buflen );
		    assert( nbytes < OP_MIN_PARTIAL_CHUNK );
		    if( !a->buffer )
			a->buffer = m_alloc( OP_MIN_PARTIAL_CHUNK );
		    memcpy( a->buffer, p, nbytes );
		    a->buflen = nbytes;
		}
	    }
	}
	else { /* the gnupg scheme (which is not openpgp compliant) */
	    size_t avail, n;

	    for(p=buf; !rc && size; ) {
		n = size;
		avail = a->size - a->count;
		if( !avail ) {
		    if( n > a->size ) {
			iobuf_put( chain, (a->size >> 8) & 0xff );
			iobuf_put( chain, a->size & 0xff );
			avail = a->size;
			a->count = 0;
		    }
		    else {
			iobuf_put( chain, (n >> 8) & 0xff );
			iobuf_put( chain, n & 0xff );
			avail = n;
			a->count = a->size - n;
		    }
		}
		if( n > avail )
		    n = avail;
		if( iobuf_write(chain, p, n ) )
		    rc = G10ERR_WRITE_FILE;
		a->count += n;
		p += n;
		size -= n;
	    }
	}
    }
    else if( control == IOBUFCTRL_INIT ) {
	if( DBG_IOBUF )
	    log_debug("init block_filter %p\n", a );
	if( a->partial )
	    a->count = 0;
	else if( a->use == 1 )
	    a->count = a->size = 0;
	else
	    a->count = a->size; /* force first length bytes */
	a->eof = 0;
	a->buffer = NULL;
	a->buflen = 0;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "block_filter";
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( a->use == 2 ) { /* write the end markers */
	    if( a->partial ) {
		u32 len;
		/* write out the remaining bytes without a partial header
		 * the length of this header may be 0 - but if it is
		 * the first block we are not allowed to use a partial header
		 * and frankly we can't do so, because this length must be
		 * a power of 2. This is _really_ complicated because we
		 * have to check the possible length of a packet prior
		 * to it's creation: a chain of filters becomes complicated
		 * and we need a lot of code to handle compressed packets etc.
		 *   :-(((((((
		 */
		/* construct header */
		len = a->buflen;
		/*log_debug("partial: remaining length=%u\n", len );*/
		if( len < 192 )
		    rc = iobuf_put(chain, len );
		else if( len < 8384 ) {
		    if( !(rc=iobuf_put( chain, ((len-192) / 256) + 192)) )
			rc = iobuf_put( chain, ((len-192) % 256));
		}
		else { /* use a 4 byte header */
		    if( !(rc=iobuf_put( chain, 0xff )) )
			if( !(rc=iobuf_put( chain, (len >> 24)&0xff )) )
			    if( !(rc=iobuf_put( chain, (len >> 16)&0xff )) )
				if( !(rc=iobuf_put( chain, (len >> 8)&0xff )))
				    rc=iobuf_put( chain, len & 0xff );
		}
		if( !rc && len )
		    rc = iobuf_write(chain, a->buffer, len );
		if( rc ) {
		    log_error("block_filter: write error: %s\n",strerror(errno));
		    rc = G10ERR_WRITE_FILE;
		}
		m_free( a->buffer ); a->buffer = NULL; a->buflen = 0;
	    }
	    else {
		iobuf_writebyte(chain, 0);
		iobuf_writebyte(chain, 0);
	    }
	}
	else if( a->size ) {
	    log_error("block_filter: pending bytes!\n");
	}
	if( DBG_IOBUF )
	    log_debug("free block_filter %p\n", a );
	m_free(a); /* we can free our context now */
    }

    return rc;
}


static void
print_chain( IOBUF a )
{
    if( !DBG_IOBUF )
	return;
    for(; a; a = a->chain ) {
	size_t dummy_len = 0;
	const char *desc = "[none]";

	if( a->filter )
	    a->filter( a->filter_ov, IOBUFCTRL_DESC, NULL,
						(byte*)&desc, &dummy_len );

	log_debug("iobuf chain: %d.%d `%s' filter_eof=%d start=%d len=%d\n",
		   a->no, a->subno, desc, a->filter_eof,
		   (int)a->d.start, (int)a->d.len );
    }
}

int
iobuf_print_chain( IOBUF a )
{
    print_chain(a);
    return 0;
}

/****************
 * Allocate a new io buffer, with no function assigned.
 * Use is the desired usage: 1 for input, 2 for output, 3 for temp buffer
 * BUFSIZE is a suggested buffer size.
 */
IOBUF
iobuf_alloc(int use, size_t bufsize)
{
    IOBUF a;
    static int number=0;

    a = m_alloc_clear(sizeof *a);
    a->use = use;
    a->d.buf = m_alloc( bufsize );
    a->d.size = bufsize;
    a->no = ++number;
    a->subno = 0;
    a->opaque = NULL;
    a->real_fname = NULL;
    return a;
}


int
iobuf_close( IOBUF a )
{
    IOBUF a2;
    size_t dummy_len=0;
    int rc=0;

    if( a && a->directfp ) {
	fclose( a->directfp );
	m_free( a->real_fname );
	if( DBG_IOBUF )
	    log_debug("iobuf_close -> %p\n", a->directfp );
	return 0;
    }

    for( ; a && !rc ; a = a2 ) {
	a2 = a->chain;
	if( a->use == 2 && (rc=iobuf_flush(a)) )
	    log_error("iobuf_flush failed on close: %s\n", g10_errstr(rc));

	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: close `%s'\n", a->no, a->subno, a->desc );
	if( a->filter && (rc = a->filter(a->filter_ov, IOBUFCTRL_FREE,
					 a->chain, NULL, &dummy_len)) )
	    log_error("IOBUFCTRL_FREE failed on close: %s\n", g10_errstr(rc) );
	m_free(a->real_fname);
	m_free(a->d.buf);
	m_free(a);
    }
    return rc;
}

int
iobuf_cancel( IOBUF a )
{
    const char *s;
    IOBUF a2;
    int rc;
  #ifdef HAVE_DOSISH_SYSTEM
    char *remove_name = NULL;
  #endif

    if( a && a->use == 2 ) {
	s = iobuf_get_real_fname(a);
	if( s && *s ) {
	  #ifdef HAVE_DOSISH_SYSTEM
	    remove_name = m_strdup ( s );
	  #else
	    remove(s);
	  #endif
	}
    }

    /* send a cancel message to all filters */
    for( a2 = a; a2 ; a2 = a2->chain ) {
	size_t dummy;
	if( a2->filter )
	    a2->filter( a2->filter_ov, IOBUFCTRL_CANCEL, a2->chain,
							 NULL, &dummy );
    }

    rc = iobuf_close(a);
  #ifdef HAVE_DOSISH_SYSTEM
    if ( remove_name ) {
	/* Argg, MSDOS does not allow to remove open files.  So
	 * we have to do it here */
	remove ( remove_name );
	m_free ( remove_name );
    }
  #endif
    return rc;
}


/****************
 * create a temporary iobuf, which can be used to collect stuff
 * in an iobuf and later be written by iobuf_write_temp() to another
 * iobuf.
 */
IOBUF
iobuf_temp()
{
    IOBUF a;

    a = iobuf_alloc(3, 8192 );

    return a;
}

IOBUF
iobuf_temp_with_content( const char *buffer, size_t length )
{
    IOBUF a;

    a = iobuf_alloc(3, length );
    memcpy( a->d.buf, buffer, length );
    a->d.len = length;

    return a;
}


/****************
 * Create a head iobuf for reading from a file
 * returns: NULL if an error occures and sets errno
 */
IOBUF
iobuf_open( const char *fname )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;
    int print_only = 0;

    if( !fname || (*fname=='-' && !fname[1])  ) {
	fp = stdin;
      #ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
      #endif
	fname = "[stdin]";
	print_only = 1;
    }
    else if( !(fp = fopen(fname, "rb")) )
	return NULL;
    a = iobuf_alloc(1, 8192 );
    fcx = m_alloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    fcx->print_only_name = print_only;
    strcpy(fcx->fname, fname );
    if( !print_only )
	a->real_fname = m_strdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: open `%s' fd=%d\n",
		   a->no, a->subno, fname, fileno(fcx->fp) );

    return a;
}

/****************
 * Create a head iobuf for reading from a file
 * returns: NULL if an error occures and sets errno
 */
IOBUF
iobuf_fdopen( int fd, const char *mode )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;

    if( !(fp = fdopen(fd, mode)) )
	return NULL;
    a = iobuf_alloc( strchr( mode, 'w')? 2:1, 8192 );
    fcx = m_alloc( sizeof *fcx + 20 );
    fcx->fp = fp;
    fcx->print_only_name = 1;
    sprintf(fcx->fname, "[fd %d]", fd );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: fdopen `%s'\n", a->no, a->subno, fcx->fname );

    return a;
}

/****************
 * create an iobuf for writing to a file; the file will be created.
 */
IOBUF
iobuf_create( const char *fname )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;
    int print_only = 0;

    if( !fname || (*fname=='-' && !fname[1]) ) {
	fp = stdout;
      #ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
      #endif
	fname = "[stdout]";
	print_only = 1;
    }
    else if( !(fp = fopen(fname, "wb")) )
	return NULL;
    a = iobuf_alloc(2, 8192 );
    fcx = m_alloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    fcx->print_only_name = print_only;
    strcpy(fcx->fname, fname );
    if( !print_only )
	a->real_fname = m_strdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: create `%s'\n", a->no, a->subno, a->desc );

    return a;
}

/****************
 * append to an iobuf; if the file does not exist, create it.
 * cannot be used for stdout.
 */
IOBUF
iobuf_append( const char *fname )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;

    if( !fname )
	return NULL;
    else if( !(fp = fopen(fname, "ab")) )
	return NULL;
    a = iobuf_alloc(2, 8192 );
    fcx = m_alloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    strcpy(fcx->fname, fname );
    a->real_fname = m_strdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: append `%s'\n", a->no, a->subno, a->desc );

    return a;
}

IOBUF
iobuf_openrw( const char *fname )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;

    if( !fname )
	return NULL;
    else if( !(fp = fopen(fname, "r+b")) )
	return NULL;
    a = iobuf_alloc(2, 8192 );
    fcx = m_alloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    strcpy(fcx->fname, fname );
    a->real_fname = m_strdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: openrw `%s'\n", a->no, a->subno, a->desc );

    return a;
}



/****************
 * You can overwrite the normal iobuf behaviour by using this function.
 * If used the iobuf is a simple wrapper around stdio.
 * NULL if an error occures and sets errno
 */
IOBUF
iobuf_fopen( const char *fname, const char *mode )
{
    IOBUF a;
    FILE *fp;
    int print_only = 0;

    if( !fname || (*fname=='-' && !fname[1])  ) {
	fp = stdin;
      #ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
      #endif
	fname = "[stdin]";
	print_only = 1;
    }
    else if( !(fp = fopen(fname, mode) ) )
	return NULL;
    a = iobuf_alloc(1, 8192 );
    a->directfp = fp;
    a->real_fname = m_strdup( fname );

    if( DBG_IOBUF )
	log_debug("iobuf_fopen -> %p\n", a->directfp );

    return a;
}



/****************
 * Register an i/o filter.
 */
int
iobuf_push_filter( IOBUF a,
		   int (*f)(void *opaque, int control,
		   IOBUF chain, byte *buf, size_t *len), void *ov )
{
    return iobuf_push_filter2( a, f, ov, 0 );
}

int
iobuf_push_filter2( IOBUF a,
		    int (*f)(void *opaque, int control,
		    IOBUF chain, byte *buf, size_t *len),
		    void *ov, int rel_ov )
{
    IOBUF b;
    size_t dummy_len=0;
    int rc=0;

    if( a->directfp )
	BUG();

    if( a->use == 2 && (rc=iobuf_flush(a)) )
	return rc;
    /* make a copy of the current stream, so that
     * A is the new stream and B the original one.
     * The contents of the buffers are transferred to the
     * new stream.
     */
    b = m_alloc(sizeof *b);
    memcpy(b, a, sizeof *b );
    /* fixme: it is stupid to keep a copy of the name at every level
     * but we need the name somewhere because the name known by file_filter
     * may have been released when we need the name of the file */
    b->real_fname = a->real_fname? m_strdup(a->real_fname):NULL;
    /* remove the filter stuff from the new stream */
    a->filter = NULL;
    a->filter_ov = NULL;
    a->filter_ov_owner = 0;
    a->filter_eof = 0;
    if( a->use == 3 )
	a->use = 2;  /* make a write stream from a temp stream */

    if( a->use == 2 ) { /* allocate a fresh buffer for the original stream */
	b->d.buf = m_alloc( a->d.size );
	b->d.len = 0;
	b->d.start = 0;
    }
    else { /* allocate a fresh buffer for the new stream */
	a->d.buf = m_alloc( a->d.size );
	a->d.len = 0;
	a->d.start = 0;
    }
    /* disable nlimit for the new stream */
    a->ntotal = b->ntotal + b->nbytes;
    a->nlimit = a->nbytes = 0;
    a->nofast &= ~1;
    /* make a link from the new stream to the original stream */
    a->chain = b;
    a->opaque = b->opaque;

    /* setup the function on the new stream */
    a->filter = f;
    a->filter_ov = ov;
    a->filter_ov_owner = rel_ov;

    a->subno = b->subno + 1;
    f( ov, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &dummy_len );

    if( DBG_IOBUF ) {
	log_debug("iobuf-%d.%d: push `%s'\n", a->no, a->subno, a->desc );
	print_chain( a );
    }

    /* now we can initialize the new function if we have one */
    if( a->filter && (rc = a->filter(a->filter_ov, IOBUFCTRL_INIT, a->chain,
		       NULL, &dummy_len)) )
	log_error("IOBUFCTRL_INIT failed: %s\n", g10_errstr(rc) );
    return rc;
}

/****************
 * Remove an i/o filter.
 */
int
pop_filter( IOBUF a, int (*f)(void *opaque, int control,
		      IOBUF chain, byte *buf, size_t *len), void *ov )
{
    IOBUF b;
    size_t dummy_len=0;
    int rc=0;

    if( a->directfp )
	BUG();

    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: pop `%s'\n", a->no, a->subno, a->desc );
    if( !a->filter ) { /* this is simple */
	b = a->chain;
	assert(b);
	m_free(a->d.buf);
	m_free(a->real_fname);
	memcpy(a,b, sizeof *a);
	m_free(b);
	return 0;
    }
    for(b=a ; b; b = b->chain )
	if( b->filter == f && (!ov || b->filter_ov == ov) )
	    break;
    if( !b )
	log_bug("pop_filter(): filter function not found\n");

    /* flush this stream if it is an output stream */
    if( a->use == 2 && (rc=iobuf_flush(b)) ) {
	log_error("iobuf_flush failed in pop_filter: %s\n", g10_errstr(rc));
	return rc;
    }
    /* and tell the filter to free it self */
    if( b->filter && (rc = b->filter(b->filter_ov, IOBUFCTRL_FREE, b->chain,
		       NULL, &dummy_len)) ) {
	log_error("IOBUFCTRL_FREE failed: %s\n", g10_errstr(rc) );
	return rc;
    }
    if( b->filter_ov && b->filter_ov_owner ) {
	m_free( b->filter_ov );
	b->filter_ov = NULL;
    }


    /* and see how to remove it */
    if( a == b && !b->chain )
	log_bug("can't remove the last filter from the chain\n");
    else if( a == b ) { /* remove the first iobuf from the chain */
	/* everything from b is copied to a. This is save because
	 * a flush has been done on the to be removed entry
	 */
	b = a->chain;
	m_free(a->d.buf);
	m_free(a->real_fname);
	memcpy(a,b, sizeof *a);
	m_free(b);
	if( DBG_IOBUF )
	   log_debug("iobuf-%d.%d: popped filter\n", a->no, a->subno );
    }
    else if( !b->chain ) { /* remove the last iobuf from the chain */
	log_bug("Ohh jeee, trying to remove a head filter\n");
    }
    else {  /* remove an intermediate iobuf from the chain */
	log_bug("Ohh jeee, trying to remove an intermediate filter\n");
    }

    return rc;
}


/****************
 * read underflow: read more bytes into the buffer and return
 * the first byte or -1 on EOF.
 */
static int
underflow(IOBUF a)
{
    size_t len;
    int rc;

    assert( a->d.start == a->d.len );
    if( a->use == 3 )
	return -1; /* EOF because a temp buffer can't do an underflow */

    if( a->filter_eof ) {
	if( a->chain && a->filter_eof == 1 ) {
	    IOBUF b = a->chain;
	    if( DBG_IOBUF )
		log_debug("iobuf-%d.%d: pop `%s' in underflow\n",
					a->no, a->subno, a->desc );
	    m_free(a->d.buf);
	    m_free(a->real_fname);
	    memcpy(a, b, sizeof *a);
	    m_free(b);
	    print_chain(a);
	}
	else
	    a->filter_eof = 0;
	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: underflow: eof (due to filter eof)\n",
						    a->no, a->subno );
	return -1; /* return one(!) EOF */
    }
    if( a->error ) {
	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: error\n", a->no, a->subno );
	return -1;
    }

    if( a->directfp ) {
	FILE *fp = a->directfp;

	len = fread( a->d.buf, 1, a->d.size, fp);
	if( len < a->d.size ) {
	    if( ferror(fp) )
		a->error = 1;
	}
	a->d.len = len;
	a->d.start = 0;
	return len? a->d.buf[a->d.start++] : -1;
    }


    if( a->filter ) {
	len = a->d.size;
	rc = a->filter( a->filter_ov, IOBUFCTRL_UNDERFLOW, a->chain,
			a->d.buf, &len );
	if( DBG_IOBUF ) {
	    log_debug("iobuf-%d.%d: underflow: req=%lu got=%lu rc=%d\n",
		    a->no, a->subno, (ulong)a->d.size, (ulong)len, rc );
	  #if 0
	    if( a->no == 7 ) {
		print_string(stderr, a->d.buf, len, 0 );
		putc('\n', stderr );
	    }
	  #endif

	}
	if( a->use == 1 && rc == -1 ) { /* EOF: we can remove the filter */
	    size_t dummy_len=0;

	    /* and tell the filter to free itself */
	    if( (rc = a->filter(a->filter_ov, IOBUFCTRL_FREE, a->chain,
			       NULL, &dummy_len)) )
		log_error("IOBUFCTRL_FREE failed: %s\n", g10_errstr(rc) );
	    if( a->filter_ov && a->filter_ov_owner ) {
		m_free( a->filter_ov );
		a->filter_ov = NULL;
	    }
	    a->filter = NULL;
	    a->desc = NULL;
	    a->filter_ov = NULL;
	    a->filter_eof = 1;
	    if( !len && a->chain ) {
		IOBUF b = a->chain;
		if( DBG_IOBUF )
		    log_debug("iobuf-%d.%d: pop `%s' in underflow (!len)\n",
					       a->no, a->subno, a->desc );
		print_chain(a);
		m_free(a->d.buf);
		m_free(a->real_fname);
		memcpy(a,b, sizeof *a);
		m_free(b);
		print_chain(a);
	    }
	}
	else if( rc )
	    a->error = 1;

	if( !len ) {
	    if( DBG_IOBUF )
		log_debug("iobuf-%d.%d: underflow: eof\n", a->no, a->subno );
	    return -1;
	}
	a->d.len = len;
	a->d.start = 0;
	return a->d.buf[a->d.start++];
    }
    else {
	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: underflow: eof (no filter)\n",
						    a->no, a->subno );
	return -1;  /* no filter; return EOF */
    }
}


int
iobuf_flush(IOBUF a)
{
    size_t len;
    int rc;

    if( a->directfp )
	return 0;

    /*log_debug("iobuf-%d.%d: flush\n", a->no, a->subno );*/
    if( a->use == 3 ) { /* increase the temp buffer */
	char *newbuf;
	size_t newsize = a->d.size + 8192;

	log_debug("increasing temp iobuf from %lu to %lu\n",
		    (ulong)a->d.size, (ulong)newsize );
	newbuf = m_alloc( newsize );
	memcpy( newbuf, a->d.buf, a->d.len );
	m_free(a->d.buf);
	a->d.buf = newbuf;
	a->d.size = newsize;
	return 0;
    }
    else if( a->use != 2 )
	log_bug("flush on non-output iobuf\n");
    else if( !a->filter )
	log_bug("iobuf_flush: no filter\n");
    len = a->d.len;
    rc = a->filter( a->filter_ov, IOBUFCTRL_FLUSH, a->chain, a->d.buf, &len );
    if( !rc && len != a->d.len ) {
	log_info("iobuf_flush did not write all!\n");
	rc = G10ERR_WRITE_FILE;
    }
    else if( rc )
	a->error = 1;
    a->d.len = 0;

    return rc;
}


/****************
 * Read a byte from the iobuf; returns -1 on EOF
 */
int
iobuf_readbyte(IOBUF a)
{
    int c;

    /* nlimit does not work together with unget */
    /* nbytes is also not valid! */
    if( a->unget.buf ) {
	if( a->unget.start < a->unget.len )
	    return a->unget.buf[a->unget.start++];
	m_free(a->unget.buf);
	a->unget.buf = NULL;
	a->nofast &= ~2;
    }

    if( a->nlimit && a->nbytes >= a->nlimit )
	return -1; /* forced EOF */

    if( a->d.start < a->d.len ) {
	c = a->d.buf[a->d.start++];
    }
    else if( (c=underflow(a)) == -1 )
	return -1; /* EOF */

    a->nbytes++;
    return c;
}


int
iobuf_read(IOBUF a, byte *buf, unsigned buflen )
{
    int c, n;

    if( a->unget.buf || a->nlimit ) {
	/* handle special cases */
	for(n=0 ; n < buflen; n++ ) {
	    if( (c = iobuf_readbyte(a)) == -1 ) {
		if( !n )
		    return -1; /* eof */
		break;
	    }
	    else
		if( buf ) *buf = c;
	    if( buf ) buf++;
	}
	return n;
    }

    n = 0;
    do {
	if( n < buflen && a->d.start < a->d.len ) {
	    unsigned size = a->d.len - a->d.start;
	    if( size > buflen - n )
		size = buflen - n;
	    if( buf )
		memcpy( buf, a->d.buf + a->d.start, size );
	    n += size;
	    a->d.start += size;
	    if( buf )
		buf += size;
	}
	if( n < buflen ) {
	    if( (c=underflow(a)) == -1 ) {
		a->nbytes += n;
		return n? n : -1/*EOF*/;
	    }
	    if( buf )
		*buf++ = c;
	    n++;
	}
    } while( n < buflen );
    a->nbytes += n;
    return n;
}


/****************
 * Have a look at the iobuf.
 * NOTE: This only works in special cases.
 */
int
iobuf_peek(IOBUF a, byte *buf, unsigned buflen )
{
    int n=0;

    if( a->filter_eof )
	return -1;

    if( !(a->d.start < a->d.len) ) {
	if( underflow(a) == -1 )
	    return -1;
	/* and unget this character */
	assert(a->d.start == 1);
	a->d.start = 0;
    }

    for(n=0 ; n < buflen && (a->d.start+n) < a->d.len ; n++, buf++ )
	*buf = a->d.buf[n];
    return n;
}




int
iobuf_writebyte(IOBUF a, unsigned c)
{

    if( a->directfp )
	BUG();

    if( a->d.len == a->d.size )
	if( iobuf_flush(a) )
	    return -1;

    assert( a->d.len < a->d.size );
    a->d.buf[a->d.len++] = c;
    return 0;
}


int
iobuf_write(IOBUF a, byte *buf, unsigned buflen )
{

    if( a->directfp )
	BUG();

    do {
	if( buflen && a->d.len < a->d.size ) {
	    unsigned size = a->d.size - a->d.len;
	    if( size > buflen ) size = buflen;
	    memcpy( a->d.buf + a->d.len, buf, size );
	    buflen -= size;
	    buf += size;
	    a->d.len += size;
	}
	if( buflen ) {
	    if( iobuf_flush(a) )
		return -1;
	}
    } while( buflen );
    return 0;
}


int
iobuf_writestr(IOBUF a, const char *buf )
{
    for( ; *buf; buf++ )
	if( iobuf_writebyte(a, *buf) )
	    return -1;
    return 0;
}



/****************
 * copy the contents of TEMP to A.
 */
int
iobuf_write_temp( IOBUF a, IOBUF temp )
{
    while( temp->chain )
	pop_filter( temp, temp->filter, NULL );
    return iobuf_write(a, temp->d.buf, temp->d.len );
}

/****************
 * copy the contents of the temp io stream to BUFFER.
 */
size_t
iobuf_temp_to_buffer( IOBUF a, byte *buffer, size_t buflen )
{
    size_t n = a->d.len;

    if( n > buflen )
	n = buflen;
    memcpy( buffer, a->d.buf, n );
    return n;
}


/****************
 * Call this function to terminate processing of the temp stream
 * without closing it.	This removes all filters from the stream
 * makes sure that iobuf_get_temp_{buffer,length}() returns correct
 * values.
 */
void
iobuf_flush_temp( IOBUF temp )
{
    while( temp->chain )
	pop_filter( temp, temp->filter, NULL );
}


/****************
 * Set a limit on how many bytes may be read from the input stream A.
 * Setting the limit to 0 disables this feature.
 */
void
iobuf_set_limit( IOBUF a, unsigned long nlimit )
{
    if( nlimit )
	a->nofast |= 1;
    else
	a->nofast &= ~1;
    a->nlimit = nlimit;
    a->ntotal += a->nbytes;
    a->nbytes = 0;
}



/****************
 * Return the length of an open file
 */
u32
iobuf_get_filelength( IOBUF a )
{
#if defined (HAVE_FOPEN64) && defined (HAVE_FSTAT64)
    struct stat64 st;
#else
    struct stat st;
#endif

    if( a->directfp )  {
	FILE *fp = a->directfp;

	if( !fstat(fileno(fp), &st) ) {
          #if defined (HAVE_FOPEN64) && defined (HAVE_FSTAT64)
            if( st.st_size >= IOBUF_FILELENGTH_LIMIT )
                return IOBUF_FILELENGTH_LIMIT;
          #endif
	    return (u32)st.st_size;
        }
	log_error("fstat() failed: %s\n", strerror(errno) );
	return 0;
    }

    /* Hmmm: file_filter may have already been removed */
    for( ; a; a = a->chain )
	if( !a->chain && a->filter == file_filter ) {
	    file_filter_ctx_t *b = a->filter_ov;
	    FILE *fp = b->fp;

	    if( !fstat(fileno(fp), &st) ) {
              #if defined (HAVE_FOPEN64) && defined (HAVE_FSTAT64)
                if( st.st_size >= IOBUF_FILELENGTH_LIMIT )
                    return IOBUF_FILELENGTH_LIMIT;
              #endif
		return st.st_size;
            }
	    log_error("fstat() failed: %s\n", strerror(errno) );
	    break;
	}

    return 0;
}

/****************
 * Tell the file position, where the next read will take place
 */
ulong
iobuf_tell( IOBUF a )
{
    return a->ntotal + a->nbytes;
}



/****************
 * This is a very limited implementation. It simply discards all internal
 * buffering and removes all filters but the first one.
 */
int
iobuf_seek( IOBUF a, ulong newpos )
{
    file_filter_ctx_t *b = NULL;

    if( a->directfp ) {
	FILE *fp = a->directfp;
	if( fseek( fp, newpos, SEEK_SET ) ) {
	    log_error("can't seek to %lu: %s\n", newpos, strerror(errno) );
	    return -1;
	}
	clearerr(fp);
    }
    else {
	for( ; a; a = a->chain ) {
	    if( !a->chain && a->filter == file_filter ) {
		b = a->filter_ov;
		break;
	    }
	}
	if( !a )
	    return -1;
	if( fseek( b->fp, newpos, SEEK_SET ) ) {
	    log_error("can't seek to %lu: %s\n", newpos, strerror(errno) );
	    return -1;
	}
    }
    a->d.len = 0;   /* discard buffer */
    a->d.start = 0;
    a->nbytes = 0;
    a->nlimit = 0;
    a->nofast &= ~1;
    a->ntotal = newpos;
    a->error = 0;
    /* remove filters, but the last */
    if( a->chain )
	log_debug("pop_filter called in iobuf_seek - please report\n");
    while( a->chain )
       pop_filter( a, a->filter, NULL );

    return 0;
}






/****************
 * Retrieve the real filename
 */
const char *
iobuf_get_real_fname( IOBUF a )
{
    if( a->real_fname )
	return a->real_fname;

    /* the old solution */
    for( ; a; a = a->chain )
	if( !a->chain && a->filter == file_filter ) {
	    file_filter_ctx_t *b = a->filter_ov;
	    return b->print_only_name? NULL : b->fname;
	}

    return NULL;
}


/****************
 * Retrieve the filename
 */
const char *
iobuf_get_fname( IOBUF a )
{
    for( ; a; a = a->chain )
	if( !a->chain && a->filter == file_filter ) {
	    file_filter_ctx_t *b = a->filter_ov;
	    return b->fname;
	}

    return NULL;
}

/****************
 * Start the block write mode, see rfc1991.new for details.
 * A value of 0 for N stops this mode (flushes and writes
 * the end marker)
 */
void
iobuf_set_block_mode( IOBUF a, size_t n )
{
    block_filter_ctx_t *ctx = m_alloc_clear( sizeof *ctx );

    assert( a->use == 1 || a->use == 2 );
    ctx->use = a->use;
    if( !n ) {
	if( a->use == 1 )
	    log_debug("pop_filter called in set_block_mode - please report\n");
	pop_filter(a, block_filter, NULL );
    }
    else {
	ctx->size = n; /* only needed for use 2 */
	iobuf_push_filter(a, block_filter, ctx );
    }
}

/****************
 * enable partial block mode as described in the OpenPGP draft.
 * LEN is the first length byte on read, but ignored on writes.
 */
void
iobuf_set_partial_block_mode( IOBUF a, size_t len )
{
    block_filter_ctx_t *ctx = m_alloc_clear( sizeof *ctx );

    assert( a->use == 1 || a->use == 2 );
    ctx->use = a->use;
    if( !len ) {
	if( a->use == 1 )
	    log_debug("pop_filter called in set_partial_block_mode"
						    " - please report\n");
	pop_filter(a, block_filter, NULL );
    }
    else {
	ctx->partial = 1;
	ctx->size = 0;
	ctx->first_c = len;
	iobuf_push_filter(a, block_filter, ctx );
    }
}


/****************
 * Checks whether the stream is in block mode
 * Note: This does not work if other filters are pushed on the stream.
 */
int
iobuf_in_block_mode( IOBUF a )
{
    if( a && a->filter == block_filter )
	return 1; /* yes */
    return 0; /* no */
}


/****************
 * Same as fgets() but if the buffer is too short a larger one will
 * be allocated up to some limit *max_length.
 * A line is considered a byte stream ending in a LF.
 * Returns the length of the line. EOF is indicated by a line of
 * length zero. The last LF may be missing due to an EOF.
 * is max_length is zero on return, the line has been truncated.
 *
 * Note: The buffer is allocated with enough space to append a CR,LF,EOL
 */
unsigned
iobuf_read_line( IOBUF a, byte **addr_of_buffer,
			  unsigned *length_of_buffer, unsigned *max_length )
{
    int c;
    char *buffer = *addr_of_buffer;
    unsigned length = *length_of_buffer;
    unsigned nbytes = 0;
    unsigned maxlen = *max_length;
    char *p;

    if( !buffer ) { /* must allocate a new buffer */
	length = 256;
	buffer = m_alloc( length );
	*addr_of_buffer = buffer;
	*length_of_buffer = length;
    }

    length -= 3; /* reserve 3 bytes (cr,lf,eol) */
    p = buffer;
    while( (c=iobuf_get(a)) != -1 ) {
	if( nbytes == length ) { /* increase the buffer */
	    if( length > maxlen  ) { /* this is out limit */
		/* skip the rest of the line */
		while( c != '\n' && (c=iobuf_get(a)) != -1 )
		    ;
		*p++ = '\n'; /* always append a LF (we have reserved space) */
		nbytes++;
		*max_length = 0; /* indicate truncation */
		break;
	    }
	    length += 3; /* correct for the reserved byte */
	    length += length < 1024? 256 : 1024;
	    buffer = m_realloc( buffer, length );
	    *addr_of_buffer = buffer;
	    *length_of_buffer = length;
	    length -= 3; /* and reserve again */
	    p = buffer + nbytes;
	}
	*p++ = c;
	nbytes++;
	if( c == '\n' )
	    break;
    }
    *p = 0; /* make sure the line is a string */

    return nbytes;
}

