/* iobuf.c  -  file handling
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
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

#include "memory.h"
#include "util.h"
#include "iobuf.h"

typedef struct {
    FILE *fp;	   /* open file handle */
    char fname[1]; /* name of the file */
} file_filter_ctx_t ;

typedef struct {
    int usage;
    size_t size;
    size_t count;
    int eof;
} block_filter_ctx_t;

static int underflow(IOBUF a);

/****************
 * Read data from a file into buf which has an allocated length of *LEN.
 * return the number of read bytes in *LEN. OPAQUE is the FILE * of
 * the stream. A is not used.
 * control maybe:
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
 */
static int
file_filter(void *opaque, int control, IOBUF chain, byte *buf, size_t *ret_len)
{
    file_filter_ctx_t *a = opaque;
    FILE *fp = a->fp;
    size_t size = *ret_len;
    size_t nbytes = 0;
    int c, rc = 0;
    char *p;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert( size ); /* need a buffer */
	for(; size; size-- ) {
	    if( (c=getc(fp)) == EOF ) {
		if( ferror(fp) ) {
		    log_error("%s: read error: %s\n",
					a->fname, strerror(errno));
		    rc = G10ERR_READ_FILE;
		}
		else if( !nbytes )
		    rc = -1; /* okay: we can return EOF now. */
		break;
	    }
	    buf[nbytes++] = c & 0xff;
	}
	*ret_len = nbytes;
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	for(p=buf; nbytes < size; nbytes++, p++ ) {
	    if( putc(*p, fp) == EOF ) {
		log_error("%s: write error: %s\n",
				    a->fname, strerror(errno));
		rc = G10ERR_WRITE_FILE;
		break;
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
	if( fp != stdin && fp != stdout )
	    fclose(fp);
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
    int c, rc = 0;
    char *p;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	size_t n=0;

	p = buf;
	assert( size ); /* need a buffer */
	if( a->eof ) /* don't read any further */
	    rc = -1;
	while( !rc && size ) {
	    if( !a->size ) { /* get the length bytes */
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

	    for(; !rc && size && a->size; size--, a->size-- ) {
		if( (c=iobuf_get(chain)) == -1 ) {
		    log_error("block_filter %p: read error (size=%lu,a->size=%lu)\n",
				a,  (ulong)size, (ulong)a->size);
		    rc = G10ERR_READ_FILE;
		}
		else {
		    *p++ = c;
		    n++;
		}
	    }
	}
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_FLUSH ) {
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
    else if( control == IOBUFCTRL_INIT ) {
	if( DBG_IOBUF )
	    log_debug("init block_filter %p\n", a );
	if( a->usage == 1 )
	    a->count = a->size = 0;
	else
	    a->count = a->size; /* force first length bytes */
	a->eof = 0;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "block_filter";
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( a->usage == 2 ) { /* write the end markers */
	    iobuf_writebyte(chain, 0);
	    iobuf_writebyte(chain, 0);
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



/****************
 * Allocate a new io buffer, with no function assigned.
 * Usage is the desired usage: 1 for input, 2 for output, 3 for temp buffer
 * BUFSIZE is a suggested buffer size.
 */
IOBUF
iobuf_alloc(int usage, size_t bufsize)
{
    IOBUF a;
    static int number=0;

    a = m_alloc_clear(sizeof *a);
    a->usage = usage;
    a->d.buf = m_alloc( bufsize );
    a->d.size = bufsize;
    a->no = ++number;
    a->subno = 0;
    a->opaque = NULL;
    return a;
}


int
iobuf_close( IOBUF a )
{
    IOBUF a2;
    size_t dummy_len;
    int rc=0;

    for( ; a; a = a2 ) {
	a2 = a->chain;
	if( a->usage == 2 && (rc=iobuf_flush(a)) )
	    log_error("iobuf_flush failed on close: %s\n", g10_errstr(rc));

	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: close '%s'\n", a->no, a->subno, a->desc );
	if( a->filter && (rc = a->filter(a->filter_ov, IOBUFCTRL_FREE,
					 a->chain, NULL, &dummy_len)) )
	    log_error("IOBUFCTRL_FREE failed on close: %s\n", g10_errstr(rc) );
	m_free(a->recorder.buf);
	m_free(a->d.buf);
	m_free(a);
    }
    return rc;
}

int
iobuf_cancel( IOBUF a )
{
    const char *s;

    if( a->usage == 2 ) {
	s = iobuf_get_fname(a);
	if( s && *s )
	    remove(s);	/* remove the file. Fixme: this will fail for MSDOZE*/
    }			/* because the file is still open */
    return iobuf_close(a);
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

    if( !fname ) {
	fp = stdin; /* fixme: set binary mode for msdoze */
	fname = "[stdin]";
    }
    else if( !(fp = fopen(fname, "rb")) )
	return NULL;
    a = iobuf_alloc(1, 8192 );
    fcx = m_alloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    strcpy(fcx->fname, fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: open '%s'\n", a->no, a->subno, fname );

    return a;
}

/****************
 * create a iobuf for writing to a file; the file will be created.
 */
IOBUF
iobuf_create( const char *fname )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;

    if( !fname ) {
	fp = stdout;
	fname = "[stdout]";
    }
    else if( !(fp = fopen(fname, "wb")) )
	return NULL;
    a = iobuf_alloc(2, 8192 );
    fcx = m_alloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    strcpy(fcx->fname, fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: create '%s'\n", a->no, a->subno, a->desc );

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
    IOBUF b;
    size_t dummy_len=0;
    int rc=0;

    if( a->usage == 2 && (rc=iobuf_flush(a)) )
	return rc;
    /* make a copy of the current stream, so that
     * A is the new stream and B the original one.
     * The contents of the buffers are transferred to the
     * new stream.
     */
    b = m_alloc(sizeof *b);
    memcpy(b, a, sizeof *b );
    /* remove the filter stuff from the new stream */
    a->filter = NULL;
    a->filter_ov = NULL;
    if( a->usage == 2 ) { /* allocate a fresh buffer for the original stream */
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
    a->nlimit = a->nbytes = 0;
    /* disable recorder for the original stream */
    b->recorder.buf = NULL;
    /* make a link from the new stream to the original stream */
    a->chain = b;
    a->opaque = b->opaque;

    /* setup the function on the new stream */
    a->filter = f;
    a->filter_ov = ov;

    a->subno = b->subno + 1;
    f( ov, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &dummy_len );

    if( DBG_IOBUF ) {
	log_debug("iobuf-%d.%d: push '%s'\n", a->no, a->subno, a->desc );
	for(b=a; b; b = b->chain )
	    log_debug("\tchain: %d.%d '%s'\n", b->no, b->subno, b->desc );
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
iobuf_pop_filter( IOBUF a, int (*f)(void *opaque, int control,
		      IOBUF chain, byte *buf, size_t *len), void *ov )
{
    IOBUF b;
    size_t dummy_len=0;
    int rc=0;

    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: pop '%s'\n", a->no, a->subno, a->desc );
    if( !a->filter ) { /* this is simple */
	b = a->chain;
	assert(b);
	m_free(a->d.buf);
	memcpy(a,b, sizeof *a);
	m_free(b);
	return 0;
    }
    for(b=a ; b; b = b->chain )
	if( b->filter == f && (!ov || b->filter_ov == ov) )
	    break;
    if( !b )
	log_bug("iobuf_pop_filter(): filter function not found\n");

    /* flush this stream if it is an output stream */
    if( a->usage == 2 && (rc=iobuf_flush(b)) ) {
	log_error("iobuf_flush failed in pop_filter: %s\n", g10_errstr(rc));
	return rc;
    }
    /* and tell the filter to free it self */
    if( (rc = b->filter(b->filter_ov, IOBUFCTRL_FREE, b->chain,
		       NULL, &dummy_len)) ) {
	log_error("IOBUFCTRL_FREE failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    /* and look how to remove it */
    if( a == b && !b->chain )
	log_bug("can't remove the last filter from the chain\n");
    else if( a == b ) { /* remove the first iobuf from the chain */
	/* everything from b is copied to a. This is save because
	 * a flush has been done on the to be removed entry
	 */
	b = a->chain;
	m_free(a->d.buf);
	memcpy(a,b, sizeof *a);
	m_free(b);
    }
    else if( !b->chain ) { /* remove the last iobuf from the chain */
	log_bug("Ohh jeee, trying to a head filter\n");
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

  /*log_debug("iobuf-%d.%d: underflow: start=%lu len=%lu\n",
		a->no, a->subno, (ulong)a->d.start, (ulong)a->d.len );*/
    assert( a->d.start == a->d.len );
    if( a->usage == 3 )
	return -1; /* EOF because a temp buffer can't do an underflow */
    if( a->filter_eof ) {
	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: filter eof\n", a->no, a->subno );
	return -1;
    }

    if( a->filter ) {
	len = a->d.size;
	rc = a->filter( a->filter_ov, IOBUFCTRL_UNDERFLOW, a->chain,
			a->d.buf, &len );
	if( a->usage == 1 && rc == -1 ) { /* EOF: we can remove the filter */
	    size_t dummy_len;

	    /* and tell the filter to free it self */
	    if( (rc = a->filter(a->filter_ov, IOBUFCTRL_FREE, a->chain,
			       NULL, &dummy_len)) )
		log_error("IOBUFCTRL_FREE failed: %s\n", g10_errstr(rc) );
	    a->filter = NULL;
	    a->desc = NULL;
	    a->filter_ov = NULL;
	    a->filter_eof = 1;
	}

	if( !len )
	    return -1;
	a->d.len = len;
	a->d.start = 0;
	return a->d.buf[a->d.start++];
    }
    else
	return -1;  /* no filter; return EOF */
}


void
iobuf_clear_eof(IOBUF a)
{
    assert(a->usage == 1);

    if( a->filter )
	log_info("iobuf-%d.%d: clear_eof '%s' with enabled filter\n", a->no, a->subno, a->desc );
    if( !a->filter_eof )
	log_info("iobuf-%d.%d: clear_eof '%s' with no EOF pending\n", a->no, a->subno, a->desc );
    iobuf_pop_filter(a, NULL, NULL);
}


int
iobuf_flush(IOBUF a)
{
    size_t len;
    int rc;

    /*log_debug("iobuf-%d.%d: flush\n", a->no, a->subno );*/
    if( a->usage == 3 )
	log_bug("temp buffer too short\n");
    else if( a->usage != 2 )
	log_bug("flush on non-output iobuf\n");
    else if( !a->filter )
	log_bug("iobuf_flush: no filter\n");
    len = a->d.len;
    rc = a->filter( a->filter_ov, IOBUFCTRL_FLUSH, a->chain, a->d.buf, &len );
    if( !rc && len != a->d.len ) {
	log_info("iobuf_flush did not write all!\n");
	rc = G10ERR_WRITE_FILE;
    }
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

    if( a->nlimit && a->nbytes >= a->nlimit )
	return -1; /* forced EOF */

    if( a->d.start < a->d.len ) {
	c = a->d.buf[a->d.start++];
    }
    else if( (c=underflow(a)) == -1 )
	return -1; /* EOF */

    a->nbytes++;

    if( a->recorder.buf ) {
	if( a->recorder.len >= a->recorder.size ) {
	    a->recorder.size += 500;
	    a->recorder.buf = m_realloc( a->recorder.buf, a->recorder.size );
	}
	((byte*)a->recorder.buf)[a->recorder.len++] = c;
    }
    return c;
}


int
iobuf_writebyte(IOBUF a, unsigned c)
{
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
    for( ; buflen; buflen--, buf++ )
	if( iobuf_writebyte(a, *buf) )
	    return -1;
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
 * Set a limit, how much bytes may be read from the input stream A.
 * Setting the limit to 0 disables this feature.
 */
void
iobuf_set_limit( IOBUF a, unsigned long nlimit )
{
    a->nlimit = nlimit;
    a->nbytes = 0;
}



void
iobuf_start_recorder( IOBUF a )
{
    m_free(a->recorder.buf);
    a->recorder.size = 500;
    a->recorder.buf = m_alloc(a->recorder.size);
    a->recorder.len = 0;
}

void
iobuf_push_recorder( IOBUF a, int c )
{
    if( a->recorder.buf ) {
	if( a->recorder.len >= a->recorder.size ) {
	    a->recorder.size += 500;
	    a->recorder.buf = m_realloc( a->recorder.buf, a->recorder.size );
	}
	((byte*)a->recorder.buf)[a->recorder.len++] = c;
    }
}


char *
iobuf_stop_recorder( IOBUF a, size_t *n )
{
    char *p;
    if( !a->recorder.buf )
	log_bug("iobuf_recorder not started\n");
    p = a->recorder.buf;
    if( n )
	*n = a->recorder.len;
    a->recorder.buf = NULL;
    return p;
}


/****************
 * Return the length of an open file
 */
u32
iobuf_get_filelength( IOBUF a )
{
    struct stat st;

    for( ; a; a = a->chain )
	if( !a->chain && a->filter == file_filter ) {
	    file_filter_ctx_t *b = a->filter_ov;
	    FILE *fp = b->fp;

	    if( !fstat(fileno(fp), &st) )
		return st.st_size;
	    log_error("fstat() failed: %s\n", strerror(errno) );
	    break;
	}

    return 0;
}

/****************
 * Retrieve the filename
 */
const char *
iobuf_get_fname( IOBUF a )
{
    struct stat st;

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

    assert( a->usage == 1 || a->usage == 2 );
    ctx->usage = a->usage;
    if( !n ) {
	iobuf_pop_filter(a, block_filter, NULL );
    }
    else {
	ctx->size = n; /* only needed for usage 2 */
	iobuf_push_filter(a, block_filter, ctx );
    }
}


/****************
 * checks wether the stream is in block mode
 */
int
iobuf_in_block_mode( IOBUF a )
{
    for(; a; a = a->chain )
	if( a->filter == block_filter )
	    return 1; /* yes */
    return 0; /* no */
}



