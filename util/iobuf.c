/* iobuf.c  -  file handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004 Free Software Foundation, Inc.
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
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <unistd.h>
#ifdef HAVE_DOSISH_SYSTEM
#include <windows.h>
#endif
#ifdef __riscos__
#include <kernel.h>
#include <swis.h>
#endif /* __riscos__ */

#include "memory.h"
#include "util.h"
#include "dynload.h"
#include "iobuf.h"

/* The size of the internal buffers. 
   NOTE: If you change this value you MUST also adjust the regression
   test "armored_key_8192" in armor.test! */
#define IOBUF_BUFFER_SIZE  8192


#undef FILE_FILTER_USES_STDIO

#ifdef HAVE_DOSISH_SYSTEM
#define USE_SETMODE 1
#endif

#ifdef FILE_FILTER_USES_STDIO
#define my_fileno(a)  fileno ((a))
#define my_fopen_ro(a,b) fopen ((a),(b))
#define my_fopen(a,b)    fopen ((a),(b))
typedef FILE *FILEP_OR_FD;
#define INVALID_FP    NULL
#define FILEP_OR_FD_FOR_STDIN  (stdin)
#define FILEP_OR_FD_FOR_STDOUT  (stdout)
typedef struct {
     FILE *fp;	   /* open file handle */
     int keep_open;
     int no_cache;
     int  print_only_name; /* flags indicating that fname is not a real file*/
     char fname[1]; /* name of the file */
 } file_filter_ctx_t ;
#else
#define my_fileno(a)  (a)
#define my_fopen_ro(a,b) fd_cache_open ((a),(b)) 
#define my_fopen(a,b) direct_open ((a),(b)) 
#ifdef HAVE_DOSISH_SYSTEM
typedef HANDLE FILEP_OR_FD;
#define INVALID_FP  ((HANDLE)-1)
#define FILEP_OR_FD_FOR_STDIN  (GetStdHandle (STD_INPUT_HANDLE))
#define FILEP_OR_FD_FOR_STDOUT (GetStdHandle (STD_OUTPUT_HANDLE))
#undef USE_SETMODE
#else
typedef int FILEP_OR_FD;
#define INVALID_FP  (-1)
#define FILEP_OR_FD_FOR_STDIN  (0)
#define FILEP_OR_FD_FOR_STDOUT (1)
#endif
typedef struct {
     FILEP_OR_FD  fp;	   /* open file handle */
     int keep_open;
     int no_cache;
     int eof_seen;
     int  print_only_name; /* flags indicating that fname is not a real file*/
     char fname[1]; /* name of the file */
 } file_filter_ctx_t ;

 struct close_cache_s { 
    struct close_cache_s *next;
    FILEP_OR_FD fp;
    char fname[1];
 };
 typedef struct close_cache_s *CLOSE_CACHE;
 static CLOSE_CACHE close_cache;
#endif

#ifdef _WIN32
typedef struct {
    int sock;
    int keep_open;
    int no_cache;
    int eof_seen;
    int  print_only_name; /* flags indicating that fname is not a real file*/
    char fname[1]; /* name of the file */
} sock_filter_ctx_t ;
#endif /*_WIN32*/

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

static int special_names_enabled;

static int underflow(IOBUF a);
static int translate_file_handle ( int fd, int for_write );



#ifndef FILE_FILTER_USES_STDIO

/* This is a replacement for strcmp.  Under W32 it does not
   distinguish between backslash and slash.  */
static int
fd_cache_strcmp (const char *a, const char *b)
{
#ifdef HAVE_DOSISH_SYSTEM
  for (; *a && *b; a++, b++)
    {
      if (*a != *b && !((*a == '/' && *b == '\\') 
                        || (*a == '\\' && *b == '/')) )
        break;
    }
  return *(const unsigned char *)a - *(const unsigned char *)b;
#else
  return strcmp (a, b);
#endif
}

/*
 * Invalidate (i.e. close) a cached iobuf or all iobufs if NULL is
 * used for FNAME.
 */
static void
fd_cache_invalidate (const char *fname)
{
    CLOSE_CACHE cc;

    if (!fname) {
        if( DBG_IOBUF )
            log_debug ("fd_cache_invalidate (all)\n");

        for (cc=close_cache; cc; cc = cc->next ) {
            if ( cc->fp != INVALID_FP ) {
#ifdef HAVE_DOSISH_SYSTEM
                CloseHandle (cc->fp);
#else
                close(cc->fp);
#endif
                cc->fp = INVALID_FP;
            }
        }
        return;
    }

    if( DBG_IOBUF )
        log_debug ("fd_cache_invalidate (%s)\n", fname);

    for (cc=close_cache; cc; cc = cc->next ) {
        if ( cc->fp != INVALID_FP && !fd_cache_strcmp (cc->fname, fname) ) {
            if( DBG_IOBUF )
                log_debug ("                did (%s)\n", cc->fname);
#ifdef HAVE_DOSISH_SYSTEM
            CloseHandle (cc->fp);
#else
	    close(cc->fp);
#endif
            cc->fp = INVALID_FP;
        }
    }
}



static FILEP_OR_FD
direct_open (const char *fname, const char *mode)
{
#ifdef HAVE_DOSISH_SYSTEM
    unsigned long da, cd, sm;
    HANDLE hfile;

    /* Note, that we do not handle all mode combinations */

    /* According to the ReactOS source it seems that open() of the
     * standard MSW32 crt does open the file in share mode which is
     * something new for MS applications ;-)
     */
    if ( strchr (mode, '+') ) {
        fd_cache_invalidate (fname);
        da = GENERIC_READ|GENERIC_WRITE;
        cd = OPEN_EXISTING;
        sm = FILE_SHARE_READ | FILE_SHARE_WRITE;
    }
    else if ( strchr (mode, 'w') ) {
        fd_cache_invalidate (fname);
        da = GENERIC_WRITE;
        cd = CREATE_ALWAYS;
        sm = FILE_SHARE_WRITE;
    }
    else {
        da = GENERIC_READ;
        cd = OPEN_EXISTING;
        sm = FILE_SHARE_READ;
    }

    hfile = CreateFile (fname, da, sm, NULL, cd, FILE_ATTRIBUTE_NORMAL, NULL);
    return hfile;
#else
    int oflag;
    int cflag = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

    /* Note, that we do not handle all mode combinations */
    if ( strchr (mode, '+') ) {
        fd_cache_invalidate (fname);
        oflag = O_RDWR;
    }
    else if ( strchr (mode, 'w') ) {
        fd_cache_invalidate (fname);
        oflag = O_WRONLY | O_CREAT | O_TRUNC;
    }
    else {
        oflag = O_RDONLY;
    }
#ifdef O_BINARY
    if (strchr (mode, 'b'))
      oflag |= O_BINARY;
#endif
#ifndef __riscos__
    return open (fname, oflag, cflag );
#else
    {
        struct stat buf;
        int rc = stat( fname, &buf );
        
        /* Don't allow iobufs on directories */
        if( !rc && S_ISDIR(buf.st_mode) && !S_ISREG(buf.st_mode) )
            return __set_errno( EISDIR );
        else
            return open( fname, oflag, cflag );
    }
#endif
#endif
}


/*
 * Instead of closing an FD we keep it open and cache it for later reuse 
 * Note that this caching strategy only works if the process does not chdir.
 */
static void
fd_cache_close (const char *fname, FILEP_OR_FD fp)
{
    CLOSE_CACHE cc;

    assert (fp);
    if ( !fname || !*fname ) {
#ifdef HAVE_DOSISH_SYSTEM
        CloseHandle (fp);
#else
        close(fp);
#endif
        if( DBG_IOBUF )
            log_debug ("fd_cache_close (%p) real\n", (void*)fp);
        return;
    }
    /* try to reuse a slot */
    for (cc=close_cache; cc; cc = cc->next ) {
        if ( cc->fp == INVALID_FP && !fd_cache_strcmp (cc->fname, fname) ) {
            cc->fp = fp;
            if( DBG_IOBUF )
                log_debug ("fd_cache_close (%s) used existing slot\n", fname);
            return;
        }
    }
    /* add a new one */
    if( DBG_IOBUF )
        log_debug ("fd_cache_close (%s) new slot created\n", fname);
    cc = xmalloc_clear (sizeof *cc + strlen (fname));
    strcpy (cc->fname, fname);
    cc->fp = fp;
    cc->next = close_cache;
    close_cache = cc;
}

/*
 * Do an direct_open on FNAME but first try to reuse one from the fd_cache
 */
static FILEP_OR_FD
fd_cache_open (const char *fname, const char *mode)
{
    CLOSE_CACHE cc;

    assert (fname);
    for (cc=close_cache; cc; cc = cc->next ) {
        if ( cc->fp != INVALID_FP && !fd_cache_strcmp (cc->fname, fname) ) {
            FILEP_OR_FD fp = cc->fp;
            cc->fp = INVALID_FP;
            if( DBG_IOBUF )
                log_debug ("fd_cache_open (%s) using cached fp\n", fname);
#ifdef HAVE_DOSISH_SYSTEM
            if (SetFilePointer (fp, 0, NULL, FILE_BEGIN) == 0xffffffff ) {
                log_error ("rewind file failed on handle %p: %s\n",
                           fp, w32_strerror (errno));
                fp = INVALID_FP;
            }
#else
            if ( lseek (fp, 0, SEEK_SET) == (off_t)-1 ) {
                log_error("can't rewind fd %d: %s\n", fp, strerror(errno) );
                fp = INVALID_FP;
            }
#endif
            return fp;
        }
    }
    if( DBG_IOBUF )
        log_debug ("fd_cache_open (%s) not cached\n", fname);
    return direct_open (fname, mode);
}


#endif /*FILE_FILTER_USES_STDIO*/


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
    FILEP_OR_FD f = a->fp;
    size_t size = *ret_len;
    size_t nbytes = 0;
    int rc = 0;

#ifdef FILE_FILTER_USES_STDIO
    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert( size ); /* need a buffer */
	if ( feof(f)) {	/* On terminals you could easiely read as many EOFs as you call 	*/
	    rc = -1;		/* fread() or fgetc() repeatly. Every call will block until you press	*/
	    *ret_len = 0;	/* CTRL-D. So we catch this case before we call fread() again.		*/
	}
	else {
	    clearerr( f );
	    nbytes = fread( buf, 1, size, f );
	    if( feof(f) && !nbytes ) {
		rc = -1; /* okay: we can return EOF now. */
            }
	    else if( ferror(f) && errno != EPIPE  ) {
		log_error("%s: read error: %s\n",
			  a->fname, strerror(errno));
		rc = G10ERR_READ_FILE;
	    }
	    *ret_len = nbytes;
	}
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( size ) {
	    clearerr( f );
	    nbytes = fwrite( buf, 1, size, f );
	    if( ferror(f) ) {
		log_error("%s: write error: %s\n", a->fname, strerror(errno));
		rc = G10ERR_WRITE_FILE;
	    }
	}
	*ret_len = nbytes;
    }
    else if( control == IOBUFCTRL_INIT ) {
        a->keep_open = a->no_cache = 0;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "file_filter";
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( f != stdin && f != stdout ) {
	    if( DBG_IOBUF )
		log_debug("%s: close fd %d\n", a->fname, fileno(f) );
            if (!a->keep_open)
                fclose(f);
	}
	f = NULL;
	xfree(a); /* we can free our context now */
    }
#else /* !stdio implementation */

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert( size ); /* need a buffer */
	if ( a->eof_seen) {
	    rc = -1;		
	    *ret_len = 0;	
	}
	else {
#ifdef HAVE_DOSISH_SYSTEM
            unsigned long nread;

            nbytes = 0;
            if ( !ReadFile ( f, buf, size, &nread, NULL ) ) {
                if ((int)GetLastError () != ERROR_BROKEN_PIPE) {
                    log_error ("%s: read error: %s\n", a->fname,
                               w32_strerror (0));
                    rc = G10ERR_READ_FILE;
                }
            }
            else if ( !nread ) {
                a->eof_seen = 1;
                rc = -1;
            }
            else {
                nbytes = nread;
            }

#else

            int n;

            nbytes = 0;
            do {
                n = read ( f, buf, size );
            } while (n == -1 && errno == EINTR );
            if ( n == -1 ) { /* error */
                if (errno != EPIPE) {
                    log_error("%s: read error: %s\n",
                              a->fname, strerror(errno));
                    rc = G10ERR_READ_FILE;
                }
            }
            else if ( !n ) { /* eof */
                a->eof_seen = 1;
                rc = -1;
            }
            else {
                nbytes = n;
            }
#endif
	    *ret_len = nbytes;
	}
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( size ) {
#ifdef HAVE_DOSISH_SYSTEM
            byte *p = buf;
            unsigned long n;

            nbytes = size;
            do {
                if (size && !WriteFile (f,  p, nbytes, &n, NULL)) {
                    log_error ("%s: write error: %s\n", a->fname,
                               w32_strerror (0));
                    rc = G10ERR_WRITE_FILE;
                    break;
                }
                p += n;
                nbytes -= n;
            } while ( nbytes );
            nbytes = p - buf;
#else
            byte *p = buf;
            int n;

            nbytes = size;
            do {
                do {
                    n = write ( f, p, nbytes );
                } while ( n == -1 && errno == EINTR );
                if ( n > 0 ) {
                    p += n;
                    nbytes -= n;
                }
            } while ( n != -1 && nbytes );
	    if( n == -1 ) {
		log_error("%s: write error: %s\n", a->fname, strerror(errno));
		rc = G10ERR_WRITE_FILE;
	    }
            nbytes = p - buf;
#endif
	}
	*ret_len = nbytes;
    }
    else if ( control == IOBUFCTRL_INIT ) {
        a->eof_seen = 0;
        a->keep_open = 0;
        a->no_cache = 0;
    }
    else if ( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "file_filter(fd)";
    }
    else if ( control == IOBUFCTRL_FREE ) {
#ifdef HAVE_DOSISH_SYSTEM
        if ( f != FILEP_OR_FD_FOR_STDIN && f != FILEP_OR_FD_FOR_STDOUT ) {
	    if( DBG_IOBUF )
		log_debug("%s: close handle %p\n", a->fname, f );
            if (!a->keep_open)
                fd_cache_close (a->no_cache?NULL:a->fname, f);
        }
#else
	if ( (int)f != 0 && (int)f != 1 ) {
	    if( DBG_IOBUF )
		log_debug("%s: close fd %d\n", a->fname, f );
            if (!a->keep_open)
                fd_cache_close (a->no_cache?NULL:a->fname, f);
	}
	f = INVALID_FP;
#endif
	xfree (a); /* we can free our context now */
    }
#endif /* !stdio implementation */
    return rc;
}

#ifdef _WIN32
/* Becuase sockets are an special object under Lose32 we have to
 * use a special filter */
static int
sock_filter (void *opaque, int control, IOBUF chain, byte *buf, size_t *ret_len)
{
    sock_filter_ctx_t *a = opaque;
    size_t size = *ret_len;
    size_t nbytes = 0;
    int rc = 0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert( size ); /* need a buffer */
	if ( a->eof_seen) {
	    rc = -1;		
	    *ret_len = 0;	
	}
	else {
            int nread;

            nread = recv ( a->sock, buf, size, 0 );
            if ( nread == SOCKET_ERROR ) {
                int ec = (int)WSAGetLastError ();
                log_error("socket read error: ec=%d\n", ec);
                rc = G10ERR_READ_FILE;
            }
            else if ( !nread ) {
                a->eof_seen = 1;
                rc = -1;
            }
            else {
                nbytes = nread;
            }
	    *ret_len = nbytes;
	}
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( size ) {
            byte *p = buf;
            int n;

            nbytes = size;
            do {
                n = send (a->sock, p, nbytes, 0);
                if ( n == SOCKET_ERROR ) {
                    int ec = (int)WSAGetLastError ();
                    log_error("socket write error: ec=%d\n", ec);
                    rc = G10ERR_WRITE_FILE;
                    break;
                }
                p += n;
                nbytes -= n;
            } while ( nbytes );
            nbytes = p - buf;
	}
	*ret_len = nbytes;
    }
    else if ( control == IOBUFCTRL_INIT ) {
        a->eof_seen = 0;
        a->keep_open = 0;
        a->no_cache = 0;
    }
    else if ( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "sock_filter";
    }
    else if ( control == IOBUFCTRL_FREE ) {
        if (!a->keep_open)
            closesocket (a->sock);
	xfree (a); /* we can free our context now */
    }
    return rc;
}
#endif /*_WIN32*/

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
			a->partial = 2;
			if( !a->size ) {
			    a->eof = 1;
			    if( !n )
				rc = -1;
			    break;
			}
		    }
		    else { /* next partial body length */
			a->size = 1 << (c & 0x1f);
		    }
	    /*	log_debug("partial: ctx=%p c=%02x size=%u\n", a, c, a->size);*/
		}
		else
		  BUG();
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
		    a->buffer = xmalloc( OP_MIN_PARTIAL_CHUNK );
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
			a->buffer = xmalloc( OP_MIN_PARTIAL_CHUNK );
		    memcpy( a->buffer, p, nbytes );
		    a->buflen = nbytes;
		}
	    }
	}
	else
	  BUG();
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
		xfree( a->buffer ); a->buffer = NULL; a->buflen = 0;
	    }
	    else
	      BUG();
	}
	else if( a->size ) {
	    log_error("block_filter: pending bytes!\n");
	}
	if( DBG_IOBUF )
	    log_debug("free block_filter %p\n", a );
	xfree(a); /* we can free our context now */
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

    a = xmalloc_clear(sizeof *a);
    a->use = use;
    a->d.buf = xmalloc( bufsize );
    a->d.size = bufsize;
    a->no = ++number;
    a->subno = 0;
    a->opaque = NULL;
    a->real_fname = NULL;
    return a;
}

int
iobuf_close ( IOBUF a )
{
    IOBUF a2;
    size_t dummy_len=0;
    int rc=0;

    if( a && a->directfp ) {
	fclose( a->directfp );
	xfree( a->real_fname );
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
	xfree(a->real_fname);
        if (a->d.buf) {
            memset (a->d.buf, 0, a->d.size); /* erase the buffer */
            xfree(a->d.buf);
        }
	xfree(a);
    }
    return rc;
}

int
iobuf_cancel( IOBUF a )
{
    const char *s;
    IOBUF a2;
    int rc;
#if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
    char *remove_name = NULL;
#endif

    if( a && a->use == 2 ) {
	s = iobuf_get_real_fname(a);
	if( s && *s ) {
#if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
	    remove_name = xstrdup ( s );
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
#if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
    if ( remove_name ) {
	/* Argg, MSDOS does not allow to remove open files.  So
	 * we have to do it here */
	remove ( remove_name );
	xfree ( remove_name );
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

    a = iobuf_alloc(3, IOBUF_BUFFER_SIZE );

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

void
iobuf_enable_special_filenames ( int yes )
{
    special_names_enabled = yes;
}

/*
 * see whether the filename has the for "-&nnnn", where n is a
 * non-zero number.
 * Returns this number or -1 if it is not the case.
 */
static int
check_special_filename ( const char *fname )
{
    if ( special_names_enabled
         && fname && *fname == '-' && fname[1] == '&' ) {
        int i;

        fname += 2;
        for (i=0; digitp (fname+i); i++ )
            ;
        if ( !fname[i] ) 
            return atoi (fname);
    }
    return -1;
}

/* This fucntion returns true if FNAME indicates a PIPE (stdout or
   stderr) or a special file name if those are enabled. */
int
iobuf_is_pipe_filename (const char *fname)
{
  if (!fname || (*fname=='-' && !fname[1]) )
    return 1;
  return check_special_filename (fname) != -1;
}

/****************
 * Create a head iobuf for reading from a file
 * returns: NULL if an error occures and sets errno
 */
IOBUF
iobuf_open( const char *fname )
{
    IOBUF a;
    FILEP_OR_FD fp;
    file_filter_ctx_t *fcx;
    size_t len;
    int print_only = 0;
    int fd;

    if( !fname || (*fname=='-' && !fname[1])  ) {
	fp = FILEP_OR_FD_FOR_STDIN;
#ifdef USE_SETMODE
	setmode ( my_fileno(fp) , O_BINARY );
#endif
	fname = "[stdin]";
	print_only = 1;
    }
    else if ( (fd = check_special_filename ( fname )) != -1 )
        return iobuf_fdopen ( translate_file_handle (fd,0), "rb" );
    else if( (fp = my_fopen_ro(fname, "rb")) == INVALID_FP )
	return NULL;
    a = iobuf_alloc(1, IOBUF_BUFFER_SIZE );
    fcx = xmalloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    fcx->print_only_name = print_only;
    strcpy(fcx->fname, fname );
    if( !print_only )
	a->real_fname = xstrdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: open `%s' fd=%d\n",
		   a->no, a->subno, fname, (int)my_fileno(fcx->fp) );

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
    FILEP_OR_FD fp;
    file_filter_ctx_t *fcx;
    size_t len;

#ifdef FILE_FILTER_USES_STDIO
    if( !(fp = fdopen(fd, mode)) )
	return NULL;
#else
    fp = (FILEP_OR_FD)fd;
#endif
    a = iobuf_alloc( strchr( mode, 'w')? 2:1, IOBUF_BUFFER_SIZE );
    fcx = xmalloc( sizeof *fcx + 20 );
    fcx->fp = fp;
    fcx->print_only_name = 1;
    sprintf(fcx->fname, "[fd %d]", fd );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: fdopen `%s'\n", a->no, a->subno, fcx->fname );
    iobuf_ioctl (a,3,1,NULL); /* disable fd caching */
    return a;
}


IOBUF
iobuf_sockopen ( int fd, const char *mode )
{
    IOBUF a;
#ifdef _WIN32
    sock_filter_ctx_t *scx;
    size_t len;

    a = iobuf_alloc( strchr( mode, 'w')? 2:1, IOBUF_BUFFER_SIZE );
    scx = xmalloc( sizeof *scx + 25 );
    scx->sock = fd;
    scx->print_only_name = 1;
    sprintf(scx->fname, "[sock %d]", fd );
    a->filter = sock_filter;
    a->filter_ov = scx;
    sock_filter( scx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    sock_filter( scx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: sockopen `%s'\n", a->no, a->subno, scx->fname);
    iobuf_ioctl (a,3,1,NULL); /* disable fd caching */ 
#else
    a = iobuf_fdopen (fd, mode);
#endif
    return a;
}

/****************
 * create an iobuf for writing to a file; the file will be created.
 */
IOBUF
iobuf_create( const char *fname )
{
    IOBUF a;
    FILEP_OR_FD fp;
    file_filter_ctx_t *fcx;
    size_t len;
    int print_only = 0;
    int fd;

    if( !fname || (*fname=='-' && !fname[1]) ) {
	fp = FILEP_OR_FD_FOR_STDOUT;
#ifdef USE_SETMODE
	setmode ( my_fileno(fp) , O_BINARY );
#endif
	fname = "[stdout]";
	print_only = 1;
    }
    else if ( (fd = check_special_filename ( fname )) != -1 )
        return iobuf_fdopen ( translate_file_handle (fd, 1), "wb" );
    else if( (fp = my_fopen(fname, "wb")) == INVALID_FP )
	return NULL;
    a = iobuf_alloc(2, IOBUF_BUFFER_SIZE );
    fcx = xmalloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    fcx->print_only_name = print_only;
    strcpy(fcx->fname, fname );
    if( !print_only )
	a->real_fname = xstrdup( fname );
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
 * Note: This is not used.
 */
#if 0 /* not used */
IOBUF
iobuf_append( const char *fname )
{
    IOBUF a;
    FILE *fp;
    file_filter_ctx_t *fcx;
    size_t len;

    if( !fname )
	return NULL;
    else if( !(fp = my_fopen(fname, "ab")) )
	return NULL;
    a = iobuf_alloc(2, IOBUF_BUFFER_SIZE );
    fcx = xmalloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    strcpy(fcx->fname, fname );
    a->real_fname = xstrdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: append `%s'\n", a->no, a->subno, a->desc );

    return a;
}
#endif

IOBUF
iobuf_openrw( const char *fname )
{
    IOBUF a;
    FILEP_OR_FD fp;
    file_filter_ctx_t *fcx;
    size_t len;

    if( !fname )
	return NULL;
    else if( (fp = my_fopen(fname, "r+b")) == INVALID_FP )
	return NULL;
    a = iobuf_alloc(2, IOBUF_BUFFER_SIZE );
    fcx = xmalloc( sizeof *fcx + strlen(fname) );
    fcx->fp = fp;
    strcpy(fcx->fname, fname );
    a->real_fname = xstrdup( fname );
    a->filter = file_filter;
    a->filter_ov = fcx;
    file_filter( fcx, IOBUFCTRL_DESC, NULL, (byte*)&a->desc, &len );
    file_filter( fcx, IOBUFCTRL_INIT, NULL, NULL, &len );
    if( DBG_IOBUF )
	log_debug("iobuf-%d.%d: openrw `%s'\n", a->no, a->subno, a->desc );

    return a;
}


int
iobuf_ioctl ( IOBUF a, int cmd, int intval, void *ptrval )
{
    if ( cmd == 1 ) {  /* keep system filepointer/descriptor open */
        if( DBG_IOBUF )
            log_debug("iobuf-%d.%d: ioctl `%s' keep=%d\n",
                      a? a->no:-1, a?a->subno:-1, a?a->desc:"?", intval );
        for( ; a; a = a->chain )
            if( !a->chain && a->filter == file_filter ) {
                file_filter_ctx_t *b = a->filter_ov;
                b->keep_open = intval;
                return 0;
            }
#ifdef _WIN32
            else if( !a->chain && a->filter == sock_filter ) {
                sock_filter_ctx_t *b = a->filter_ov;
                b->keep_open = intval;
                return 0;
            }
#endif
    }
    else if ( cmd == 2 ) {  /* invalidate cache */
        if( DBG_IOBUF )
            log_debug("iobuf-*.*: ioctl `%s' invalidate\n",
                      ptrval? (char*)ptrval:"[all]");
        if ( !a && !intval ) {
#ifndef FILE_FILTER_USES_STDIO
            fd_cache_invalidate (ptrval);
#endif
            return 0;
        }
    }
    else if ( cmd == 3 ) {  /* disallow/allow caching */
        if( DBG_IOBUF )
            log_debug("iobuf-%d.%d: ioctl `%s' no_cache=%d\n",
                      a? a->no:-1, a?a->subno:-1, a?a->desc:"?", intval );
        for( ; a; a = a->chain )
            if( !a->chain && a->filter == file_filter ) {
                file_filter_ctx_t *b = a->filter_ov;
                b->no_cache = intval;
                return 0;
            }
#ifdef _WIN32
            else if( !a->chain && a->filter == sock_filter ) {
                sock_filter_ctx_t *b = a->filter_ov;
                b->no_cache = intval;
                return 0;
            }
#endif
    }

    return -1;
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
    b = xmalloc(sizeof *b);
    memcpy(b, a, sizeof *b );
    /* fixme: it is stupid to keep a copy of the name at every level
     * but we need the name somewhere because the name known by file_filter
     * may have been released when we need the name of the file */
    b->real_fname = a->real_fname? xstrdup(a->real_fname):NULL;
    /* remove the filter stuff from the new stream */
    a->filter = NULL;
    a->filter_ov = NULL;
    a->filter_ov_owner = 0;
    a->filter_eof = 0;
    if( a->use == 3 )
	a->use = 2;  /* make a write stream from a temp stream */

    if( a->use == 2 ) { /* allocate a fresh buffer for the original stream */
	b->d.buf = xmalloc( a->d.size );
	b->d.len = 0;
	b->d.start = 0;
    }
    else { /* allocate a fresh buffer for the new stream */
	a->d.buf = xmalloc( a->d.size );
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
static int
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
	xfree(a->d.buf);
	xfree(a->real_fname);
	memcpy(a,b, sizeof *a);
	xfree(b);
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
	xfree( b->filter_ov );
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
	xfree(a->d.buf);
	xfree(a->real_fname);
	memcpy(a,b, sizeof *a);
	xfree(b);
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
	if( a->chain ) {
	    IOBUF b = a->chain;
	    if( DBG_IOBUF )
		log_debug("iobuf-%d.%d: pop `%s' in underflow\n",
					a->no, a->subno, a->desc );
	    xfree(a->d.buf);
	    xfree(a->real_fname);
	    memcpy(a, b, sizeof *a);
	    xfree(b);
	    print_chain(a);
	}
	else
             a->filter_eof = 0;  /* for the top level filter */
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
	if( DBG_IOBUF )
	    log_debug("iobuf-%d.%d: underflow: req=%lu\n",
                      a->no, a->subno, (ulong)len );
	rc = a->filter( a->filter_ov, IOBUFCTRL_UNDERFLOW, a->chain,
			a->d.buf, &len );
	if( DBG_IOBUF ) {
	    log_debug("iobuf-%d.%d: underflow: got=%lu rc=%d\n",
		    a->no, a->subno, (ulong)len, rc );
/*  	    if( a->no == 1 ) */
/*                   log_hexdump ("     data:", a->d.buf, len); */
	}
	if( a->use == 1 && rc == -1 ) { /* EOF: we can remove the filter */
	    size_t dummy_len=0;

	    /* and tell the filter to free itself */
	    if( (rc = a->filter(a->filter_ov, IOBUFCTRL_FREE, a->chain,
			       NULL, &dummy_len)) )
		log_error("IOBUFCTRL_FREE failed: %s\n", g10_errstr(rc) );
	    if( a->filter_ov && a->filter_ov_owner ) {
		xfree( a->filter_ov );
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
		xfree(a->d.buf);
		xfree(a->real_fname);
		memcpy(a,b, sizeof *a);
		xfree(b);
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

    if( a->use == 3 ) { /* increase the temp buffer */
	char *newbuf;
	size_t newsize = a->d.size + IOBUF_BUFFER_SIZE;

	if( DBG_IOBUF )
	  log_debug("increasing temp iobuf from %lu to %lu\n",
		    (ulong)a->d.size, (ulong)newsize );
	newbuf = xmalloc( newsize );
	memcpy( newbuf, a->d.buf, a->d.len );
	xfree(a->d.buf);
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
	xfree(a->unget.buf);
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
iobuf_set_limit( IOBUF a, off_t nlimit )
{
    if( nlimit )
	a->nofast |= 1;
    else
	a->nofast &= ~1;
    a->nlimit = nlimit;
    a->ntotal += a->nbytes;
    a->nbytes = 0;
}



/* Return the length of an open file A.  IF OVERFLOW is not NULL it
   will be set to true if the file is larger than what off_t can cope
   with.  The function return 0 on error or on overflow condition.  */
off_t
iobuf_get_filelength (IOBUF a, int *overflow )
{
    struct stat st;

    if (overflow)
      *overflow = 0;

    if( a->directfp )  {
	FILE *fp = a->directfp;

       if( !fstat(fileno(fp), &st) )
           return st.st_size;
	log_error("fstat() failed: %s\n", strerror(errno) );
	return 0;
    }

    /* Hmmm: file_filter may have already been removed */
    for( ; a; a = a->chain )
	if( !a->chain && a->filter == file_filter ) {
	    file_filter_ctx_t *b = a->filter_ov;
	    FILEP_OR_FD fp = b->fp;

#if defined(HAVE_DOSISH_SYSTEM) && !defined(FILE_FILTER_USES_STDIO)
            ulong size;
            static int (* __stdcall get_file_size_ex) 
              (void *handle, LARGE_INTEGER *size);
            static int get_file_size_ex_initialized;

            if (!get_file_size_ex_initialized)
              {
                void *handle;
                
                handle = dlopen ("kernel32.dll", RTLD_LAZY);
                if (handle)
                  {
                    get_file_size_ex = dlsym (handle, "GetFileSizeEx");
                    if (!get_file_size_ex)
                    dlclose (handle);
                  }
                get_file_size_ex_initialized = 1;
              }

            if (get_file_size_ex)
              {
                /* This is a newer system with GetFileSizeEx; we use
                   this then becuase it seem that GetFileSize won't
                   return a proper error in case a file is larger than
                   4GB. */
                LARGE_INTEGER size;
                
                if (get_file_size_ex (fp, &size))
                  {
                    if (!size.u.HighPart)
                      return size.u.LowPart;
                    if (overflow)
                      *overflow = 1;
                    return 0; 
                  }
              }
            else
              {
                if  ((size=GetFileSize (fp, NULL)) != 0xffffffff)
                  return size;
              }
            log_error ("GetFileSize for handle %p failed: %s\n",
                       fp, w32_strerror (0));
#else
            if( !fstat(my_fileno(fp), &st) )
		return st.st_size;
	    log_error("fstat() failed: %s\n", strerror(errno) );
#endif
	    break;
	}

    return 0;
}


/* Return the file descriptor of the underlying file or -1 if it is
   not available.  */
int 
iobuf_get_fd (IOBUF a)
{
  if (a->directfp)
    return fileno ( (FILE*)a->directfp );

  for ( ; a; a = a->chain )
    if (!a->chain && a->filter == file_filter)
      {
        file_filter_ctx_t *b = a->filter_ov;
        FILEP_OR_FD fp = b->fp;

        return my_fileno (fp);
      }

  return -1;
}


/****************
 * Tell the file position, where the next read will take place
 */
off_t
iobuf_tell( IOBUF a )
{
    return a->ntotal + a->nbytes;
}


#if !defined(HAVE_FSEEKO) && !defined(fseeko)

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifndef LONG_MAX
# define LONG_MAX ((long) ((unsigned long) -1 >> 1))
#endif
#ifndef LONG_MIN
# define LONG_MIN (-1 - LONG_MAX)
#endif

/****************
 * A substitute for fseeko, for hosts that don't have it.
 */
static int
fseeko( FILE *stream, off_t newpos, int whence )
{
    while( newpos != (long) newpos ) {
       long pos = newpos < 0 ? LONG_MIN : LONG_MAX;
       if( fseek( stream, pos, whence ) != 0 )
           return -1;
       newpos -= pos;
       whence = SEEK_CUR;
    }
    return fseek( stream, (long)newpos, whence );
}
#endif

/****************
 * This is a very limited implementation. It simply discards all internal
 * buffering and removes all filters but the first one.
 */
int
iobuf_seek( IOBUF a, off_t newpos )
{
    file_filter_ctx_t *b = NULL;

    if( a->directfp ) {
	FILE *fp = a->directfp;
        if( fseeko( fp, newpos, SEEK_SET ) ) {
            log_error("can't seek: %s\n", strerror(errno) );
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
#ifdef FILE_FILTER_USES_STDIO
       if( fseeko( b->fp, newpos, SEEK_SET ) ) {
           log_error("can't fseek: %s\n", strerror(errno) );
           return -1;
       }
#else
#ifdef HAVE_DOSISH_SYSTEM
       if (SetFilePointer (b->fp, newpos, NULL, FILE_BEGIN) == 0xffffffff ) {
           log_error ("SetFilePointer failed on handle %p: %s\n",
                      b->fp, w32_strerror (0));
           return -1;
       }
#else
       if ( lseek (b->fp, newpos, SEEK_SET) == (off_t)-1 ) {
           log_error("can't lseek: %s\n", strerror(errno) );
           return -1;
       }
#endif
#endif
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
 * enable partial block mode as described in the OpenPGP draft.
 * LEN is the first length byte on read, but ignored on writes.
 */
void
iobuf_set_partial_block_mode( IOBUF a, size_t len )
{
    block_filter_ctx_t *ctx = xmalloc_clear( sizeof *ctx );

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
	buffer = xmalloc( length );
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
	    buffer = xrealloc( buffer, length );
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

/* This is the non iobuf specific function */
int
iobuf_translate_file_handle ( int fd, int for_write )
{
#ifdef _WIN32
    {
        int x;
            
        if  ( fd <= 2 )
            return fd; /* do not do this for error, stdin, stdout, stderr */

        x = _open_osfhandle ( fd, for_write? 1:0 );
        if (x==-1 )
            log_error ("failed to translate osfhandle %p\n", (void*)fd );
        else {
            /*log_info ("_open_osfhandle %p yields %d%s\n",
              (void*)fd, x, for_write? " for writing":"" );*/
            fd = x;
        }
    }
#endif
    return fd;
}

static int
translate_file_handle ( int fd, int for_write )
{
#ifdef _WIN32
#ifdef FILE_FILTER_USES_STDIO  
    fd = iobuf_translate_file_handle (fd, for_write);
#else
    {
        int x;

        if  ( fd == 0 ) 
            x = (int)GetStdHandle (STD_INPUT_HANDLE);
        else if (fd == 1)    
            x = (int)GetStdHandle (STD_OUTPUT_HANDLE);
        else if (fd == 2)    
            x = (int)GetStdHandle (STD_ERROR_HANDLE);
        else
            x = fd;

        if (x == -1)
            log_debug ("GetStdHandle(%d) failed: %s\n",
                       fd, w32_strerror (0));

        fd = x;
    }
#endif
#endif
    return fd;
}


void
iobuf_skip_rest(IOBUF a, unsigned long n, int partial)
{
    if ( partial ) {
	for (;;) {
	    if (a->nofast || a->d.start >= a->d.len) {
		if (iobuf_readbyte (a) == -1) {
		    break;
		}
	    } else {
		unsigned long count = a->d.len - a->d.start;
		a->nbytes += count;
		a->d.start = a->d.len;
	    }
	}
    } else {
	unsigned long remaining = n;
	while (remaining > 0) {
	    if (a->nofast || a->d.start >= a->d.len) {
		if (iobuf_readbyte (a) == -1) {
		    break;
		}
		--remaining;
	    } else {
		unsigned long count = a->d.len - a->d.start;
		if (count > remaining) {
		    count = remaining;
		}
		a->nbytes += count;
		a->d.start += count;
		remaining -= count;
	    }
	}
    }
}
