/* mpicoder.c  -  Coder for the external representation of MPIs
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
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "mpi.h"
#include "mpi-internal.h"
#include "memory.h"
#include "g10lib.h"

#define MAX_EXTERN_MPI_BITS 16384


static MPI
mpi_read_from_buffer(byte *buffer, unsigned *ret_nread, int secure)
{
    int i, j;
    unsigned nbits, nbytes, nlimbs, nread=0;
    mpi_limb_t a;
    MPI val = MPI_NULL;

    if( *ret_nread < 2 )
	goto leave;
    nbits = buffer[0] << 8 | buffer[1];
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	goto leave;
    }
    buffer += 2;
    nread = 2;

    nbytes = (nbits+7) / 8;
    nlimbs = (nbytes+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB;
    val = secure? mpi_alloc_secure( nlimbs )
		: mpi_alloc( nlimbs );
    i = BYTES_PER_MPI_LIMB - nbytes % BYTES_PER_MPI_LIMB;
    i %= BYTES_PER_MPI_LIMB;
    j= val->nlimbs = nlimbs;
    val->sign = 0;
    for( ; j > 0; j-- ) {
	a = 0;
	for(; i < BYTES_PER_MPI_LIMB; i++ ) {
	    if( ++nread > *ret_nread )
		log_bug("mpi larger than buffer");
	    a <<= 8;
	    a |= *buffer++;
	}
	i = 0;
	val->d[j-1] = a;
    }

  leave:
    *ret_nread = nread;
    return val;
}


/****************
 * Make an mpi from a character string.
 */
int
mpi_fromstr(MPI val, const char *str)
{
    int hexmode=0, sign=0, prepend_zero=0, i, j, c, c1, c2;
    unsigned nbits, nbytes, nlimbs;
    mpi_limb_t a;

    if( *str == '-' ) {
	sign = 1;
	str++;
    }
    if( *str == '0' && str[1] == 'x' )
	hexmode = 1;
    else
	return 1; /* other bases are not yet supported */
    str += 2;

    nbits = strlen(str)*4;
    if( nbits % 8 )
	prepend_zero = 1;
    nbytes = (nbits+7) / 8;
    nlimbs = (nbytes+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB;
    if( val->alloced < nlimbs )
	mpi_resize(val, nlimbs );
    i = BYTES_PER_MPI_LIMB - nbytes % BYTES_PER_MPI_LIMB;
    i %= BYTES_PER_MPI_LIMB;
    j= val->nlimbs = nlimbs;
    val->sign = sign;
    for( ; j > 0; j-- ) {
	a = 0;
	for(; i < BYTES_PER_MPI_LIMB; i++ ) {
	    if( prepend_zero ) {
		c1 = '0';
		prepend_zero = 0;
	    }
	    else
		c1 = *str++;
	    assert(c1);
	    c2 = *str++;
	    assert(c2);
	    if( c1 >= '0' && c1 <= '9' )
		c = c1 - '0';
	    else if( c1 >= 'a' && c1 <= 'f' )
		c = c1 - 'a' + 10;
	    else if( c1 >= 'A' && c1 <= 'F' )
		c = c1 - 'A' + 10;
	    else {
		mpi_clear(val);
		return 1;
	    }
	    c <<= 4;
	    if( c2 >= '0' && c2 <= '9' )
		c |= c2 - '0';
	    else if( c2 >= 'a' && c2 <= 'f' )
		c |= c2 - 'a' + 10;
	    else if( c2 >= 'A' && c2 <= 'F' )
		c |= c2 - 'A' + 10;
	    else {
		mpi_clear(val);
		return 1;
	    }
	    a <<= 8;
	    a |= c;
	}
	i = 0;
	val->d[j-1] = a;
    }

    return 0;
}


/****************
 * print an MPI to the given stream and return the number of characters
 * printed.
 * FIXME: Replace this by the more generic gcry_mpi_print()
 */
static int
mpi_print( FILE *fp, MPI a, int mode )
{
    int i, n=0;

    if( a == MPI_NULL )
	return fprintf(fp, "[MPI_NULL]");
    if( !mode ) {
	unsigned int n1;
	n1 = mpi_get_nbits(a);
	n += fprintf(fp, "[%u bits]", n1);
    }
    else {
	if( a->sign )
	    putc('-', fp);
       #if BYTES_PER_MPI_LIMB == 2
	  #define X "4"
       #elif BYTES_PER_MPI_LIMB == 4
	  #define X "8"
       #elif BYTES_PER_MPI_LIMB == 8
	  #define X "16"
       #else
	  #error please define the format here
       #endif
	for(i=a->nlimbs; i > 0 ; i-- ) {
	    n += fprintf(fp, i!=a->nlimbs? "%0" X "lX":"%lX", (ulong)a->d[i-1]);
       #undef X
	}
	if( !a->nlimbs )
	    putc('0', fp );
    }
    return n;
}


void
g10_log_mpidump( const char *text, MPI a )
{
    FILE *fp = stderr; /* used to be log_stream() */

    /* FIXME: Replace this function by a g10_log_xxx one */
    fprintf(fp,"%s: ",text);
    mpi_print(fp, a, 1 );
    fputc('\n', fp);
}



/****************
 * Return an m_alloced buffer with the MPI (msb first).
 * NBYTES receives the length of this buffer. Caller must free the
 * return string (This function does return a 0 byte buffer with NBYTES
 * set to zero if the value of A is zero. If sign is not NULL, it will
 * be set to the sign of the A.
 */
static byte *
do_get_buffer( MPI a, unsigned *nbytes, int *sign, int force_secure )
{
    byte *p, *buffer;
    mpi_limb_t alimb;
    int i;

    if( sign )
	*sign = a->sign;
    *nbytes = a->nlimbs * BYTES_PER_MPI_LIMB;
    p = buffer = force_secure || mpi_is_secure(a) ? g10_xmalloc_secure( *nbytes)
						  : g10_xmalloc( *nbytes );

    for(i=a->nlimbs-1; i >= 0; i-- ) {
	alimb = a->d[i];
      #if BYTES_PER_MPI_LIMB == 4
	*p++ = alimb >> 24;
	*p++ = alimb >> 16;
	*p++ = alimb >>  8;
	*p++ = alimb	  ;
      #elif BYTES_PER_MPI_LIMB == 8
	*p++ = alimb >> 56;
	*p++ = alimb >> 48;
	*p++ = alimb >> 40;
	*p++ = alimb >> 32;
	*p++ = alimb >> 24;
	*p++ = alimb >> 16;
	*p++ = alimb >>  8;
	*p++ = alimb	  ;
      #else
	#error please implement for this limb size.
      #endif
    }

    /* this is sub-optimal but we need to do the shift oepration because
     * the caller has to free the returned buffer */
    for(p=buffer; !*p && *nbytes; p++, --*nbytes )
	;
    if( p != buffer )
	memmove(buffer,p, *nbytes);
    return buffer;
}


byte *
mpi_get_buffer( MPI a, unsigned *nbytes, int *sign )
{
    return do_get_buffer( a, nbytes, sign, 0 );
}

byte *
mpi_get_secure_buffer( MPI a, unsigned *nbytes, int *sign )
{
    return do_get_buffer( a, nbytes, sign, 1 );
}

/****************
 * Use BUFFER to update MPI.
 */
void
mpi_set_buffer( MPI a, const byte *buffer, unsigned nbytes, int sign )
{
    const byte *p;
    mpi_limb_t alimb;
    int nlimbs;
    int i;

    nlimbs = (nbytes + BYTES_PER_MPI_LIMB - 1) / BYTES_PER_MPI_LIMB;
    RESIZE_IF_NEEDED(a, nlimbs);
    a->sign = sign;

    for(i=0, p = buffer+nbytes-1; p >= buffer+BYTES_PER_MPI_LIMB; ) {
      #if BYTES_PER_MPI_LIMB == 4
	alimb  = *p--	    ;
	alimb |= *p-- <<  8 ;
	alimb |= *p-- << 16 ;
	alimb |= *p-- << 24 ;
      #elif BYTES_PER_MPI_LIMB == 8
	alimb  = (mpi_limb_t)*p--	;
	alimb |= (mpi_limb_t)*p-- <<  8 ;
	alimb |= (mpi_limb_t)*p-- << 16 ;
	alimb |= (mpi_limb_t)*p-- << 24 ;
	alimb |= (mpi_limb_t)*p-- << 32 ;
	alimb |= (mpi_limb_t)*p-- << 40 ;
	alimb |= (mpi_limb_t)*p-- << 48 ;
	alimb |= (mpi_limb_t)*p-- << 56 ;
      #else
	#error please implement for this limb size.
      #endif
	a->d[i++] = alimb;
    }
    if( p >= buffer ) {
      #if BYTES_PER_MPI_LIMB == 4
	alimb  = *p--	    ;
	if( p >= buffer ) alimb |= *p-- <<  8 ;
	if( p >= buffer ) alimb |= *p-- << 16 ;
	if( p >= buffer ) alimb |= *p-- << 24 ;
      #elif BYTES_PER_MPI_LIMB == 8
	alimb  = (mpi_limb_t)*p-- ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- <<	8 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 16 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 24 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 32 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 40 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 48 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 56 ;
      #else
	#error please implement for this limb size.
      #endif
	a->d[i++] = alimb;
    }
    a->nlimbs = i;
    assert( i == nlimbs );
}



int
gcry_mpi_scan( struct gcry_mpi **ret_mpi, enum gcry_mpi_format format,
		const char *buffer, size_t *nbytes )
{
    struct gcry_mpi *a = NULL;
    unsigned int len;

    len = nbytes? *nbytes : strlen(buffer);

    /* TODO: add a way to allocate the MPI in secure memory
     * Hmmm: maybe it is better to retrieve this information from
     * the provided buffer. */
     #warning secure memory is not used here.
    if( format == GCRYMPI_FMT_STD ) {
	const byte *s = buffer;

	a = mpi_alloc( (len+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	if( len ) { /* not zero */
	    a->sign = *s & 0x80;
	    if( a->sign ) {
		/* FIXME: we have to convert from 2compl to magnitude format */
		mpi_free(a);
		return GCRYERR_INTERNAL;
	    }
	    else
		mpi_set_buffer( a, s, len, 0 );
	}
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else if( format == GCRYMPI_FMT_USG ) {
	a = mpi_alloc( (len+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	if( len )  /* not zero */
	    mpi_set_buffer( a, buffer, len, 0 );
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else if( format == GCRYMPI_FMT_PGP ) {
	a = mpi_read_from_buffer( (char*)buffer, &len, 0 );
	if( nbytes )
	    *nbytes = len;
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return a? 0 : GCRYERR_INV_OBJ;
    }
    else if( format == GCRYMPI_FMT_SSH ) {
	const byte *s = buffer;
	size_t n;

	if( len < 4 )
	    return GCRYERR_TOO_SHORT;
	n = s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3];
	s += 4; len -= 4;
	if( n > len )
	    return GCRYERR_TOO_LARGE; /* or should it be too_short */

	a = mpi_alloc( (n+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	if( len ) { /* not zero */
	    a->sign = *s & 0x80;
	    if( a->sign ) {
		/* FIXME: we have to convert from 2compl to magnitude format */
		mpi_free(a);
		return GCRYERR_INTERNAL;
	    }
	    else
		mpi_set_buffer( a, s, n, 0 );
	}
	if( nbytes )
	    *nbytes = n+4;
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else if( format == GCRYMPI_FMT_HEX ) {
	if( nbytes )
	    return GCRYERR_INV_ARG; /* can only handle C strings for now */
	a = mpi_alloc(0);
	if( mpi_fromstr( a, buffer ) )
	    return GCRYERR_INV_OBJ;
	if( ret_mpi )
	    *ret_mpi = a;
	else
	    mpi_free(a);
	return 0;
    }
    else
	return GCRYERR_INV_ARG;
}

/****************
 * Write a using format into buffer which has a length of *NBYTES.
 * Returns the number of bytes actually written in nbytes.
 * Buffer maybe NULL to query the required length of the buffer
 */
int
gcry_mpi_print( enum gcry_mpi_format format, char *buffer, size_t *nbytes,
		 struct gcry_mpi *a )
{
    unsigned int nbits = mpi_get_nbits(a);
    size_t len;

    if( !nbytes )
	return GCRYERR_INV_ARG;

    len = *nbytes;
    *nbytes = 0;
    if( format == GCRYMPI_FMT_STD ) {
	char *tmp;
	int extra = 0;
	unsigned int n;

	if( a->sign )
	    return GCRYERR_INTERNAL; /* can't handle it yet */

	tmp = mpi_get_buffer( a, &n, NULL );
	if( n && (*tmp & 0x80) ) {
	    n++;
	    extra=1;
	}

	if( n > len && buffer ) {
	    g10_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	if( buffer ) {
	    byte *s = buffer;
	    if( extra )
		*s++ = 0;

	    memcpy( s, tmp, n-extra );
	}
	g10_free(tmp);
	*nbytes = n;
	return 0;
    }
    else if( format == GCRYMPI_FMT_USG ) {
	unsigned int n = (nbits + 7)/8;

	/* we ignore the sign for this format */
	/* FIXME: for performance reasons we should put this into
	 * mpi_aprint becuase we can then use the buffer directly */
	if( n > len && buffer )
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	if( buffer ) {
	    char *tmp;
	    tmp = mpi_get_buffer( a, &n, NULL );
	    memcpy( buffer, tmp, n );
	    g10_free(tmp);
	}
	*nbytes = n;
	return 0;
    }
    else if( format == GCRYMPI_FMT_PGP ) {
	unsigned int n = (nbits + 7)/8;

	if( a->sign )
	    return GCRYERR_INV_ARG; /* pgp format can only handle unsigned */

	if( n+2 > len && buffer )
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	if( buffer ) {
	    char *tmp;
	    byte *s = buffer;
	    s[0] = nbits >> 8;
	    s[1] = nbits;

	    tmp = mpi_get_buffer( a, &n, NULL );
	    memcpy( s+2, tmp, n );
	    g10_free(tmp);
	}
	*nbytes = n+2;
	return 0;
    }
    else if( format == GCRYMPI_FMT_SSH ) {
	char *tmp;
	int extra = 0;
	unsigned int n;

	if( a->sign )
	    return GCRYERR_INTERNAL; /* can't handle it yet */

	tmp = mpi_get_buffer( a, &n, NULL );
	if( n && (*tmp & 0x80) ) {
	    n++;
	    extra=1;
	}

	if( n+4 > len && buffer ) {
	    g10_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	if( buffer ) {
	    byte *s = buffer;
	    *s++ = n >> 24;
	    *s++ = n >> 16;
	    *s++ = n >> 8;
	    *s++ = n;
	    if( extra )
		*s++ = 0;

	    memcpy( s, tmp, n-extra );
	}
	g10_free(tmp);
	*nbytes = 4+n;
	return 0;
    }
    else if( format == GCRYMPI_FMT_HEX ) {
	byte *tmp;
	int i;
	int extra = 0;
	unsigned int n=0;

	tmp = mpi_get_buffer( a, &n, NULL );
	if( !n || (*tmp & 0x80) )
	    extra=2;

	if( 2*n + extra + !!a->sign + 1 > len && buffer ) {
	    g10_free(tmp);
	    return GCRYERR_TOO_SHORT;  /* the provided buffer is too short */
	}
	if( buffer ) {
	    byte *s = buffer;
	    if( a->sign )
		*s++ = '-';
	    if( extra ) {
		*s++ = '0';
		*s++ = '0';
	    }

	    for(i=0; i < n; i++ ) {
		unsigned int c = tmp[i];
		*s++ = (c >> 4) < 10? '0'+(c>>4) : 'A'+(c>>4)-10 ;
		c &= 15;
		*s++ = c < 10? '0'+c : 'A'+c-10 ;
	    }
	    *s++ = 0;
	    *nbytes = (char*)s - buffer;
	}
	else {
	    *nbytes = 2*n + extra + !!a->sign + 1;
	}
	g10_free(tmp);
	return 0;
    }
    else
	return GCRYERR_INV_ARG;
}

/****************
 * Like gcry_mpi_print but this function allocates the buffer itself.
 * The caller has to supply the address of a pointer. nbytes may be
 * NULL.
 */
int
gcry_mpi_aprint( enum gcry_mpi_format format, void **buffer, size_t *nbytes,
		 struct gcry_mpi *a )
{
    size_t n;
    int rc;

    *buffer = NULL;
    rc = gcry_mpi_print( format, NULL, &n, a );
    if( rc )
	return rc;
    *buffer = mpi_is_secure(a) ? g10_xmalloc_secure( n ) : g10_xmalloc( n );
    rc = gcry_mpi_print( format, *buffer, &n, a );
    if( rc ) {
	g10_free(*buffer);
	*buffer = NULL;
    }
    else if( nbytes )
	*nbytes = n;
    return rc;
}


