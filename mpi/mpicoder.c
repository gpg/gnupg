/* mpicoder.c  -  Coder for the external representation of MPIs
 * Copyright (C) 1998, 1999, 2005 Free Software Foundation, Inc.
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
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "mpi.h"
#include "mpi-internal.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"

#ifdef M_DEBUG
#undef mpi_read
#endif

#define MAX_EXTERN_MPI_BITS 16384

/****************
 * write an mpi to out.
 */
int
mpi_write( IOBUF out, MPI a )
{
    int rc;
    unsigned nbits = mpi_get_nbits(a);
    byte *p, *buf;
    unsigned n;

    if( nbits > MAX_EXTERN_MPI_BITS )
	log_bug("mpi_encode: mpi too large (%u bits)\n", nbits);

    iobuf_put(out, (nbits >>8) );
    iobuf_put(out, (nbits) );

    p = buf = mpi_get_buffer( a, &n, NULL );
    rc = iobuf_write( out, p, n );
    xfree(buf);
    return rc;
}


/****************
 * Read an external representation of an mpi and return the MPI
 * The external format is a 16 bit unsigned value stored in network byte order,
 * giving the number of bits for the following integer. The integer is stored
 * with MSB first (left padded with zeroes to align on a byte boundary).
 */
MPI
#ifdef M_DEBUG
mpi_debug_read(IOBUF inp, unsigned *ret_nread, int secure, const char *info)
#else
mpi_read(IOBUF inp, unsigned *ret_nread, int secure)
#endif
{
    int c, i, j;
    unsigned int nmax = *ret_nread;
    unsigned nbits, nbytes, nlimbs, nread=0;
    mpi_limb_t a;
    MPI val = NULL;

    if (nread == nmax)
        goto overflow;
    if( (c = iobuf_get(inp)) == -1 )
	goto leave;
    nread++;
    nbits = c << 8;

    if (nread == nmax)
        goto overflow;
    if( (c = iobuf_get(inp)) == -1 )
	goto leave;
    nread++;
    nbits |= c;

    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large for this implementation (%u bits)\n", nbits);
	goto leave;
    }

    nbytes = (nbits+7) / 8;
    nlimbs = (nbytes+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB;
#ifdef M_DEBUG
    val = secure? mpi_debug_alloc_secure( nlimbs, info )
		: mpi_debug_alloc( nlimbs, info );
#else
    val = secure? mpi_alloc_secure( nlimbs )
		: mpi_alloc( nlimbs );
#endif
    i = BYTES_PER_MPI_LIMB - nbytes % BYTES_PER_MPI_LIMB;
    i %= BYTES_PER_MPI_LIMB;
    val->nbits = nbits;
    j= val->nlimbs = nlimbs;
    val->sign = 0;
    for( ; j > 0; j-- ) {
	a = 0;
	for(; i < BYTES_PER_MPI_LIMB; i++ ) {
            if (nread == nmax) {
#ifdef M_DEBUG
                mpi_debug_free (val);
#else
                mpi_free (val);
#endif
                val = NULL;
                goto overflow;
            }
	    a <<= 8;
	    a |= iobuf_get(inp) & 0xff; nread++;
	}
	i = 0;
	val->d[j-1] = a;
    }

  leave:
    *ret_nread = nread;
    return val;
  overflow:
    log_error ("mpi larger than indicated length (%u bytes)\n", nmax);
    *ret_nread = nread;
    return val;
}


MPI
mpi_read_from_buffer(byte *buffer, unsigned int *ret_nread, int secure)
{
    int i, j;
    unsigned nbits, nbytes, nlimbs, nread=0;
    mpi_limb_t a;
    MPI val = NULL;

    if( *ret_nread < 2 )
	goto leave;
    nbits = buffer[0] << 8 | buffer[1];
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_info ("mpi too large (%u bits)\n", nbits);
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
    val->nbits = nbits;
    j= val->nlimbs = nlimbs;
    val->sign = 0;
    for( ; j > 0; j-- ) {
	a = 0;
	for(; i < BYTES_PER_MPI_LIMB; i++ ) {
          if( ++nread > *ret_nread ) {
              /* This (as well as the above error condition) may
                 happen if we use this function to parse a decrypted
                 MPI which didn't turn out to be a real MPI - possible
                 because the supplied key was wrong but the OpenPGP
                 checksum didn't caught it. */
		log_info ("mpi larger than buffer\n");
                mpi_free (val);
                val = NULL;
                goto leave;
          }
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
 */
int
mpi_print( FILE *fp, MPI a, int mode )
{
    int i, n=0;

    if( a == NULL )
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
    FILE *fp = log_stream();

    g10_log_print_prefix(text);
    mpi_print(fp, a, 1 );
    fputc('\n', fp);
}

/****************
 * Special function to get the low 8 bytes from an mpi.
 * This can be used as a keyid; KEYID is an 2 element array.
 * Return the low 4 bytes.
 */
u32
mpi_get_keyid( MPI a, u32 *keyid )
{
#if BYTES_PER_MPI_LIMB == 4
    if( keyid ) {
	keyid[0] = a->nlimbs >= 2? a->d[1] : 0;
	keyid[1] = a->nlimbs >= 1? a->d[0] : 0;
    }
    return a->nlimbs >= 1? a->d[0] : 0;
#elif BYTES_PER_MPI_LIMB == 8
    if( keyid ) {
	keyid[0] = a->nlimbs? (u32)(a->d[0] >> 32) : 0;
	keyid[1] = a->nlimbs? (u32)(a->d[0] & 0xffffffff) : 0;
    }
    return a->nlimbs? (u32)(a->d[0] & 0xffffffff) : 0;
#else
#error Make this function work with other LIMB sizes
#endif
}


/****************
 * Return an xmalloced buffer with the MPI (msb first).
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
    unsigned int n;

    if( sign )
	*sign = a->sign;
    *nbytes = n = a->nlimbs * BYTES_PER_MPI_LIMB;
    if (!n)
      n++; /* avoid zero length allocation */
    p = buffer = force_secure || mpi_is_secure(a) ? xmalloc_secure(n)
						  : xmalloc(n);

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

    /* this is sub-optimal but we need to do the shift operation
     * because the caller has to free the returned buffer */
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
	alimb  = (mpi_limb_t)*p-- ;
	alimb |= (mpi_limb_t)*p-- <<  8 ;
	alimb |= (mpi_limb_t)*p-- << 16 ;
	alimb |= (mpi_limb_t)*p-- << 24 ;
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
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- <<  8 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 16 ;
	if( p >= buffer ) alimb |= (mpi_limb_t)*p-- << 24 ;
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
