/* mpicoder.c  -  Coder for the external representation of MPIs
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
#include <assert.h>

#include "mpi.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"

#ifdef M_DEBUG
  #undef mpi_decode
  #undef mpi_decode_buffer
#endif

#define MAX_EXTERN_MPI_BITS 16384

/****************
 * write an mpi to out.
 */
int
mpi_encode( IOBUF out, MPI a )
{
    u16 dummy;
    return mpi_encode_csum( out, a, &dummy );
}

int
mpi_encode_csum( IOBUF out, MPI a, u16 *csum )
{
    int i;
    byte c;
    unsigned nbits = a->nlimbs * BITS_PER_MPI_LIMB;
    mpi_limb_t limb;

#if BYTES_PER_MPI_LIMB != 4
  #error Make this function work with other LIMB sizes
#endif
    if( nbits > MAX_EXTERN_MPI_BITS )
	log_bug("mpi_encode: mpi too large (%u bits)\n", nbits);
    iobuf_put(out, (c=nbits >>8) ); *csum += c;
    iobuf_put(out, (c=nbits) );     *csum += c;
    for(i=a->nlimbs-1; i >= 0; i-- ) {
	limb = a->d[i];
	iobuf_put(out, (c=limb >> 24) ); *csum += c;
	iobuf_put(out, (c=limb >> 16) ); *csum += c;
	iobuf_put(out, (c=limb >>  8) ); *csum += c;
	iobuf_put(out, (c=limb	    ) ); *csum += c;
    }
    return 0;
}

/****************
 * encode the MPI into a newly allocated buffer, the buffer is
 * so constructed, that it can be used for mpi_write. The caller
 * must free the returned buffer. The buffer is allocated in the same
 * type of memory space as A is.
 */
byte *
mpi_encode_buffer( MPI a )
{
    abort();
    return NULL;
}

/****************
 * write an mpi to out. This is a special function to handle
 * encrypted values. It simply writes the buffer a to OUT.
 * A is a special buffer, starting with 2 bytes giving it's length
 * (in big endian order) and 2 bytes giving it's length in bits (also
 * big endian)
 */
int
mpi_write( IOBUF out, byte *a)
{
    u16 dummy;
    return mpi_write_csum( out, a, &dummy );
}

int
mpi_write_csum( IOBUF out, byte *a, u16 *csum)
{
    int rc;
    unsigned n;

    n = *a++ << 8;
    n |= *a++;
    rc = iobuf_write(out, a, n );
    for( ; n; n--, a++ )
	*csum += *a;
    return rc;
}

/****************
 * Decode an external representation and return an MPI
 * The external format is a 16 bit unsigned value stored in network byte order,
 * giving the number of bits for the following integer. The integer is stored
 * with MSB first (left padded with zeroes to align on a byte boundary).
 */
MPI
#ifdef M_DEBUG
mpi_debug_decode(IOBUF inp, unsigned *ret_nread, const char *info)
#else
mpi_decode(IOBUF inp, unsigned *ret_nread)
#endif
{
    int c, i, j;
    unsigned nbits, nbytes, nlimbs, nread=0;
    mpi_limb_t a;
    MPI val = MPI_NULL;

    if( (c = iobuf_get(inp)) == -1 )
	goto leave;
    nbits = c << 8;
    if( (c = iobuf_get(inp)) == -1 )
	goto leave;
    nbits |= c;
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	goto leave;
    }
    nread = 2;

    nbytes = (nbits+7) / 8;
    nlimbs = (nbytes+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB;
  #ifdef M_DEBUG
    val = mpi_debug_alloc( nlimbs, info );
  #else
    val = mpi_alloc( nlimbs );
  #endif
    i = BYTES_PER_MPI_LIMB - nbytes % BYTES_PER_MPI_LIMB;
    i %= BYTES_PER_MPI_LIMB;
    j= val->nlimbs = nlimbs;
    val->sign = 0;
    for( ; j > 0; j-- ) {
	a = 0;
	for(; i < BYTES_PER_MPI_LIMB; i++ ) {
	    a <<= 8;
	    a |= iobuf_get(inp) & 0xff; nread++;
	}
	i = 0;
	val->d[j-1] = a;
    }

  leave:
    if( nread > *ret_nread )
	log_error("Ooops: mpi crosses packet border");
    else
	*ret_nread = nread;
    return val;
}


/****************
 * Decode an MPI from the buffer, the buffer starts with two bytes giving
 * the length of the data to follow, the original data follows.
 * The MPI is alloced from secure MPI space
 */
MPI
#ifdef M_DEBUG
mpi_debug_decode_buffer(byte *buffer, const char *info )
#else
mpi_decode_buffer(byte *buffer )
#endif
{
    int i, j;
    u16 buflen;
    unsigned nbits, nbytes, nlimbs;
    mpi_limb_t a;
    byte *p = buffer;
    MPI val;

    if( !buffer )
	log_bug("mpi_decode_buffer: no buffer\n");
    buflen = *p++ << 8;
    buflen |= *p++;
    nbits = *p++ << 8;
    nbits |= *p++;
    nbytes = (nbits+7) / 8;
    if( nbytes+2 != buflen )
	log_bug("mpi_decode_buffer: length conflict\n");
    nlimbs = (nbytes+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB;
  #ifdef M_DEBUG
    val = mpi_debug_alloc_secure( nlimbs, info );
  #else
    val = mpi_alloc_secure( nlimbs );
  #endif
    i = BYTES_PER_MPI_LIMB - nbytes % BYTES_PER_MPI_LIMB;
    i %= BYTES_PER_MPI_LIMB;
    j= val->nlimbs = nlimbs;
    val->sign = 0;
    for( ; j > 0; j-- ) {
	a = 0;
	for(; i < BYTES_PER_MPI_LIMB; i++ ) {
	    a <<= 8;
	    a |= *p++;
	}
	i = 0;
	val->d[j-1] = a;
    }
    return val;
}


/****************
 * Read a MPI from the external medium and return it in a newly allocated
 * buffer (This buffer is allocated in the secure memory space, because
 * we properly need this to decipher this string).
 * Return: the allocated string and in RET_NREAD the number of bytes
 *	   read (including the 2 length bytes), the returned buffer will
 *	   be prefixed with two bytes describing the length of the following
 *	   data.
 */
byte *
mpi_read(IOBUF inp, unsigned *ret_nread)
{
    int c;
    u16 buflen;
    unsigned nbits, nbytes, nread;
    byte *p, *buf;

    if( (c = iobuf_get(inp)) == -1 )
	return NULL;
    nbits = c << 8;
    if( (c = iobuf_get(inp)) == -1 )
	return NULL;
    nbits |= c;
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	return NULL;
    }
    nread = 2;

    nbytes = (nbits+7) / 8;
    buflen = nbytes + 2;
    p = buf = m_alloc_secure( buflen+2 );
    *p++ = buflen >> 8;
    *p++ = buflen & 0xff;
    *p++ = nbits >> 8;
    *p++ = nbits & 0xff;
    for( ; nbytes ; nbytes--, nread++ )
	*p++ = iobuf_get(inp) & 0xff;

    if( nread > *ret_nread )
	log_error("Ooops: mpi crosses packet border");
    else
	*ret_nread = nread;
    return buf;
}


/****************
 * Make a mpi from a character string.
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
 * print an MPI to the give stream and return the number of characters
 * printed.
 */
int
mpi_print( FILE *fp, MPI a, int mode )
{
    int i, n=0;

    if( a == MPI_NULL )
	return fprintf(fp, "[MPI_NULL]");
    if( !mode )
	n += fprintf(fp, "[%d bits]", a->nlimbs * BITS_PER_MPI_LIMB );
    else {
	if( a->sign )
	    putc('-', fp);
	for(i=a->nlimbs; i > 0 ; i-- ) {
	    n += fprintf(fp, i!=a->nlimbs? "%0" STR2(BYTES_PER_MPI_LIMB2)
				"lX":"%lX", (unsigned long)a->d[i-1] );
	}
	if( !a->nlimbs )
	    putc('0', fp );
    }
    return n;
}


/****************
 * Special function to get the low 8 bytes from a mpi,
 * this can be used as a keyid, KEYID is an 2 element array.
 * Does return the low 4 bytes.
 */
u32
mpi_get_keyid( MPI a, u32 *keyid )
{
#if BYTES_PER_MPI_LIMB != 4
  #error Make this function work with other LIMB sizes
#endif
    if( keyid ) {
	keyid[0] = a->nlimbs >= 2? a->d[1] : 0;
	keyid[1] = a->nlimbs >= 1? a->d[0] : 0;
    }
    return a->nlimbs >= 1? a->d[0] : 0;
}


