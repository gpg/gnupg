/* misc.c -  miscellaneous functions
 *	Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
  #include <asm/sysinfo.h>
  #include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
  #include <sys/time.h>
  #include <sys/resource.h>
#endif
#include <assert.h>

#include <gcrypt.h>
#include "util.h"
#include "main.h"
#include "options.h"
#include "i18n.h"


#define MAX_EXTERN_MPI_BITS 16384

#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#warning using trap_unaligned
static int
setsysinfo(unsigned long op, void *buffer, unsigned long size,
		     int *start, void *arg, unsigned long flag)
{
    return syscall(__NR_osf_setsysinfo, op, buffer, size, start, arg, flag);
}

void
trap_unaligned(void)
{
    unsigned int buf[2];

    buf[0] = SSIN_UACPROC;
    buf[1] = UAC_SIGBUS | UAC_NOPRINT;
    setsysinfo(SSI_NVPAIRS, buf, 1, 0, 0, 0);
}
#else
void
trap_unaligned(void)
{  /* dummy */
}
#endif


void
disable_core_dumps()
{
 #ifndef HAVE_DOSISH_SYSTEM
  #ifdef HAVE_SETRLIMIT
    struct rlimit limit;

    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if( !setrlimit( RLIMIT_CORE, &limit ) )
	return;
    if( errno != EINVAL )
	log_fatal(_("can't disable core dumps: %s\n"), strerror(errno) );
  #endif
    if( !opt.quiet )
	log_info(_("WARNING: program may create a core file!\n"));
 #endif
}



/****************
 * write an mpi to out.
 */
int
mpi_write( IOBUF out, MPI a )
{
    char buffer[(MAX_EXTERN_MPI_BITS+7)/8];
    size_t nbytes;
    int rc;

    nbytes = (MAX_EXTERN_MPI_BITS+7)/8;
    rc = gcry_mpi_print( GCRYMPI_FMT_PGP, buffer, &nbytes, a );
    if( !rc )
	rc = iobuf_write( out, buffer, nbytes );

    return rc;
}

/****************
 * Writye a MPI to out, but in this case it is an opaque one,
 * s used vor v3 protected keys.
 */
int
mpi_write_opaque( IOBUF out, MPI a )
{
    size_t nbytes, nbits;
    int rc;
    char *p;

    assert( gcry_mpi_get_flag( a, GCRYMPI_FLAG_OPAQUE ) );
    p = gcry_mpi_get_opaque( a, &nbits );
    nbytes = (nbits+7) / 8;
    iobuf_put( out, nbits >> 8 );
    iobuf_put( out, nbits );
    rc = iobuf_write( out, p, nbytes );
    return rc;
}


/****************
 * Read an external representation of an mpi and return the MPI
 * The external format is a 16 bit unsigned value stored in network byte order,
 * giving the number of bits for the following integer. The integer is stored
 * with MSB first (left padded with zeroes to align on a byte boundary).
 */
MPI
mpi_read(IOBUF inp, unsigned int *ret_nread, int secure)
{
    int c, c1, c2, i;
    unsigned int nbits, nbytes, nread=0;
    MPI a = NULL;
    byte *buf = NULL;
    byte *p;

    if( (c = c1 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits = c << 8;
    if( (c = c2 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits |= c;
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	goto leave;
    }
    nread = 2;
    nbytes = (nbits+7) / 8;
    buf = secure? gcry_xmalloc_secure( nbytes+2 ) : gcry_xmalloc( nbytes+2 );
    p = buf;
    p[0] = c1;
    p[1] = c2;
    for( i=0 ; i < nbytes; i++ ) {
	p[i+2] = iobuf_get(inp) & 0xff;
	nread++;
    }
    nread += nbytes;
    if( gcry_mpi_scan( &a, GCRYMPI_FMT_PGP, buf, &nread ) )
	a = NULL;

  leave:
    gcry_free(buf);
    if( nread > *ret_nread )
	log_bug("mpi larger than packet");
    else
	*ret_nread = nread;
    return a;
}

/****************
 * Same as mpi_read but the value is stored as an opaque MPI.
 * This function is used to read encrypted MPI of v3 packets.
 */
GCRY_MPI
mpi_read_opaque(IOBUF inp, unsigned *ret_nread )
{
    int c, c1, c2, i;
    unsigned nbits, nbytes, nread=0;
    GCRY_MPI a = NULL;
    byte *buf = NULL;
    byte *p;

    if( (c = c1 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits = c << 8;
    if( (c = c2 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits |= c;
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	goto leave;
    }
    nread = 2;
    nbytes = (nbits+7) / 8;
    buf = gcry_xmalloc( nbytes );
    p = buf;
    for( i=0 ; i < nbytes; i++ ) {
	p[i] = iobuf_get(inp) & 0xff;
    }
    nread += nbytes;
    a = gcry_mpi_set_opaque(NULL, buf, nbits );
    buf = NULL;

  leave:
    gcry_free(buf);
    if( nread > *ret_nread )
	log_bug("mpi larger than packet");
    else
	*ret_nread = nread;
    return a;
}


int
mpi_print( FILE *fp, MPI a, int mode )
{
    int n=0;

    if( !a )
	return fprintf(fp, "[MPI_NULL]");
    if( !mode ) {
	unsigned int n1;
	n1 = gcry_mpi_get_nbits(a);
	n += fprintf(fp, "[%u bits]", n1);
    }
    else {
	int rc;
	char *buffer;

	rc = gcry_mpi_aprint( GCRYMPI_FMT_HEX, (void **)&buffer, NULL, a );
	assert( !rc );
	fputs( buffer, fp );
	n += strlen(buffer);
	gcry_free( buffer );
    }
    return n;
}



u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    a += n & 0xff;
    return a;
}

u16
checksum( byte *p, unsigned n )
{
    u16 a;

    for(a=0; n; n-- )
	a += *p++;
    return a;
}

u16
checksum_mpi( MPI a )
{
    int rc;
    u16 csum;
    byte *buffer;
    size_t nbytes;

    rc = gcry_mpi_print( GCRYMPI_FMT_PGP, NULL, &nbytes, a );
    assert( !rc );
    /* fixme: for numbers not in the suecre memory we
     * should use a stack based buffer and only allocate
     * a larger one when the mpi_print return an error
     */
    buffer = gcry_is_secure(a)? gcry_xmalloc_secure(nbytes) : gcry_xmalloc(nbytes);
    rc = gcry_mpi_print( GCRYMPI_FMT_PGP, buffer, &nbytes, a );
    assert( !rc );
    csum = checksum( buffer, nbytes );
    gcry_free( buffer );
    return csum;
}


u32
buffer_to_u32( const byte *buffer )
{
    unsigned long a;
    a =  *buffer << 24;
    a |= buffer[1] << 16;
    a |= buffer[2] << 8;
    a |= buffer[3];
    return a;
}


static void
no_exp_algo(void)
{
    static int did_note = 0;

    if( !did_note ) {
	did_note = 1;
	log_info(_("Experimental algorithms should not be used!\n"));
    }
}

void
print_pubkey_algo_note( int algo )
{
    if( algo >= 100 && algo <= 110 )
	no_exp_algo();
    else if( is_RSA( algo ) ) {
	static int did_note = 0;

	if( !did_note ) {
	    did_note = 1;
	    log_info(_("RSA keys are deprecated; please consider "
		       "creating a new key and use this key in the future\n"));
	}
    }
}

void
print_cipher_algo_note( int algo )
{
    if( algo >= 100 && algo <= 110 )
	no_exp_algo();
    else if(	algo == GCRY_CIPHER_3DES
	     || algo == GCRY_CIPHER_CAST5
	     || algo == GCRY_CIPHER_BLOWFISH
	     || algo == GCRY_CIPHER_TWOFISH
	   )
	;
    else {
	static int did_note = 0;

	if( !did_note ) {
	    did_note = 1;
	    log_info(_("this cipher algorithm is depreciated; "
		       "please use a more standard one!\n"));
	}
    }
}

void
print_digest_algo_note( int algo )
{
    if( algo >= 100 && algo <= 110 )
	no_exp_algo();
}



/****************
 * Wrapper around the libgcrypt function with addional checks on
 * openPGP contrainst for the algo ID.
 */
int
openpgp_cipher_test_algo( int algo )
{
    if( algo < 0 || algo > 110 )
	return GCRYERR_INV_CIPHER_ALGO;
    return gcry_cipher_test_algo(algo);
}

int
openpgp_pk_test_algo( int algo, unsigned int usage_flags )
{
    size_t n = usage_flags;

    if( algo < 0 || algo > 110 )
	return GCRYERR_INV_PK_ALGO;
    return gcry_pk_algo_info( algo, GCRYCTL_TEST_ALGO, NULL, &n );
}


int
openpgp_md_test_algo( int algo )
{
    if( algo < 0 || algo > 110 )
	return GCRYERR_INV_MD_ALGO;
    return gcry_md_test_algo(algo);
}


int
pubkey_get_npkey( int algo )
{
    int n = gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NPKEY, NULL, 0 );
    return n > 0? n : 0;
}

int
pubkey_get_nskey( int algo )
{
    int n = gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NSKEY, NULL, 0 );
    return n > 0? n : 0;
}

int
pubkey_get_nsig( int algo )
{
    int n = gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NSIGN, NULL, 0 );
    return n > 0? n : 0;
}

int
pubkey_get_nenc( int algo )
{
    int n = gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NENCR, NULL, 0 );
    return n > 0? n : 0;
}


unsigned int
pubkey_nbits( int algo, MPI *key )
{
    int rc, nbits;
    GCRY_SEXP sexp;

    if( algo == GCRY_PK_DSA ) {
	rc = gcry_sexp_build ( &sexp, NULL,
			      "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
				  key[0], key[1], key[2], key[3] );
    }
    else if( algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E ) {
	rc = gcry_sexp_build ( &sexp, NULL,
			      "(public-key(elg(p%m)(g%m)(y%m)))",
				  key[0], key[1], key[2] );
    }
    else if( algo == GCRY_PK_RSA ) {
	rc = gcry_sexp_build ( &sexp, NULL,
			      "(public-key(rsa(n%m)(e%m)))",
				  key[0], key[1] );
    }
    else
	return 0;

    if ( rc )
	BUG ();

    nbits = gcry_pk_get_nbits( sexp );
    gcry_sexp_release( sexp );
    return nbits;
}

