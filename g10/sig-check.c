/* sig-check.c -  Check a signature
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
#include <assert.h>
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "mpi.h"
#include "keydb.h"
#include "cipher.h"


/****************
 * Check the signature which is contained in the rsa_integer.
 * The md5handle should be currently open, so that this function
 * is able to append some data, before getting the digest.
 */
int
signature_check( PKT_signature *sig, MD_HANDLE digest )
{
    PKT_pubkey_cert *pkc = m_alloc_clear( sizeof *pkc );
    MPI result = mpi_alloc(35);
    int rc=0, i, j, c, old_enc;
    byte *dp;


    if( get_pubkey( pkc, sig->keyid ) ) {
	rc = G10ERR_NO_PUBKEY;
	goto leave;
    }

    if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	RSA_public_key pkey;
	pkey.n = pkc->d.rsa.rsa_n;
	pkey.e = pkc->d.rsa.rsa_e;
	rsa_public( result, sig->d.rsa.rsa_integer, &pkey );
    }
    else {
	log_debug("signature_check: unsupported pubkey algo %d\n",
			pkc->pubkey_algo );
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }


    /* Now RESULT contains the deciphered session key.
     *
     * The session key is stored in different ways:
     *
     * Old versions encodes the digest in in this format (msb is left):
     *
     *	   0  1  MD5(16 bytes)	0  PAD(n bytes)  1
     *
     * Later versions encodes the digest like this:
     *
     *	   0  1  PAD(n bytes)	0  ASN(18 bytes)  MD(16 bytes)
     *
     * RIPE MD 160 digests are encoded like this:
     *
     *	   0  42 PAD(n bytes)	0  ASN(18 bytes)  MD(20 bytes)
     *
     * FIXME: we should use another ASN!
     *
     * PAD consists of FF bytes.
     * ASN is here the constant: 3020300c06082a864886f70d020505000410
     */
    old_enc = 0;
    for(i=j=0; (c=mpi_getbyte(result, i)) != -1; i++ ) {
	if( !j ) {
	    if( !i && c != 1 )
		break;
	    else if( i && c == 0xff )
		; /* skip the padding */
	    else if( i && !c )
		j++;
	    else
		break;
	}
	else if( ++j == 18 && c != 1 )
	    break;
	else if( j == 19 && c == 0 ) {
	    old_enc++;
	    break;
	}
    }
    if( old_enc ) {
	log_error("old encoding scheme is not supported\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    if( sig->d.rsa.digest_algo == DIGEST_ALGO_RMD160 ) {
	static byte asn[18] = /* stored reverse FIXME: need other values*/
	      { 0x10, 0x04, 0x00, 0x05, 0x05, 0x02, 0x0d, 0xf7, 0x86,
		0x48, 0x86, 0x2a, 0x08, 0x06, 0x0c, 0x30, 0x20, 0x30 };

	for(i=20,j=0; j < 18 && (c=mpi_getbyte(result, i)) != -1; i++, j++ )
	    if( asn[j] != c )
		break;
	if( j != 18 ) { /* ASN is wrong */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}
	if( !c ) {
	    for(; (c=mpi_getbyte(result, i)) != -1; i++ )
		if( c != 0xff  )
		    break;
	    if( c != 42 || mpi_getbyte(result, i) ) {
		/* Padding or leading bytes in signature is wrong */
		rc = G10ERR_BAD_PUBKEY;
		goto leave;
	    }
	    if( mpi_getbyte(result, 19) != sig->d.rsa.digest_start[0]
		|| mpi_getbyte(result, 18) != sig->d.rsa.digest_start[1] ) {
		/* Wrong key used to check the signature */
		rc = G10ERR_BAD_PUBKEY;
		goto leave;
	    }
	}

	/* complete the digest */
	rmd160_putchar( digest.u.rmd, sig->sig_class );
	{   u32 a = sig->timestamp;
	    rmd160_putchar( digest.u.rmd, (a >> 24) & 0xff );
	    rmd160_putchar( digest.u.rmd, (a >> 16) & 0xff );
	    rmd160_putchar( digest.u.rmd, (a >>  8) & 0xff );
	    rmd160_putchar( digest.u.rmd,  a	    & 0xff );
	}
	dp = rmd160_final( digest.u.rmd );
	for(i=19; i >= 0; i--, dp++ )
	    if( mpi_getbyte( result, i ) != *dp ) {
		rc = G10ERR_BAD_SIGN;
		goto leave;
	    }
    }
    else if( sig->d.rsa.digest_algo == DIGEST_ALGO_MD5 ) {
	static byte asn[18] = /* stored reverse */
	      { 0x10, 0x04, 0x00, 0x05, 0x05, 0x02, 0x0d, 0xf7, 0x86,
		0x48, 0x86, 0x2a, 0x08, 0x06, 0x0c, 0x30, 0x20, 0x30 };

	for(i=16,j=0; j < 18 && (c=mpi_getbyte(result, i)) != -1; i++, j++ )
	    if( asn[j] != c )
		break;
	if( j != 18 ) { /* ASN is wrong */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}
	if( !c ) {
	    for(; (c=mpi_getbyte(result, i)) != -1; i++ )
		if( c != 0xff  )
		    break;
	    if( c != 1 || mpi_getbyte(result, i) ) {
		/* Padding or leading bytes in signature is wrong */
		rc = G10ERR_BAD_PUBKEY;
		goto leave;
	    }
	    if( mpi_getbyte(result, 15) != sig->d.rsa.digest_start[0]
		|| mpi_getbyte(result, 14) != sig->d.rsa.digest_start[1] ) {
		/* Wrong key used to check the signature */
		rc = G10ERR_BAD_PUBKEY;
		goto leave;
	    }
	}

	/* complete the digest */
	md5_putchar( digest.u.md5, sig->sig_class );
	{   u32 a = sig->timestamp;
	    md5_putchar( digest.u.md5, (a >> 24) & 0xff );
	    md5_putchar( digest.u.md5, (a >> 16) & 0xff );
	    md5_putchar( digest.u.md5, (a >>  8) & 0xff );
	    md5_putchar( digest.u.md5,	a	 & 0xff );
	}
	md5_final( digest.u.md5 );
	dp = md5_read( digest.u.md5 );
	for(i=15; i >= 0; i--, dp++ )
	    if( mpi_getbyte( result, i ) != *dp ) {
		rc = G10ERR_BAD_SIGN;
		goto leave;
	    }
    }
    else {
	rc = G10ERR_DIGEST_ALGO;
	goto leave;
    }

  leave:
    mpi_free( result );
    if( pkc )
	free_pubkey_cert( pkc );
    return rc;
}

