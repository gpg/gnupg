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
#include "main.h"


/****************
 * Check the signature which is contained in the rsa_integer.
 * The md5handle should be currently open, so that this function
 * is able to append some data, before getting the digest.
 */
int
signature_check( PKT_signature *sig, MD_HANDLE digest )
{
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
    MPI result = NULL;
    int rc=0, i, j, c, old_enc;
    byte *dp;


    if( get_pubkey( pkc, sig->keyid ) ) {
	rc = G10ERR_NO_PUBKEY;
	goto leave;
    }

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	ELG_public_key pkey;

	if( (rc=check_digest_algo(sig->d.elg.digest_algo)) )
	    goto leave;
	/* complete the digest */
	md_putc( digest, sig->sig_class );
	{   u32 a = sig->timestamp;
	    md_putc( digest, (a >> 24) & 0xff );
	    md_putc( digest, (a >> 16) & 0xff );
	    md_putc( digest, (a >>  8) & 0xff );
	    md_putc( digest,  a        & 0xff );
	}
	md_final( digest );
	result = encode_md_value( digest, mpi_get_nbits(pkc->d.elg.p));
	pkey.p = pkc->d.elg.p;
	pkey.g = pkc->d.elg.g;
	pkey.y = pkc->d.elg.y;
	if( !elg_verify( sig->d.elg.a, sig->d.elg.b, result, &pkey ) )
	    rc = G10ERR_BAD_SIGN;
    }
 #ifdef HAVE_RSA_CIPHER
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	RSA_public_key pkey;

	result = mpi_alloc(40);
	pkey.n = pkc->d.rsa.rsa_n;
	pkey.e = pkc->d.rsa.rsa_e;
	rsa_public( result, sig->d.rsa.rsa_integer, &pkey );

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
	    static byte asn[15] = /* stored reverse */
		  { 0x14, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x24, 0x2b,
		    0x05, 0x06, 0x09, 0x30, 0x21, 0x30 };

	    for(i=20,j=0; (c=mpi_getbyte(result, i)) != -1 && j < 15; i++, j++ )
		if( asn[j] != c )
		    break;
	    if( j != 15 || mpi_getbyte(result, i) ) { /* ASN is wrong */
		rc = G10ERR_BAD_PUBKEY;
		goto leave;
	    }
	    for(i++; (c=mpi_getbyte(result, i)) != -1; i++ )
		if( c != 0xff  )
		    break;
	    i++;
	    if( c != DIGEST_ALGO_RMD160 || mpi_getbyte(result, i) ) {
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

	    /* complete the digest */
	    md_putc( digest, sig->sig_class );
	    {	u32 a = sig->timestamp;
		md_putc( digest, (a >> 24) & 0xff );
		md_putc( digest, (a >> 16) & 0xff );
		md_putc( digest, (a >>	8) & 0xff );
		md_putc( digest,  a	   & 0xff );
	    }
	    md_final( digest );
	    dp = md_read( digest, DIGEST_ALGO_RMD160 );
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
	    if( j != 18 || mpi_getbyte(result, i) ) { /* ASN is wrong */
		rc = G10ERR_BAD_PUBKEY;
		goto leave;
	    }
	    for(i++; (c=mpi_getbyte(result, i)) != -1; i++ )
		if( c != 0xff  )
		    break;
	    i++;
	    if( c != DIGEST_ALGO_MD5 || mpi_getbyte(result, i) ) {
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

	    /* complete the digest */
	    md_putc( digest, sig->sig_class );
	    {	u32 a = sig->timestamp;
		md_putc( digest, (a >> 24) & 0xff );
		md_putc( digest, (a >> 16) & 0xff );
		md_putc( digest, (a >>	8) & 0xff );
		md_putc( digest,  a	   & 0xff );
	    }
	    md_final( digest );
	    dp = md_read( digest, DIGEST_ALGO_MD5 );
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
    }
  #endif/*HAVE_RSA_CIPHER*/
    else {
	/*log_debug("signature_check: unsupported pubkey algo %d\n",
			pkc->pubkey_algo );*/
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }


  leave:
    if( pkc )
	free_public_cert( pkc );
    mpi_free( result );
    return rc;
}


/****************
 * check the signature pointed to by NODE. This is a key signatures
 */
int
check_key_signature( KBNODE root, KBNODE node, int *is_selfsig )
{
    KBNODE unode;
    MD_HANDLE md;
    PKT_public_cert *pkc;
    PKT_signature *sig;
    int algo;
    int rc;

    if( is_selfsig )
	*is_selfsig = 0;
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( (node->pkt->pkt.signature->sig_class&~3) == 0x10 );
    assert( root->pkt->pkttype == PKT_PUBLIC_CERT );

    pkc = root->pkt->pkt.public_cert;
    sig = node->pkt->pkt.signature;

    if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	algo = sig->d.elg.digest_algo;
    else if(sig->pubkey_algo == PUBKEY_ALGO_RSA )
	algo = sig->d.rsa.digest_algo;
    else
	return G10ERR_PUBKEY_ALGO;
    if( (rc=check_digest_algo(algo)) )
	return rc;

    unode = find_kbparent( root, node );

    if( unode && unode->pkt->pkttype == PKT_USER_ID ) {
	PKT_user_id *uid = unode->pkt->pkt.user_id;

	if( is_selfsig ) {
	    u32 keyid[2];

	    keyid_from_pkc( pkc, keyid );
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		*is_selfsig = 1;
	}
	md = md_open( algo, 0 );
	hash_public_cert( md, pkc );
	md_write( md, uid->name, uid->len );
	rc = signature_check( sig, md );
	md_close(md);
    }
    else {
	log_error("no user id for key signature packet\n");
	rc = G10ERR_SIG_CLASS;
    }

    return rc;
}


