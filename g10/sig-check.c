/* sig-check.c -  Check a signature
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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


static int do_check( PKT_public_cert *pkc, PKT_signature *sig,
						MD_HANDLE digest );


/****************
 * Check the signature which is contained in the rsa_integer.
 * The md5handle should be currently open, so that this function
 * is able to append some data, before getting the digest.
 */
int
signature_check( PKT_signature *sig, MD_HANDLE digest )
{
    PKT_public_cert *pkc = m_alloc_clear( sizeof *pkc );
    int rc=0;

    if( get_pubkey( pkc, sig->keyid ) )
	rc = G10ERR_NO_PUBKEY;
    else
	rc = do_check( pkc, sig, digest );

    free_public_cert( pkc );
    return rc;
}


static int
do_check( PKT_public_cert *pkc, PKT_signature *sig, MD_HANDLE digest )
{
    MPI result = NULL;
    int rc=0;

    if( pkc->version == 4 && pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	log_info("WARNING: This is probably a PGP generated "
		 "ElGamal key which is NOT secure for signatures!\n");

    if( pkc->timestamp > sig->timestamp )
	return G10ERR_TIME_CONFLICT; /* pubkey newer that signature */

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	if( (rc=check_digest_algo(sig->digest_algo)) )
	    goto leave;
	/* make sure the digest algo is enabled (in case of a detached
	 * signature */
	md_enable( digest, sig->digest_algo );
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
	if( !elg_verify( sig->d.elg.a, sig->d.elg.b, result, &pkc->d.elg ) )
	    rc = G10ERR_BAD_SIGN;
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_DSA ) {
	if( (rc=check_digest_algo(sig->digest_algo)) )
	    goto leave;
	/* make sure the digest algo is enabled (in case of a detached
	 * signature */
	md_enable( digest, sig->digest_algo );

	/* complete the digest */
	if( sig->version >= 4 )
	    md_putc( digest, sig->version );
	md_putc( digest, sig->sig_class );
	if( sig->version < 4 ) {
	    u32 a = sig->timestamp;
	    md_putc( digest, (a >> 24) & 0xff );
	    md_putc( digest, (a >> 16) & 0xff );
	    md_putc( digest, (a >>  8) & 0xff );
	    md_putc( digest,  a        & 0xff );
	}
	else {
	    byte buf[6];
	    size_t n;
	    md_putc( digest, sig->pubkey_algo );
	    md_putc( digest, sig->digest_algo );
	    if( sig->hashed_data ) {
		n = (sig->hashed_data[0] << 8) | sig->hashed_data[1];
		md_write( digest, sig->hashed_data, n+2 );
		n += 6;
	    }
	    else
		n = 6;
	    /* add some magic */
	    buf[0] = sig->version;
	    buf[1] = 0xff;
	    buf[2] = n >> 24;
	    buf[3] = n >> 16;
	    buf[4] = n >>  8;
	    buf[5] = n;
	    md_write( digest, buf, 6 );
	}
	md_final( digest );
	result = mpi_alloc( (md_digest_length(sig->digest_algo)
			     +BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	mpi_set_buffer( result, md_read(digest, sig->digest_algo),
				md_digest_length(sig->digest_algo), 0 );
	if( DBG_CIPHER )
	    log_mpidump("calc sig frame: ", result);
	if( !dsa_verify( sig->d.dsa.r, sig->d.dsa.s, result, &pkc->d.dsa ) )
	    rc = G10ERR_BAD_SIGN;
    }
 #ifdef HAVE_RSA_CIPHER
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	int i, j, c, old_enc;
	byte *dp;
	const byte *asn;
	size_t mdlen, asnlen;

	result = mpi_alloc(40);
	rsa_public( result, sig->d.rsa.rsa_integer, &pkc->d.rsa );

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

	if( (rc=check_digest_algo(sig->digest_algo)) )
	    goto leave; /* unsupported algo */
	md_enable( digest, sig->digest_algo );
	asn = md_asn_oid( sig->digest_algo, &asnlen, &mdlen );

	for(i=mdlen,j=asnlen-1; (c=mpi_getbyte(result, i)) != -1 && j >= 0;
							       i++, j-- )
	    if( asn[j] != c )
		break;
	if( j != -1 || mpi_getbyte(result, i) ) { /* ASN is wrong */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}
	for(i++; (c=mpi_getbyte(result, i)) != -1; i++ )
	    if( c != 0xff  )
		break;
	i++;
	if( c != sig->digest_algo || mpi_getbyte(result, i) ) {
	    /* Padding or leading bytes in signature is wrong */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}
	if( mpi_getbyte(result, mdlen-1) != sig->digest_start[0]
	    || mpi_getbyte(result, mdlen-2) != sig->digest_start[1] ) {
	    /* Wrong key used to check the signature */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}

	/* complete the digest */
	md_putc( digest, sig->sig_class );
	{   u32 a = sig->timestamp;
	    md_putc( digest, (a >> 24) & 0xff );
	    md_putc( digest, (a >> 16) & 0xff );
	    md_putc( digest, (a >>  8) & 0xff );
	    md_putc( digest,  a        & 0xff );
	}
	md_final( digest );
	dp = md_read( digest, sig->digest_algo );
	for(i=mdlen-1; i >= 0; i--, dp++ ) {
	    if( mpi_getbyte( result, i ) != *dp ) {
		rc = G10ERR_BAD_SIGN;
		goto leave;
	    }
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
    mpi_free( result );
    return rc;
}


/****************
 * check the signature pointed to by NODE. This is a key signature.
 * If the function detects a self-signature, it uses the PKC from
 * NODE and does not read any public key.
 */
int
check_key_signature( KBNODE root, KBNODE node, int *is_selfsig )
{
    MD_HANDLE md;
    PKT_public_cert *pkc;
    PKT_signature *sig;
    int algo;
    int rc;

    if( is_selfsig )
	*is_selfsig = 0;
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( root->pkt->pkttype == PKT_PUBLIC_CERT );

    pkc = root->pkt->pkt.public_cert;
    sig = node->pkt->pkt.signature;

    if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	algo = sig->digest_algo;
    else if( sig->pubkey_algo == PUBKEY_ALGO_DSA )
	algo = sig->digest_algo;
    else if(sig->pubkey_algo == PUBKEY_ALGO_RSA )
	algo = sig->digest_algo;
    else
	return G10ERR_PUBKEY_ALGO;
    if( (rc=check_digest_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x20 ) {
	md = md_open( algo, 0 );
	hash_public_cert( md, pkc );
	rc = do_check( pkc, sig, md );
	md_close(md);
    }
    else if( sig->sig_class == 0x18 ) {
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBKEY_SUBCERT );

	if( snode ) {
	    md = md_open( algo, 0 );
	    hash_public_cert( md, pkc );
	    hash_public_cert( md, snode->pkt->pkt.public_cert );
	    rc = do_check( pkc, sig, md );
	    md_close(md);
	}
	else {
	    log_error("no subkey for key signature packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }
    else {
	KBNODE unode = find_prev_kbnode( root, node, PKT_USER_ID );

	if( unode ) {
	    PKT_user_id *uid = unode->pkt->pkt.user_id;
	    u32 keyid[2];

	    keyid_from_pkc( pkc, keyid );
	    md = md_open( algo, 0 );
	    hash_public_cert( md, pkc );
	    if( sig->version >=4 ) {
		byte buf[5];
		buf[0] = 0xb4; /* indicates a userid packet */
		buf[1] = uid->len >> 24;  /* always use 4 length bytes */
		buf[2] = uid->len >> 16;
		buf[3] = uid->len >>  8;
		buf[4] = uid->len;
		md_write( md, buf, 5 );
	    }
	    md_write( md, uid->name, uid->len );
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] ) {
		if( is_selfsig )
		    *is_selfsig = 1;
		rc = do_check( pkc, sig, md );
	    }
	    else
		rc = signature_check( sig, md );
	    md_close(md);
	}
	else {
	    log_error("no user id for key signature packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }

    return rc;
}


