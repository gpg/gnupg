/* pubkey-enc.c -  public key encoded packet handling
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
#include <assert.h>

#include <gcrypt.h>
#include "util.h"
#include "packet.h"
#include "keydb.h"
#include "trustdb.h"
#include "status.h"
#include "options.h"
#include "main.h"
#include "i18n.h"

static int get_it( PKT_pubkey_enc *k,
		   DEK *dek, PKT_secret_key *sk, u32 *keyid );


/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
static int
pk_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    GCRY_SEXP s_skey, s_data, s_plain;
    int rc;

    *result = NULL;
    /* make a sexp from skey */
    if( algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E ) {
	rc = gcry_sexp_build ( &s_skey, NULL,
			      "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
				  skey[0], skey[1], skey[2], skey[3] );
    }
    else if( algo == GCRY_PK_RSA ) {
	rc = gcry_sexp_build ( &s_skey, NULL,
		    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
		     skey[0], skey[1], skey[2], skey[3], skey[4], skey[5] );
    }
    else
	return GPGERR_PUBKEY_ALGO;

    if ( rc )
	BUG ();

    /* put data into a S-Exp s_data */
    if( algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E ) {
	rc = gcry_sexp_build ( &s_data, NULL,
			       "(enc-val(elg(a%m)(b%m)))", data[0], data[1] );
    }
    else if( algo == GCRY_PK_RSA ) {
	rc = gcry_sexp_build ( &s_data, NULL,
			       "(enc-val(rsa(a%m)))", data[0] );
    }
    else
	BUG();

    if ( rc )
	BUG ();

    rc = gcry_pk_decrypt( &s_plain, s_data, s_skey );
    gcry_sexp_release( s_skey );
    gcry_sexp_release( s_data);
    if( rc )
	return rc;

    *result = gcry_sexp_nth_mpi( s_plain, 0, 0 );
    gcry_sexp_release( s_plain );
    if( !*result )
	return -1; /* oops */

    return 0;
}


/****************
 * Get the session key from a pubkey enc paket and return
 * it in DEK, which should have been allocated in secure memory.
 */
int
get_session_key( PKT_pubkey_enc *k, DEK *dek )
{
    PKT_secret_key *sk = NULL;
    int rc;

    if( is_RSA(k->pubkey_algo) ) /* warn about that */
	write_status(STATUS_RSA_OR_IDEA);

    rc = openpgp_pk_test_algo( k->pubkey_algo, 0 );
    if( rc )
	goto leave;

    if( k->keyid[0] || k->keyid[1] ) {
	sk = gcry_xcalloc( 1, sizeof *sk );
	sk->pubkey_algo = k->pubkey_algo; /* we want a pubkey with this algo*/
	if( !(rc = get_seckey( sk, k->keyid )) )
	    rc = get_it( k, dek, sk, k->keyid );
    }
    else { /* anonymous receiver: Try all available secret keys */
	void *enum_context = NULL;
	u32 keyid[2];

	for(;;) {
	    if( sk )
		free_secret_key( sk );
	    sk = gcry_xcalloc( 1, sizeof *sk );
	    rc=enum_secret_keys( &enum_context, sk, 1);
	    if( rc ) {
		rc = GPGERR_NO_SECKEY;
		break;
	    }
	    if( sk->pubkey_algo != k->pubkey_algo )
		continue;
	    keyid_from_sk( sk, keyid );
	    log_info(_("anonymous receiver; trying secret key %08lX ...\n"),
				     (ulong)keyid[1] );
	    rc = check_secret_key( sk, 1 ); /* ask only once */
	    if( !rc )
		rc = get_it( k, dek, sk, keyid );
	    if( !rc ) {
		log_info(_("okay, we are the anonymous recipient.\n") );
		break;
	    }
	}
	enum_secret_keys( &enum_context, NULL, 0 ); /* free context */
    }

  leave:
    if( sk )
	free_secret_key( sk );
    return rc;
}


static int
get_it( PKT_pubkey_enc *k, DEK *dek, PKT_secret_key *sk, u32 *keyid )
{
    int rc;
    MPI plain_dek  = NULL;
    byte *frame = NULL;
    unsigned int n;
    size_t nframe;
    u16 csum, csum2;

    rc = pk_decrypt(sk->pubkey_algo, &plain_dek, k->data, sk->skey );
    if( rc )
	goto leave;
    if( gcry_mpi_aprint( GCRYMPI_FMT_USG, &frame, &nframe, plain_dek ) )
	BUG();

    mpi_release( plain_dek ); plain_dek = NULL;

    /* Now get the DEK (data encryption key) from the frame
     *
     * Old versions encode the DEK in in this format (msb is left):
     *
     *	   0  1  DEK(16 bytes)	CSUM(2 bytes)  0  RND(n bytes) 2
     *
     * Later versions encode the DEK like this:
     *
     *	   0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
     *
     * (mpi_get_buffer already removed the leading zero - still true
     *	for gcry_mpi_aprint(0 which is used now?)
     *
     * RND are non-zero randow bytes.
     * A   is the cipher algorithm
     * DEK is the encryption key (session key) with length k
     * CSUM
     */
    if( DBG_CIPHER )
	log_hexdump("DEK frame:", frame, nframe );
    n=0;
    if( n + 7 > nframe )
	{ rc = GPGERR_WRONG_SECKEY; goto leave; }
    if( frame[n] == 1 && frame[nframe-1] == 2 ) {
	log_info(_("old encoding of the DEK is not supported\n"));
	rc = GPGERR_CIPHER_ALGO;
	goto leave;
    }
    if( frame[n] != 2 )  /* somethink is wrong */
	{ rc = GPGERR_WRONG_SECKEY; goto leave; }
    for(n++; n < nframe && frame[n]; n++ ) /* skip the random bytes */
	;
    n++; /* and the zero byte */
    if( n + 4 > nframe )
	{ rc = GPGERR_WRONG_SECKEY; goto leave; }

    dek->keylen = nframe - (n+1) - 2;
    dek->algo = frame[n++];
    if( dek->algo ==  GCRY_CIPHER_IDEA )
	write_status(STATUS_RSA_OR_IDEA);
    rc = openpgp_cipher_test_algo( dek->algo );
    if( rc ) {
	if( !opt.quiet && rc == GPGERR_CIPHER_ALGO ) {
	    log_info(_("cipher algorithm %d is unknown or disabled\n"),
							    dek->algo);
	}
	dek->algo = 0;
	goto leave;
    }
    if( dek->keylen != gcry_cipher_get_algo_keylen( dek->algo ) ) {
	rc = GPGERR_WRONG_SECKEY;
	goto leave;
    }

    /* copy the key to DEK and compare the checksum */
    csum  = frame[nframe-2] << 8;
    csum |= frame[nframe-1];
    memcpy( dek->key, frame+n, dek->keylen );
    for( csum2=0, n=0; n < dek->keylen; n++ )
	csum2 += dek->key[n];
    if( csum != csum2 ) {
	rc = GPGERR_WRONG_SECKEY;
	goto leave;
    }
    if( DBG_CIPHER )
	log_hexdump("DEK is:", dek->key, dek->keylen );
    /* check that the algo is in the preferences and whether it has expired */
    {
	PKT_public_key *pk = gcry_xcalloc( 1, sizeof *pk );
	if( (rc = get_pubkey( pk, keyid )) )
	    log_error("public key problem: %s\n", gpg_errstr(rc) );
	else if( !pk->local_id && query_trust_record(pk) )
	    log_error("can't check algorithm against preferences\n");
	else if( dek->algo != GCRY_CIPHER_3DES
	    && !is_algo_in_prefs( pk->local_id, PREFTYPE_SYM, dek->algo ) ) {
	    /* Don't print a note while we are not on verbose mode,
	     * the cipher is blowfish and the preferences have twofish
	     * listed */
	    if( opt.verbose || dek->algo != GCRY_CIPHER_BLOWFISH
		|| !is_algo_in_prefs( pk->local_id, PREFTYPE_SYM,
						    GCRY_CIPHER_TWOFISH ) )
		log_info(_(
		    "NOTE: cipher algorithm %d not found in preferences\n"),
								 dek->algo );
	}


	if( !rc && pk->expiredate && pk->expiredate <= make_timestamp() ) {
	    log_info(_("NOTE: secret key %08lX expired at %s\n"),
			   (ulong)keyid[1], asctimestamp( pk->expiredate) );
	}

	/* FIXME: check wheter the key has been revoked and display
	 * the revocation reason.  Actually the user should know this himself,
	 * but the sender might not know already and therefor the user
	 * should get a notice that an revoked key has been used to decode
	 * the message.  The user can than watch out for snakes send by
	 * one of those Eves outside his paradise :-)
	 */
	free_public_key( pk );
	rc = 0;
    }


  leave:
    mpi_release(plain_dek);
    gcry_free(frame);
    return rc;
}


