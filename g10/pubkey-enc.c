/* pubkey-enc.c -  public key encoded packet handling
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "mpi.h"
#include "keydb.h"
#include "trustdb.h"
#include "cipher.h"
#include "status.h"
#include "options.h"
#include "i18n.h"

static int get_it( PKT_pubkey_enc *k,
		   DEK *dek, PKT_secret_key *sk, u32 *keyid );

/****************
 * Get the session key from a pubkey enc paket and return
 * it in DEK, which should have been allocated in secure memory.
 */
int
get_session_key( PKT_pubkey_enc *k, DEK *dek )
{
    PKT_secret_key *sk = NULL;
    int rc;

    rc = check_pubkey_algo( k->pubkey_algo );
    if( rc )
	goto leave;

    if( (k->keyid[0] || k->keyid[1]) && !opt.try_all_secrets ) {
	sk = m_alloc_clear( sizeof *sk );
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
	    sk = m_alloc_clear( sizeof *sk );
	    rc=enum_secret_keys( &enum_context, sk, 1);
	    if( rc ) {
		rc = G10ERR_NO_SECKEY;
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
    unsigned n, nframe;
    u16 csum, csum2;

    rc = pubkey_decrypt(sk->pubkey_algo, &plain_dek, k->data, sk->skey );
    if( rc )
	goto leave;
    frame = mpi_get_buffer( plain_dek, &nframe, NULL );
    mpi_free( plain_dek ); plain_dek = NULL;

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
     * (mpi_get_buffer already removed the leading zero).
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
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    if( frame[n] == 1 && frame[nframe-1] == 2 ) {
	log_info(_("old encoding of the DEK is not supported\n"));
	rc = G10ERR_CIPHER_ALGO;
	goto leave;
    }
    if( frame[n] != 2 )  /* somethink is wrong */
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    for(n++; n < nframe && frame[n]; n++ ) /* skip the random bytes */
	;
    n++; /* and the zero byte */
    if( n + 4 > nframe )
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }

    dek->keylen = nframe - (n+1) - 2;
    dek->algo = frame[n++];
    if( dek->algo ==  CIPHER_ALGO_IDEA )
	write_status(STATUS_RSA_OR_IDEA);
    rc = check_cipher_algo( dek->algo );
    if( rc ) {
	if( !opt.quiet && rc == G10ERR_CIPHER_ALGO ) {
	    log_info(_("cipher algorithm %d is unknown or disabled\n"),
							    dek->algo);
	}
	dek->algo = 0;
	goto leave;
    }
    if( (dek->keylen*8) != cipher_get_keylen( dek->algo ) ) {
	rc = G10ERR_WRONG_SECKEY;
	goto leave;
    }

    /* copy the key to DEK and compare the checksum */
    csum  = frame[nframe-2] << 8;
    csum |= frame[nframe-1];
    memcpy( dek->key, frame+n, dek->keylen );
    for( csum2=0, n=0; n < dek->keylen; n++ )
	csum2 += dek->key[n];
    if( csum != csum2 ) {
	rc = G10ERR_WRONG_SECKEY;
	goto leave;
    }
    if( DBG_CIPHER )
	log_hexdump("DEK is:", dek->key, dek->keylen );
    /* check that the algo is in the preferences and whether it has expired */
    {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	if( (rc = get_pubkey( pk, keyid )) )
	    log_error("public key problem: %s\n", g10_errstr(rc) );
	else if( !pk->local_id && query_trust_record(pk) )
	    log_error("can't check algorithm against preferences\n");
	else if( dek->algo != CIPHER_ALGO_3DES
	    && !is_algo_in_prefs( pk->local_id, PREFTYPE_SYM, dek->algo ) ) {
	    /* Don't print a note while we are not on verbose mode,
	     * the cipher is blowfish and the preferences have twofish
	     * listed */
	    if( opt.verbose || dek->algo != CIPHER_ALGO_BLOWFISH
		|| !is_algo_in_prefs( pk->local_id, PREFTYPE_SYM,
						    CIPHER_ALGO_TWOFISH ) )
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
    mpi_free(plain_dek);
    m_free(frame);
    return rc;
}


static int
hextobyte( const char *s )
{
    int c;

    if( *s >= '0' && *s <= '9' )
	c = 16 * (*s - '0');
    else if( *s >= 'A' && *s <= 'F' )
	c = 16 * (10 + *s - 'A');
    else if( *s >= 'a' && *s <= 'f' )
	c = 16 * (10 + *s - 'a');
    else
	return -1;
    s++;
    if( *s >= '0' && *s <= '9' )
	c += *s - '0';
    else if( *s >= 'A' && *s <= 'F' )
	c += 10 + *s - 'A';
    else if( *s >= 'a' && *s <= 'f' )
	c += 10 + *s - 'a';
    else
	return -1;
    return c;
}

/****************
 * Get the session key from the given string.
 * String is supposed to be formatted as this:
 *  <algo-id>:<even-number-of-hex-digits>
 */
int
get_override_session_key( DEK *dek, const char *string )
{
    const char *s;
    int i;

    if ( !string )
	return G10ERR_BAD_KEY;
    dek->algo = atoi(string);
    if ( dek->algo < 1 )
	return G10ERR_BAD_KEY;
    if ( !(s = strchr ( string, ':' )) )
	return G10ERR_BAD_KEY;
    s++;
    for(i=0; i < DIM(dek->key) && *s; i++, s +=2 ) {
	int c = hextobyte ( s );
	if (c == -1)
	    return G10ERR_BAD_KEY;
	dek->key[i] = c;
    }
    if ( *s )
	return G10ERR_BAD_KEY;
    dek->keylen = i;
    return 0;
}

