/* rsa.c
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
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"

void
g10_rsa_encrypt( PKT_public_cert *pkc, PKT_pubkey_enc *enc, DEK *dek )
{
  #ifdef HAVE_RSA_CIPHER
    assert( enc->pubkey_algo == PUBKEY_ALGO_RSA );

    keyid_from_pkc( pkc, enc->keyid );
    enc->d.rsa.rsa_integer = encode_session_key( dek,
				mpi_get_nbits(pkc->d.rsa.rsa_n) );
    if( DBG_CIPHER )
	log_mpidump("Plain DEK frame: ", enc->d.rsa.rsa_integer);
    rsa_public( enc->d.rsa.rsa_integer, enc->d.rsa.rsa_integer, &pkc->d.rsa);
    if( DBG_CIPHER )
	log_mpidump("Encry DEK frame: ", enc->d.rsa.rsa_integer);
    if( opt.verbose ) {
	char *ustr = get_user_id_string( enc->keyid );
	log_info("RSA encrypted for: %s\n", ustr );
	m_free(ustr);
    }
 #else
    BUG();
 #endif/* ! HAVE_RSA_CIPHER*/
}


void
g10_rsa_sign( PKT_secret_cert *skc, PKT_signature *sig,
				    MD_HANDLE md, int digest_algo )
{
 #ifdef HAVE_RSA_CIPHER
    byte *dp;

    assert( sig->pubkey_algo == PUBKEY_ALGO_RSA );
    if( !digest_algo )
	digest_algo = md_get_algo(md);

    dp = md_read( md, digest_algo );
    keyid_from_skc( skc, sig->keyid );
    sig->digest_algo = digest_algo;
    sig->digest_start[0] = dp[0];
    sig->digest_start[1] = dp[1];
    sig->d.rsa.rsa_integer =
		   encode_md_value( md, mpi_get_nbits(skc->d.rsa.rsa_n));
    rsa_secret( sig->d.rsa.rsa_integer, sig->d.rsa.rsa_integer, &skc->d.rsa );
    if( opt.verbose ) {
	char *ustr = get_user_id_string( sig->keyid );
	log_info("RSA signature from: %s\n", ustr );
	m_free(ustr);
    }
 #else
    BUG();
 #endif/* ! HAVE_RSA_CIPHER*/
}

