/* elg.c
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
g10_elg_encrypt( PKT_public_cert *pkc, PKT_pubkey_enc *enc, DEK *dek )
{
    ELG_public_key pkey;
    MPI frame;

    assert( enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL );

    enc->d.elg.a = mpi_alloc( mpi_get_nlimbs(pkc->d.elg.p) );
    enc->d.elg.b = mpi_alloc( mpi_get_nlimbs(pkc->d.elg.p) );
    keyid_from_pkc( pkc, enc->keyid );
    frame = encode_session_key( dek, mpi_get_nbits(pkc->d.elg.p) );
    pkey.p = pkc->d.elg.p;
    pkey.g = pkc->d.elg.g;
    pkey.y = pkc->d.elg.y;
    if( DBG_CIPHER )
	log_mpidump("Plain DEK frame: ", frame);
    elg_encrypt( enc->d.elg.a, enc->d.elg.b, frame, &pkey);
    mpi_free( frame );
    if( DBG_CIPHER ) {
	log_mpidump("Encry DEK a: ", enc->d.elg.a );
	log_mpidump("      DEK b: ", enc->d.elg.b );
    }
    if( opt.verbose ) {
	char *ustr = get_user_id_string( enc->keyid );
	log_info("ElGamal encrypted for: %s\n", ustr );
	m_free(ustr);
    }
}


void
g10_elg_sign( PKT_secret_cert *skc, PKT_signature *sig,
	      MD_HANDLE md, int digest_algo )
{
    ELG_secret_key skey;
    MPI frame;
    byte *dp;

    assert( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL );
    if( !digest_algo )
	digest_algo = md_get_algo(md);

    dp = md_read( md, digest_algo );
    keyid_from_skc( skc, sig->keyid );
    sig->d.elg.digest_algo = digest_algo;
    sig->d.elg.digest_start[0] = dp[0];
    sig->d.elg.digest_start[1] = dp[1];
    sig->d.elg.a = mpi_alloc( mpi_get_nlimbs(skc->d.elg.p) );
    sig->d.elg.b = mpi_alloc( mpi_get_nlimbs(skc->d.elg.p) );
    frame = encode_md_value( md, mpi_get_nbits(skc->d.elg.p));
    skey.p = skc->d.elg.p;
    skey.g = skc->d.elg.g;
    skey.y = skc->d.elg.y;
    skey.x = skc->d.elg.x;
    elg_sign( sig->d.elg.a, sig->d.elg.b, frame, &skey);
    memset( &skey, 0, sizeof skey );
    mpi_free(frame);
    if( opt.verbose ) {
	char *ustr = get_user_id_string( sig->keyid );
	log_info("ElGamal signature from: %s\n", ustr );
	m_free(ustr);
    }
}

