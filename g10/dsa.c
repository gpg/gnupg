/* dsa.c
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
g10_dsa_sign( PKT_secret_cert *skc, PKT_signature *sig,
	      MD_HANDLE md, int digest_algo )
{
    MPI frame;
    byte *dp;

    assert( sig->pubkey_algo == PUBKEY_ALGO_DSA );
    if( !digest_algo )
	digest_algo = md_get_algo(md);

    dp = md_read( md, digest_algo );
    keyid_from_skc( skc, sig->keyid );
    sig->digest_algo = digest_algo;
    sig->digest_start[0] = dp[0];
    sig->digest_start[1] = dp[1];
    sig->d.dsa.r = mpi_alloc( mpi_get_nlimbs(skc->d.dsa.p) );
    sig->d.dsa.s = mpi_alloc( mpi_get_nlimbs(skc->d.dsa.p) );
    frame = mpi_alloc( (md_digest_length(digest_algo)+BYTES_PER_MPI_LIMB-1)
		       / BYTES_PER_MPI_LIMB );
    mpi_set_buffer( frame, md_read(md, digest_algo),
			   md_digest_length(digest_algo), 0 );
    if( DBG_CIPHER )
	log_mpidump("used sig frame: ", frame);
    dsa_sign( sig->d.dsa.r, sig->d.dsa.s, frame, &skc->d.dsa );
    mpi_free(frame);
    if( opt.verbose ) {
	char *ustr = get_user_id_string( sig->keyid );
	log_info("DSA signature from: %s\n", ustr );
	m_free(ustr);
    }
}

