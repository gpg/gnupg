/* keyid.c - jeyid and fingerprint handling
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
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "main.h"
#include "packet.h"
#include "options.h"
#include "mpi.h"
#include "keydb.h"




/****************
 * Get the keyid from the secret key certificate and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_skc( PKT_seckey_cert *skc, u32 *keyid )
{
    u32 lowbits;
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	lowbits = mpi_get_keyid( skc->d.elg.y, keyid );
    }
    else if( skc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	lowbits = mpi_get_keyid( skc->d.rsa.rsa_n, keyid );
    }
    else
	log_bug(NULL);

    return lowbits;
}


/****************
 * Get the keyid from the public key certificate and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_pkc( PKT_pubkey_cert *pkc, u32 *keyid )
{
    u32 lowbits;
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	lowbits = mpi_get_keyid( pkc->d.elg.y, keyid );
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	lowbits = mpi_get_keyid( pkc->d.rsa.rsa_n, keyid );
    }
    else
	log_bug(NULL);

    return lowbits;
}


