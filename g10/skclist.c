/* skclist.c
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
#include "keydb.h"
#include "memory.h"
#include "util.h"


void
release_sk_list( SK_LIST sk_list )
{
    SK_LIST sk_rover;

    for( ; sk_list; sk_list = sk_rover ) {
	sk_rover = sk_list->next;
	free_secret_key( sk_list->sk );
	m_free( sk_list );
    }
}

int
build_sk_list( STRLIST locusr, SK_LIST *ret_sk_list, int unlock,
							unsigned usage )
{
    SK_LIST sk_list = NULL;
    int rc;

    if( !locusr ) { /* use the default one */
	PKT_secret_key *sk;

	sk = m_alloc_clear( sizeof *sk );
	if( (rc = get_seckey_byname( sk, NULL, unlock )) ) {
	    free_secret_key( sk ); sk = NULL;
	    log_error("no default secret key: %s\n", g10_errstr(rc) );
	}
	else if( !(rc=check_pubkey_algo2(sk->pubkey_algo, usage)) ) {
	    SK_LIST r;
	    if( sk->version == 4 && (usage & 1)
		&& sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E ) {
		log_error("this is a PGP generated "
		    "ElGamal key which is NOT secure for signatures!\n");
		free_secret_key( sk ); sk = NULL;
	    }
	    else {
		r = m_alloc( sizeof *r );
		r->sk = sk; sk = NULL;
		r->next = sk_list;
		r->mark = 0;
		sk_list = r;
	    }
	}
	else {
	    free_secret_key( sk ); sk = NULL;
	    log_error("invalid default secret key: %s\n", g10_errstr(rc) );
	}
    }
    else {
	for(; locusr; locusr = locusr->next ) {
	    PKT_secret_key *sk;

	    sk = m_alloc_clear( sizeof *sk );
	    if( (rc = get_seckey_byname( sk, locusr->d, unlock )) ) {
		free_secret_key( sk ); sk = NULL;
		log_error("skipped '%s': %s\n", locusr->d, g10_errstr(rc) );
	    }
	    else if( !(rc=check_pubkey_algo2(sk->pubkey_algo, usage)) ) {
		SK_LIST r;
		if( sk->version == 4 && (usage & 1)
		    && sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E ) {
		    log_info("skipped '%s': this is a PGP generated "
			"ElGamal key which is not secure for signatures!\n",
			locusr->d );
		    free_secret_key( sk ); sk = NULL;
		}
		else {
		    r = m_alloc( sizeof *r );
		    r->sk = sk; sk = NULL;
		    r->next = sk_list;
		    r->mark = 0;
		    sk_list = r;
		}
	    }
	    else {
		free_secret_key( sk ); sk = NULL;
		log_error("skipped '%s': %s\n", locusr->d, g10_errstr(rc) );
	    }
	}
    }


    if( !rc && !sk_list ) {
	log_error("no valid signators\n");
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_sk_list( sk_list );
    else
	*ret_sk_list = sk_list;
    return rc;
}

