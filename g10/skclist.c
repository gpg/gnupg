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
release_skc_list( SKC_LIST skc_list )
{
    SKC_LIST skc_rover;

    for( ; skc_list; skc_list = skc_rover ) {
	skc_rover = skc_list->next;
	free_secret_cert( skc_list->skc );
	m_free( skc_list );
    }
}

int
build_skc_list( STRLIST locusr, SKC_LIST *ret_skc_list, int unlock,
							unsigned usage )
{
    SKC_LIST skc_list = NULL;
    int rc;

    if( !locusr ) { /* use the default one */
	PKT_secret_cert *skc;

	skc = m_alloc_clear( sizeof *skc );
	if( (rc = get_seckey_byname( skc, NULL, unlock )) ) {
	    free_secret_cert( skc ); skc = NULL;
	    log_error("no default secret key: %s\n", g10_errstr(rc) );
	}
	else if( !(rc=check_pubkey_algo2(skc->pubkey_algo, usage)) ) {
	    SKC_LIST r;
	    if( skc->version == 4 && (usage & 1)
		&& skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
		log_info("WARNING: This is probably a PGP generated "
		    "ElGamal key which is NOT secure for signatures!\n");
	    r = m_alloc( sizeof *r );
	    r->skc = skc; skc = NULL;
	    r->next = skc_list;
	    r->mark = 0;
	    skc_list = r;
	}
	else {
	    free_secret_cert( skc ); skc = NULL;
	    log_error("invalid default secret key: %s\n", g10_errstr(rc) );
	}
    }
    else {
	for(; locusr; locusr = locusr->next ) {
	    PKT_secret_cert *skc;

	    skc = m_alloc_clear( sizeof *skc );
	    if( (rc = get_seckey_byname( skc, locusr->d, unlock )) ) {
		free_secret_cert( skc ); skc = NULL;
		log_error("skipped '%s': %s\n", locusr->d, g10_errstr(rc) );
	    }
	    else if( !(rc=check_pubkey_algo2(skc->pubkey_algo, usage)) ) {
		SKC_LIST r;
		if( skc->version == 4 && (usage & 1)
		    && skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
		    log_info("WARNING: This is probably a PGP generated "
			"ElGamal key which is NOT secure for signatures!\n");
		r = m_alloc( sizeof *r );
		r->skc = skc; skc = NULL;
		r->next = skc_list;
		r->mark = 0;
		skc_list = r;
	    }
	    else {
		free_secret_cert( skc ); skc = NULL;
		log_error("skipped '%s': %s\n", locusr->d, g10_errstr(rc) );
	    }
	}
    }


    if( !rc && !skc_list ) {
	log_error("no valid signators\n");
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_skc_list( skc_list );
    else
	*ret_skc_list = skc_list;
    return rc;
}

