/* skclist.c
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
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "i18n.h"
#include "cipher.h"


void
release_sk_list( SK_LIST sk_list )
{
    SK_LIST sk_rover;

    for( ; sk_list; sk_list = sk_rover ) {
	sk_rover = sk_list->next;
	free_secret_key( sk_list->sk );
	xfree ( sk_list );
    }
}



static int
key_present_in_sk_list(SK_LIST sk_list, PKT_secret_key *sk)
{
    for (; sk_list; sk_list = sk_list->next) {
	if ( !cmp_secret_keys(sk_list->sk, sk) )
	    return 0;
    }
    return -1;
}

static int
is_duplicated_entry (STRLIST list, STRLIST item)
{
    for(; list && list != item; list = list->next) {
        if ( !strcmp (list->d, item->d) )
            return 1;
    }
    return 0;
}


int
build_sk_list( STRLIST locusr, SK_LIST *ret_sk_list,
               int unlock, unsigned int use )
{
    SK_LIST sk_list = NULL;
    int rc;

    if( !locusr ) { /* use the default one */
	PKT_secret_key *sk;

	sk = xcalloc (1, sizeof *sk );
	sk->req_usage = use;
	if( (rc = get_seckey_byname( sk, NULL, unlock )) ) {
	    free_secret_key( sk ); sk = NULL;
	    log_error("no default secret key: %s\n", gpg_strerror (rc) );
	}
	else if( !(rc=openpgp_pk_test_algo (sk->pubkey_algo, use)) ) {
	    SK_LIST r;

	    if( sk->version == 4 && (use & PUBKEY_USAGE_SIG)
		&& sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E ) {
		log_info("this is a PGP generated "
		    "ElGamal key which is NOT secure for signatures!\n");
		free_secret_key( sk ); sk = NULL;
	    }
	    else {
		r = xmalloc ( sizeof *r );
		r->sk = sk; sk = NULL;
		r->next = sk_list;
		r->mark = 0;
		sk_list = r;
	    }
	}
	else {
	    free_secret_key( sk ); sk = NULL;
	    log_error("invalid default secret key: %s\n", gpg_strerror (rc) );
	}
    }
    else {
        STRLIST locusr_orig = locusr;
	for(; locusr; locusr = locusr->next ) {
	    PKT_secret_key *sk;
            
            rc = 0;
            /* Do an early check agains duplicated entries.  However this
             * won't catch all duplicates because the user IDs may be
             * specified in different ways.
             */
            if ( is_duplicated_entry ( locusr_orig, locusr ) ) {
		log_error(_("skipped `%s': duplicated\n"), locusr->d );
                continue;
            }
	    sk = xcalloc (1, sizeof *sk );
	    sk->req_usage = use;
	    if( (rc = get_seckey_byname( sk, locusr->d, 0 )) ) {
		free_secret_key( sk ); sk = NULL;
		log_error(_("skipped `%s': %s\n"), locusr->d, gpg_strerror (rc) );
	    }
            else if ( key_present_in_sk_list(sk_list, sk) == 0) {
                free_secret_key(sk); sk = NULL;
                log_info(_("skipped: secret key already present\n"));
            }
            else if ( unlock && (rc = check_secret_key( sk, 0 )) ) {
		free_secret_key( sk ); sk = NULL;
		log_error(_("skipped `%s': %s\n"), locusr->d, gpg_strerror (rc) );
            }
	    else if( !(rc=openpgp_pk_test_algo (sk->pubkey_algo, use)) ) {
		SK_LIST r;

		if( sk->version == 4 && (use & PUBKEY_USAGE_SIG)
		    && sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E ) {
		    log_info(_("skipped `%s': this is a PGP generated "
			"ElGamal key which is not secure for signatures!\n"),
			locusr->d );
		    free_secret_key( sk ); sk = NULL;
		}
		else {
		    r = xmalloc ( sizeof *r );
		    r->sk = sk; sk = NULL;
		    r->next = sk_list;
		    r->mark = 0;
		    sk_list = r;
		}
	    }
	    else {
		free_secret_key( sk ); sk = NULL;
		log_error("skipped `%s': %s\n", locusr->d, gpg_strerror (rc) );
	    }
	}
    }


    if( !rc && !sk_list ) {
	log_error("no valid signators\n");
	rc = GPG_ERR_NO_USER_ID;
    }

    if( rc )
	release_sk_list( sk_list );
    else
	*ret_sk_list = sk_list;
    return rc;
}

