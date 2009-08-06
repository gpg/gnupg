/* skclist.c - Build a list of secret keys
 * Copyright (C) 1998, 1999, 2000, 2001, 2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "status.h"
#include "keydb.h"
#include "util.h"
#include "i18n.h"
#include "cipher.h"

#ifndef GCRYCTL_FAKED_RANDOM_P
#define GCRYCTL_FAKED_RANDOM_P 51
#endif

/* Return true if Libgcrypt's RNG is in faked mode.  */
int
random_is_faked (void)
{
  return !!gcry_control ( GCRYCTL_FAKED_RANDOM_P, 0);
}



void
release_sk_list( SK_LIST sk_list )
{
    SK_LIST sk_rover;

    for( ; sk_list; sk_list = sk_rover ) {
	sk_rover = sk_list->next;
	free_secret_key( sk_list->sk );
	xfree( sk_list );
    }
}


/* Check that we are only using keys which don't have
 * the string "(insecure!)" or "not secure" or "do not use"
 * in one of the user ids
 */
static int
is_insecure( PKT_secret_key *sk )
{
    u32 keyid[2];
    KBNODE node = NULL, u;
    int insecure = 0;

    keyid_from_sk( sk, keyid );
    node = get_pubkeyblock( keyid );
    for ( u = node; u; u = u->next ) {
        if ( u->pkt->pkttype == PKT_USER_ID ) {
            PKT_user_id *id = u->pkt->pkt.user_id;
            if ( id->attrib_data )
                continue; /* skip attribute packets */
            if ( strstr( id->name, "(insecure!)" )
                 || strstr( id->name, "not secure" )
                 || strstr( id->name, "do not use" )
                 || strstr( id->name, "(INSECURE!)" ) ) {
                insecure = 1;
                break;
            }
        }
    }
    release_kbnode( node );
    
    return insecure;
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
is_duplicated_entry (strlist_t list, strlist_t item)
{
    for(; list && list != item; list = list->next) {
        if ( !strcmp (list->d, item->d) )
            return 1;
    }
    return 0;
}


int
build_sk_list( strlist_t locusr, SK_LIST *ret_sk_list,
               int unlock, unsigned int use )
{
    SK_LIST sk_list = NULL;
    int rc;

    if( !locusr )
      { /* use the default one */
	PKT_secret_key *sk;

	sk = xmalloc_clear( sizeof *sk );
	sk->req_usage = use;
	if( (rc = get_seckey_byname( sk, NULL, unlock )) ) {
	  free_secret_key( sk ); sk = NULL;
	  log_error("no default secret key: %s\n", g10_errstr(rc) );
          write_status_text (STATUS_INV_SGNR,
                             get_inv_recpsgnr_code (GPG_ERR_NO_SECKEY));
	}
	else if( !(rc=openpgp_pk_test_algo2 (sk->pubkey_algo, use)) )
	  {
	    SK_LIST r;

	    if( random_is_faked() && !is_insecure( sk ) )
	      {
		log_info(_("key is not flagged as insecure - "
			   "can't use it with the faked RNG!\n"));
		free_secret_key( sk ); sk = NULL;
                write_status_text (STATUS_INV_SGNR, 
                                   get_inv_recpsgnr_code (GPG_ERR_NOT_TRUSTED));
	      }
	    else
	      {
		r = xmalloc( sizeof *r );
		r->sk = sk; sk = NULL;
		r->next = sk_list;
		r->mark = 0;
		sk_list = r;
	      }
	  }
	else
	  {
	    free_secret_key( sk ); sk = NULL;
	    log_error("invalid default secret key: %s\n", g10_errstr(rc) );
            write_status_text (STATUS_INV_SGNR, get_inv_recpsgnr_code (rc));
	  }
      }
    else {
        strlist_t locusr_orig = locusr;
	for(; locusr; locusr = locusr->next ) {
	    PKT_secret_key *sk;
            
            rc = 0;
            /* Do an early check agains duplicated entries.  However this
             * won't catch all duplicates because the user IDs may be
             * specified in different ways.
             */
            if ( is_duplicated_entry ( locusr_orig, locusr ) )
	      {
		log_info (_("skipped \"%s\": duplicated\n"), locusr->d );
                continue;
	      }
	    sk = xmalloc_clear( sizeof *sk );
	    sk->req_usage = use;
	    if( (rc = get_seckey_byname( sk, locusr->d, 0 )) )
	      {
		free_secret_key( sk ); sk = NULL;
		log_error(_("skipped \"%s\": %s\n"),
			  locusr->d, g10_errstr(rc) );
                write_status_text_and_buffer 
                  (STATUS_INV_SGNR, get_inv_recpsgnr_code (rc), 
                   locusr->d, strlen (locusr->d), -1);
	      }
            else if ( key_present_in_sk_list(sk_list, sk) == 0) {
                free_secret_key(sk); sk = NULL;
                log_info(_("skipped: secret key already present\n"));
            }
            else if ( unlock && (rc = check_secret_key( sk, 0 )) )
	      {
		free_secret_key( sk ); sk = NULL;
		log_error(_("skipped \"%s\": %s\n"),
			  locusr->d, g10_errstr(rc) );
                write_status_text_and_buffer 
                  (STATUS_INV_SGNR, get_inv_recpsgnr_code (rc), 
                   locusr->d, strlen (locusr->d), -1);
	      }
	    else if( !(rc=openpgp_pk_test_algo2 (sk->pubkey_algo, use)) ) {
		SK_LIST r;

		if( sk->version == 4 && (use & PUBKEY_USAGE_SIG)
		    && sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E )
		  {
		    log_info(_("skipped \"%s\": %s\n"),locusr->d,
			     _("this is a PGP generated Elgamal key which"
			       " is not secure for signatures!"));
		    free_secret_key( sk ); sk = NULL;
                    write_status_text_and_buffer 
                      (STATUS_INV_SGNR, 
                       get_inv_recpsgnr_code (GPG_ERR_WRONG_KEY_USAGE), 
                       locusr->d, strlen (locusr->d), -1);
		  }
		else if( random_is_faked() && !is_insecure( sk ) ) {
		    log_info(_("key is not flagged as insecure - "
			       "can't use it with the faked RNG!\n"));
		    free_secret_key( sk ); sk = NULL;
                    write_status_text_and_buffer 
                      (STATUS_INV_SGNR, 
                       get_inv_recpsgnr_code (GPG_ERR_NOT_TRUSTED), 
                       locusr->d, strlen (locusr->d), -1);
		}
		else {
		    r = xmalloc( sizeof *r );
		    r->sk = sk; sk = NULL;
		    r->next = sk_list;
		    r->mark = 0;
		    sk_list = r;
		}
	    }
	    else {
		free_secret_key( sk ); sk = NULL;
		log_error("skipped \"%s\": %s\n", locusr->d, g10_errstr(rc) );
                write_status_text_and_buffer 
                  (STATUS_INV_SGNR, get_inv_recpsgnr_code (rc), 
                   locusr->d, strlen (locusr->d), -1);
	    }
	}
    }


    if( !rc && !sk_list ) {
	log_error("no valid signators\n");
        write_status_text (STATUS_NO_SGNR, "0");
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_sk_list( sk_list );
    else
	*ret_sk_list = sk_list;
    return rc;
}

