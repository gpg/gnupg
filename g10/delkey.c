/* delkey.c - delete keys
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
#include <ctype.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "trustdb.h"
#include "filter.h"
#include "ttyio.h"
#include "status.h"
#include "i18n.h"


/****************
 * Delete a public or secret key from a keyring.
 * r_sec_avail will be set if a secret key is available and the public
 * key can't be deleted for that reason.
 */
static int
do_delete_key( const char *username, int secret, int *r_sec_avail )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    KBNODE node;
    KBPOS kbpos;
    PKT_public_key *pk = NULL;
    PKT_secret_key *sk = NULL;
    u32 keyid[2];
    int okay=0;
    int yes;

    *r_sec_avail = 0;
    /* search the userid */
    rc = secret? find_secret_keyblock_byname( &kbpos, username )
	       : find_keyblock_byname( &kbpos, username );
    if( rc ) {
	log_error(_("%s: user not found\n"), username );
	write_status_text( STATUS_DELETE_PROBLEM, "1" );
	goto leave;
    }

    /* read the keyblock */
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("%s: read problem: %s\n", username, g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_KEY:PKT_PUBLIC_KEY );
    if( !node ) {
	log_error("Oops; key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    if( secret ) {
	sk = node->pkt->pkt.secret_key;
	keyid_from_sk( sk, keyid );
    }
    else {
	pk = node->pkt->pkt.public_key;
	keyid_from_pk( pk, keyid );
	rc = seckey_available( keyid );
	if( !rc ) {
            *r_sec_avail = 1;
            rc = -1;
            goto leave;
	}
	else if( rc != G10ERR_NO_SECKEY ) {
	    log_error("%s: get secret key: %s\n", username, g10_errstr(rc) );
	}
	else
	    rc = 0;
    }

    if( rc )
	rc = 0;
    else if( opt.batch && secret )
	log_error(_("can't do that in batchmode\n"));
    else if( opt.batch && opt.answer_yes )
	okay++;
    else if( opt.batch )
	log_error(_("can't do that in batchmode without \"--yes\"\n"));
    else {
	char *p;
	size_t n;

	if( secret )
	    tty_printf("sec  %4u%c/%08lX %s   ",
		      nbits_from_sk( sk ),
		      pubkey_letter( sk->pubkey_algo ),
		      (ulong)keyid[1], datestr_from_sk(sk) );
	else
	    tty_printf("pub  %4u%c/%08lX %s   ",
		      nbits_from_pk( pk ),
		      pubkey_letter( pk->pubkey_algo ),
		      (ulong)keyid[1], datestr_from_pk(pk) );
	p = get_user_id( keyid, &n );
	tty_print_utf8_string( p, n );
	m_free(p);
	tty_printf("\n\n");

	yes = cpr_get_answer_is_yes( secret? "delete_key.secret.okay"
					   : "delete_key.okay",
			      _("Delete this key from the keyring? "));
	if( !cpr_enabled() && secret && yes ) {
	    /* I think it is not required to check a passphrase; if
	     * the user is so stupid as to let others access his secret keyring
	     * (and has no backup) - it is up him to read some very
	     * basic texts about security.
	     */
	    yes = cpr_get_answer_is_yes("delete_key.secret.okay",
			 _("This is a secret key! - really delete? "));
	}
	if( yes )
	    okay++;
    }


    if( okay ) {
	rc = delete_keyblock( &kbpos );
	if( rc ) {
	    log_error("delete_keyblock failed: %s\n", g10_errstr(rc) );
	    goto leave;
	}
    }

  leave:
    release_kbnode( keyblock );
    return rc;
}

/****************
 * Delete a public or secret key from a keyring.
 */
int
delete_key( const char *username, int secret, int allow_both )
{
    int rc, avail;

    rc = do_delete_key (username, secret, &avail );
    if ( rc && avail ) { 
        if ( allow_both ) {
            rc = do_delete_key (username, 1, &avail );
            if ( !rc )
                rc = do_delete_key (username, 0, &avail );
        }
        else {
            log_error(_(
                "there is a secret key for this public key!\n"));
            log_info(_(
                "use option \"--delete-secret-key\" to delete it first.\n"));
            write_status_text( STATUS_DELETE_PROBLEM, "2" );
        }
    }
    return rc;
}
