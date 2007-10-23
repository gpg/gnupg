/* delkey.c - delete keys
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2004,
 *               2005 Free Software Foundation, Inc.
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
do_delete_key( const char *username, int secret, int force, int *r_sec_avail )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    KBNODE node;
    KEYDB_HANDLE hd = keydb_new (secret);
    PKT_public_key *pk = NULL;
    PKT_secret_key *sk = NULL;
    u32 keyid[2];
    int okay=0;
    int yes;
    KEYDB_SEARCH_DESC desc;
    int exactmatch;

    *r_sec_avail = 0;

    /* search the userid */
    classify_user_id (username, &desc);
    exactmatch = (desc.mode == KEYDB_SEARCH_MODE_FPR
                  || desc.mode == KEYDB_SEARCH_MODE_FPR16
                  || desc.mode == KEYDB_SEARCH_MODE_FPR20);
    rc = desc.mode? keydb_search (hd, &desc, 1):G10ERR_INV_USER_ID;
    if (rc) {
	log_error (_("key \"%s\" not found: %s\n"), username, g10_errstr (rc));
	write_status_text( STATUS_DELETE_PROBLEM, "1" );
	goto leave;
    }

    /* read the keyblock */
    rc = keydb_get_keyblock (hd, &keyblock );
    if (rc) {
	log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_KEY:PKT_PUBLIC_KEY );
    if( !node ) {
	log_error("Oops; key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    if( secret )
      {
	sk = node->pkt->pkt.secret_key;
	keyid_from_sk( sk, keyid );
      }
    else
      {
	/* public */
	pk = node->pkt->pkt.public_key;
	keyid_from_pk( pk, keyid );

	if(!force)
	  {
	    rc = seckey_available( keyid );
	    if( !rc )
	      {
		*r_sec_avail = 1;
		rc = -1;
		goto leave;
	      }
	    else if( rc != G10ERR_NO_SECKEY )
	      log_error("%s: get secret key: %s\n", username, g10_errstr(rc) );
	    else
	      rc = 0;
	  }
      }

    if( rc )
	rc = 0;
    else if (opt.batch && exactmatch)
        okay++;
    else if( opt.batch && secret )
      {
	log_error(_("can't do this in batch mode\n"));
        log_info (_("(unless you specify the key by fingerprint)\n"));
      }
    else if( opt.batch && opt.answer_yes )
	okay++;
    else if( opt.batch )
      {
	log_error(_("can't do this in batch mode without \"--yes\"\n"));
        log_info (_("(unless you specify the key by fingerprint)\n"));
      }
    else {
        if( secret )
            print_seckey_info( sk );
        else
            print_pubkey_info(NULL, pk );
	tty_printf( "\n" );

	yes = cpr_get_answer_is_yes( secret? "delete_key.secret.okay"
					   : "delete_key.okay",
			      _("Delete this key from the keyring? (y/N) "));
	if( !cpr_enabled() && secret && yes ) {
	    /* I think it is not required to check a passphrase; if
	     * the user is so stupid as to let others access his secret keyring
	     * (and has no backup) - it is up him to read some very
	     * basic texts about security.
	     */
	    yes = cpr_get_answer_is_yes("delete_key.secret.okay",
			 _("This is a secret key! - really delete? (y/N) "));
	}
	if( yes )
	    okay++;
    }


    if( okay ) {
	rc = keydb_delete_keyblock (hd);
	if (rc) {
	    log_error (_("deleting keyblock failed: %s\n"), g10_errstr(rc) );
	    goto leave;
	}

	/* Note that the ownertrust being cleared will trigger a
           revalidation_mark().  This makes sense - only deleting keys
           that have ownertrust set should trigger this. */

        if (!secret && pk && clear_ownertrusts (pk)) {
          if (opt.verbose)
            log_info (_("ownertrust information cleared\n"));
        }
    }

  leave:
    keydb_release (hd);
    release_kbnode (keyblock);
    return rc;
}

/****************
 * Delete a public or secret key from a keyring.
 */
int
delete_keys( STRLIST names, int secret, int allow_both )
{
    int rc, avail, force=(!allow_both && !secret && opt.expert);

    /* Force allows us to delete a public key even if a secret key
       exists. */

    for(;names;names=names->next) {
       rc = do_delete_key (names->d, secret, force, &avail );
       if ( rc && avail ) { 
	 if ( allow_both ) {
	   rc = do_delete_key (names->d, 1, 0, &avail );
	   if ( !rc )
	     rc = do_delete_key (names->d, 0, 0, &avail );
	 }
	 else {
	   log_error(_(
	      "there is a secret key for public key \"%s\"!\n"),names->d);
	   log_info(_(
	      "use option \"--delete-secret-keys\" to delete it first.\n"));
	   write_status_text( STATUS_DELETE_PROBLEM, "2" );
	   return rc;
	 }
       }

       if(rc) {
	 log_error("%s: delete key failed: %s\n", names->d, g10_errstr(rc) );
	 return rc;
       }
    }

    return 0;
}
