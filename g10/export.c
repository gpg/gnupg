/* export.c
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
#include "main.h"
#include "i18n.h"

static int do_export( STRLIST users, int secret, int onlyrfc );
static int do_export_stream( IOBUF out, STRLIST users,
			     int secret, int onlyrfc, int *any );

/****************
 * Export the public keys (to standard out or --output).
 * Depending on opt.armor the output is armored.
 * If onlyrfc is True only RFC24404 compatible keys are exported.
 * If USERS is NULL, the complete ring will be exported.
 */
int
export_pubkeys( STRLIST users, int onlyrfc )
{
    return do_export( users, 0, onlyrfc );
}

/****************
 * Export to an already opened stream; return -1 if no keys have
 * been exported
 */
int
export_pubkeys_stream( IOBUF out, STRLIST users, int onlyrfc )
{
    int any, rc;

    rc = do_export_stream( out, users, 0, onlyrfc, &any );
    if( !rc && !any )
	rc = -1;
    return rc;
}

int
export_seckeys( STRLIST users )
{
    return do_export( users, 1, 0 );
}

int
export_secsubkeys( STRLIST users )
{
    return do_export( users, 2, 0 );
}

static int
do_export( STRLIST users, int secret, int onlyrfc )
{
    IOBUF out = NULL;
    int any, rc;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);

    rc = open_outfile( NULL, 0, &out );
    if( rc )
	return rc;

    if( opt.armor ) {
	afx.what = secret?5:1;
	iobuf_push_filter( out, armor_filter, &afx );
    }
    if( opt.compress_keys && opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );
    rc = do_export_stream( out, users, secret, onlyrfc, &any );

    if( rc || !any )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    return rc;
}


static int
do_export_stream( IOBUF out, STRLIST users, int secret, int onlyrfc, int *any )
{
    int rc = 0;
    PACKET pkt;
    KBNODE keyblock = NULL;
    KBNODE kbctx, node;
    int ndesc;
    KEYDB_SEARCH_DESC *desc;
    KEYDB_HANDLE kdbhd;
    STRLIST sl;

    *any = 0;
    init_packet( &pkt );
    kdbhd = keydb_new (secret);

    if (!users) {
        ndesc = 1;
        desc = m_alloc_clear ( ndesc * sizeof *desc);
        desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
    }
    else {
        for (ndesc=0, sl=users; sl; sl = sl->next, ndesc++) 
            ;
        desc = m_alloc ( ndesc * sizeof *desc);
        
        for (ndesc=0, sl=users; sl; sl = sl->next) {
            classify_user_id (sl->d, desc+ndesc);
            if (desc->mode) 
                ndesc++;
            else
                log_error (_("key `%s' not found: %s\n"),
                           sl->d, g10_errstr (G10ERR_INV_USER_ID));
        }

        /* it would be nice to see which of the given users did
           actually match one in the keyring.  To implement this we
           need to have a found flag for each entry in desc and to set
           this we must check all those entries after a match to mark
           all matched one - currently we stop at the first match.  To
           do this we need an extra flag to enable this feature so */
    }


    while (!(rc = keydb_search (kdbhd, desc, ndesc))) {
	if (!users) 
            desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

        /* read the keyblock */
        rc = keydb_get_keyblock (kdbhd, &keyblock );
	if( rc ) {
            log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	    goto leave;
	}

	/* do not export keys which are incompatible with rfc2440 */
	if( onlyrfc && (node = find_kbnode( keyblock, PKT_PUBLIC_KEY )) ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    if( pk->version == 3 && pk->pubkey_algo > 3 ) {
		log_info(_("key %08lX: not a rfc2440 key - skipped\n"),
			      (ulong)keyid_from_pk( pk, NULL) );
		continue;
	    }
	}

	/* we can't apply GNU mode 1001 on an unprotected key */
	if( secret == 2
	    && (node = find_kbnode( keyblock, PKT_SECRET_KEY ))
	    && !node->pkt->pkt.secret_key->is_protected )
	{
	    log_info(_("key %08lX: not protected - skipped\n"),
		  (ulong)keyid_from_sk( node->pkt->pkt.secret_key, NULL) );
	    continue;
	}

	/* and write it */
	for( kbctx=NULL; (node = walk_kbnode( keyblock, &kbctx, 0 )); ) {
	    /* don't export any comment packets but those in the
	     * secret keyring */
	    if( !secret && node->pkt->pkttype == PKT_COMMENT )
		continue;
            /* make sure that ring_trust packets never get exported */
            if (node->pkt->pkttype == PKT_RING_TRUST)
              continue;
	    /* do not export packets which are marked as not exportable */
	    if( node->pkt->pkttype == PKT_SIGNATURE ) {
	        if( !node->pkt->pkt.signature->flags.exportable )
		  continue; /* not exportable */

                /* delete our verification cache */
                delete_sig_subpkt (node->pkt->pkt.signature->unhashed,
                                   SIGSUBPKT_PRIV_VERIFY_CACHE);
	    }

	    if( secret == 2 && node->pkt->pkttype == PKT_SECRET_KEY ) {
		/* we don't want to export the secret parts of the
		 * primary key, this is done by using GNU protection mode 1001
		 */
		int save_mode = node->pkt->pkt.secret_key->protect.s2k.mode;
		node->pkt->pkt.secret_key->protect.s2k.mode = 1001;
		rc = build_packet( out, node->pkt );
		node->pkt->pkt.secret_key->protect.s2k.mode = save_mode;
	    }
	    else {
		rc = build_packet( out, node->pkt );
	    }

	    if( rc ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, g10_errstr(rc) );
		rc = G10ERR_WRITE_FILE;
		goto leave;
	    }
	}
	++*any;
    }
    if( rc == -1 )
	rc = 0;

  leave:
    keydb_release (kdbhd);
    release_kbnode( keyblock );
    if( !*any )
	log_info(_("WARNING: nothing exported\n"));
    return rc;
}

