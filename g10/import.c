/* import.c
 *	Copyright (c) 1998 by Werner Koch (dd9jn)
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

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"


/****************
 * Import the public keys from the given filename.
 * Import is a somewhat misleading name, as we (only) add informations
 * about the public keys into aout trustdb.
 *
 * NOTE: this function is not really needed and will be changed to
 *	a function which reads a plain textfile, describing a public
 *	key and its associated ownertrust.  This can be used (together
 *	with the export function) to make a backup of the assigned
 *	ownertrusts.
 */
int
import_pubkeys( const char *filename )
{
    int rc;
    PACKET pkt;
    int save_mode;
    ulong offset;
    IOBUF iobuf = NULL;

    init_packet(&pkt);
    save_mode = set_packet_list_mode(0);

    if( !(iobuf = iobuf_open( filename )) ) {
	rc = G10ERR_KEYRING_OPEN;
	goto leave;
    }

    while( !(rc=search_packet(iobuf, &pkt, PKT_PUBLIC_CERT, &offset)) ) {
	PKT_public_cert *pkc = pkt.pkt.public_cert;
	u32 keyid[2];
	int otrust;

	assert( pkt.pkttype == PKT_PUBLIC_CERT );

	keyid_from_pkc( pkc, keyid );
	rc = get_ownertrust( pkc, &otrust );
	if( rc && rc != -1  ) {
	    log_error("error getting otrust of %08lX: %s\n",
					      keyid[1], g10_errstr(rc) );
	}
	else if( rc == -1 ) { /* No pubkey in trustDB: Insert */
	    rc = insert_trust_record( pkc );
	    if( rc ) {
		log_error("failed to insert it into the trustdb: %s\n",
							  g10_errstr(rc) );
	    }
	    else {
		rc = get_ownertrust( pkc, &otrust );
		if( rc )
		    log_fatal("failed to reread the pubkey record: %s\n",
							      g10_errstr(rc) );
		log_info("key %08lX inserted in trustdb (localid=%lu)\n",
						 keyid[1], pkc->local_id );
	    }
	}
	else
	    log_info("key %08lX  already in trustdb (localid=%lu)\n",
					     keyid[1], pkc->local_id );

	free_packet(&pkt);
    }

    iobuf_close(iobuf);
    if( !(iobuf = iobuf_open( filename )) ) {
	rc = G10ERR_KEYRING_OPEN;
	goto leave;
    }

    while( !(rc=search_packet(iobuf, &pkt, PKT_PUBLIC_CERT, &offset)) ) {
	PKT_public_cert *pkc = pkt.pkt.public_cert;
	u32 keyid[2];
	int trustlevel;

	assert( pkt.pkttype == PKT_PUBLIC_CERT );

	keyid_from_pkc( pkc, keyid );
	rc = check_pkc_trust( pkc, &trustlevel );
	if( rc ) {
	    log_error("error checking trust of %08lX: %s\n",
					      keyid[1], g10_errstr(rc) );
	}
	else if( trustlevel & TRUST_NO_PUBKEY ) {
	    /* No pubkey in trustDB: Insert and check again */
	    rc = insert_trust_record( pkc );
	    if( rc ) {
		log_error("failed to insert it into the trustdb: %s\n",
							  g10_errstr(rc) );
	    }
	    else {
		rc = check_pkc_trust( pkc, &trustlevel );
		if( rc )
		    log_fatal("trust check after insert failed: %s\n",
							      g10_errstr(rc) );
		if( trustlevel & TRUST_NO_PUBKEY )
		    BUG();
	    }
	}

	free_packet(&pkt);
    }

  leave:
    iobuf_close(iobuf);
    free_packet(&pkt);
    set_packet_list_mode(save_mode);
    return rc;
}


