/* pkclist.c
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

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"


/****************
 * Check wether we can trust this pkc which has a trustlevel of TRUSTLEVEL
 * Returns: true if we trust.
 */
static int
do_we_trust( PKT_public_cert *pkc, int trustlevel )
{
    /* Eventuell fragen falls der trustlevel nicht ausreichend ist */


    return 1; /* yes */
}



void
release_pkc_list( PKC_LIST pkc_list )
{
    PKC_LIST pkc_rover;

    for( ; pkc_list; pkc_list = pkc_rover ) {
	pkc_rover = pkc_list->next;
	free_public_cert( pkc_list->pkc );
	m_free( pkc_list );
    }
}

int
build_pkc_list( STRLIST remusr, PKC_LIST *ret_pkc_list )
{
    PKC_LIST pkc_list = NULL;
    PKC_LIST pkc_rover = NULL;
    int rc;

    if( !remusr ) { /* ask!!! */
	log_bug("ask for public key nyi\n");
    }
    else {
	for(; remusr; remusr = remusr->next ) {
	    PKT_public_cert *pkc;

	    pkc = m_alloc_clear( sizeof *pkc );
	    if( (rc = get_pubkey_byname( pkc, remusr->d )) ) {
		free_public_cert( pkc ); pkc = NULL;
		log_error("skipped '%s': %s\n", remusr->d, g10_errstr(rc) );
	    }
	    else if( !(rc=check_pubkey_algo(pkc->pubkey_algo)) ) {
		int trustlevel;

		rc = check_pkc_trust( pkc, &trustlevel );
		if( rc ) {
		    free_public_cert( pkc ); pkc = NULL;
		    log_error("error checking pkc of '%s': %s\n",
						      remusr->d, g10_errstr(rc) );
		}
		else if( do_we_trust( pkc, trustlevel ) ) {
		    PKC_LIST r;

		    r = m_alloc( sizeof *r );
		    r->pkc = pkc; pkc = NULL;
		    r->next = pkc_list;
		    r->mark = 0;
		    pkc_list = r;
		}
		else { /* we don't trust this pkc */
		    free_public_cert( pkc ); pkc = NULL;
		}
	    }
	    else {
		free_public_cert( pkc ); pkc = NULL;
		log_error("skipped '%s': %s\n", remusr->d, g10_errstr(rc) );
	    }
	}
    }


    if( !rc && !pkc_list ) {
	log_error("no valid addressees\n");
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_pkc_list( pkc_list );
    else
	*ret_pkc_list = pkc_list;
    return rc;
}


