/* hkp.c  -  Horrowitz Keyserver Protocol
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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

#include "errors.h"
#include "util.h"
#include "ttyio.h"
#include "i18n.h"
#include "options.h"
#include "http.h"
#include "main.h"


/****************
 * Try to import the key with KEYID from a keyserver but ask the user
 * before doing so.
 * Returns: 0 the key was successfully imported
 *	    -1 key not found on server or user does not want to
 *	       import the key
 *	    or other error codes.
 */
int
hkp_ask_import( u32 *keyid )
{
    struct http_context hd;
    char *request;
    int rc;

    if( !opt.keyserver_name )
	return -1;
    log_info("requesting key %08lX from %s ...\n", (ulong)keyid[1],
						   opt.keyserver_name );
    request = m_alloc( strlen( opt.keyserver_name ) + 100 );
    /* hkp does not accept the long keyid - we should really write a
     * nicer one */
    sprintf( request, "x-hkp://%s:11371/pks/lookup?op=get&search=0x%08lX",
			opt.keyserver_name, (ulong)keyid[1] );
    rc = open_http_document( &hd, request, 0 );
    if( rc ) {
	log_info("can't get key from keyserver: %s\n", g10_errstr(rc) );
	goto leave;
    }
    rc = import_keys_stream( hd.fp_read , 0 );
    close_http_document( &hd );

  leave:
    m_free( request );
    return rc;
}


