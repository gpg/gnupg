/* hkp.c  -  Horrowitz Keyserver Protocol
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
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include "errors.h"
#include "util.h"
#include "ttyio.h"
#include "i18n.h"
#include "options.h"
#include "filter.h"
#include "http.h"
#include "main.h"

static int urlencode_filter( void *opaque, int control,
			     IOBUF a, byte *buf, size_t *ret_len);

/****************
 * Try to import the key with KEYID from a keyserver but ask the user
 * before doing so.
 * Returns: 0 the key was successfully imported
 *	    -1 key not found on server or user does not want to
 *	       import the key
 *	    or other error codes.
 */
int
hkp_ask_import( u32 *keyid, void *stats_handle)
{
    struct http_context hd;
    char *request;
    int rc;
    unsigned int hflags = opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY : 0;

    if( !opt.keyserver_name )
	return -1;
    log_info(_("requesting key %08lX from %s ...\n"), (ulong)keyid[1],
						   opt.keyserver_name );
    request = m_alloc( strlen( opt.keyserver_name ) + 100 );
    /* hkp does not accept the long keyid - we should really write a
     * nicer one :-)
     * FIXME: request binary mode - need to pass no_armor mode
     * down to the import function.  Marc told that there is such a
     * binary mode ... how?
     */
    if ( !strncmp (opt.keyserver_name, "x-broken-hkp://", 15) ) {
        sprintf( request, "x-hkp://%s/pks/lookup?op=get&search=0x%08lX",
			opt.keyserver_name+15, (ulong)keyid[1] );
        hflags |= HTTP_FLAG_NO_SHUTDOWN;
    }
    else if ( !strncmp (opt.keyserver_name, "x-hkp://", 8) ) {
        sprintf( request, "%s/pks/lookup?op=get&search=0x%08lX",
			opt.keyserver_name, (ulong)keyid[1] );
    }
    else {
        sprintf( request, "x-hkp://%s:11371/pks/lookup?op=get&search=0x%08lX",
			opt.keyserver_name, (ulong)keyid[1] );
    }
    rc = http_open_document( &hd, request, hflags );
    if( rc ) {
	log_info(_("can't get key from keyserver: %s\n"),
			rc == G10ERR_NETWORK? strerror(errno)
					    : g10_errstr(rc) );
    }
    else {
	rc = import_keys_stream( hd.fp_read , 0, stats_handle );
	http_close( &hd );
    }

    m_free( request );
    return rc;
}



int
hkp_import( STRLIST users )
{
    void *stats_handle;

    if( !opt.keyserver_name ) {
	log_error(_("no keyserver known (use option --keyserver)\n"));
	return -1;
    }

    stats_handle = import_new_stats_handle ();
    for( ; users; users = users->next ) {
        KEYDB_SEARCH_DESC desc;

	classify_user_id (users->d, &desc);
	if(    desc.mode != KEYDB_SEARCH_MODE_SHORT_KID
            && desc.mode != KEYDB_SEARCH_MODE_LONG_KID ) {
	    log_error (_("%s: not a valid key ID\n"), users->d );
	    continue;
	}
	/* because the function may use log_info in some situations, the
	 * errorcounter ist not increaed and the program will return
	 * with success - which is not good when this function is used.
	 */
	if( hkp_ask_import( desc.u.kid, stats_handle ) )
	    log_inc_errorcount();
    }
    import_print_stats (stats_handle);
    import_release_stats_handle (stats_handle);
    return 0;
}


int
hkp_export( STRLIST users )
{
    int rc;
    armor_filter_context_t afx;
    IOBUF temp = iobuf_temp();
    struct http_context hd;
    char *request;
    unsigned int status;
    unsigned int hflags = opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY : 0;

    if( !opt.keyserver_name ) {
	log_error(_("no keyserver known (use option --keyserver)\n"));
	return -1;
    }

    iobuf_push_filter( temp, urlencode_filter, NULL );

    memset( &afx, 0, sizeof afx);
    afx.what = 1;
    iobuf_push_filter( temp, armor_filter, &afx );

    rc = export_pubkeys_stream( temp, users, 1 );
    if( rc == -1 ) {
	iobuf_close(temp);
	return 0;
    }

    iobuf_flush_temp( temp );

    request = m_alloc( strlen( opt.keyserver_name ) + 100 );
    if ( !strncmp (opt.keyserver_name, "x-broken-hkp://", 15) ) {
        sprintf( request, "x-hkp://%s/pks/add", opt.keyserver_name+15 );
        hflags |= HTTP_FLAG_NO_SHUTDOWN;
    }
    else if ( !strncmp (opt.keyserver_name, "x-hkp://", 8) ) {
        sprintf( request, "%s/pks/add", opt.keyserver_name );
    }
    else {
        sprintf( request, "x-hkp://%s:11371/pks/add", opt.keyserver_name );
    }
    rc = http_open( &hd, HTTP_REQ_POST, request , hflags );
    if( rc ) {
	log_error(_("can't connect to `%s': %s\n"),
		   opt.keyserver_name,
			rc == G10ERR_NETWORK? strerror(errno)
					    : g10_errstr(rc) );
	iobuf_close(temp);
	m_free( request );
	return rc;
    }

    sprintf( request, "Content-Length: %u\n",
		      (unsigned)iobuf_get_temp_length(temp) + 9 );
    iobuf_writestr( hd.fp_write, request );
    m_free( request );
    http_start_data( &hd );

    iobuf_writestr( hd.fp_write, "keytext=" );
    iobuf_write( hd.fp_write, iobuf_get_temp_buffer(temp),
			      iobuf_get_temp_length(temp) );
    iobuf_put( hd.fp_write, '\n' );
    iobuf_flush_temp( temp );
    iobuf_close(temp);

    rc = http_wait_response( &hd, &status );
    if( rc ) {
	log_error(_("error sending to `%s': %s\n"),
		   opt.keyserver_name, g10_errstr(rc) );
    }
    else {
      #if 1
	if( opt.verbose ) {
	    int c;
	    while( (c=iobuf_get(hd.fp_read)) != EOF )
		putchar( c );
	}
      #endif
	if( (status/100) == 2 )
	    log_info(_("success sending to `%s' (status=%u)\n"),
					opt.keyserver_name, status  );
	else
	    log_error(_("failed sending to `%s': status=%u\n"),
					opt.keyserver_name, status  );
    }
    http_close( &hd );
    return rc;
}

static int
urlencode_filter( void *opaque, int control,
		  IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    int rc=0;

    if( control == IOBUFCTRL_FLUSH ) {
	const byte *p;
	for(p=buf; size; p++, size-- ) {
	    if( isalnum(*p) || *p == '-' )
		iobuf_put( a, *p );
	    else if( *p == ' ' )
		iobuf_put( a, '+' );
	    else {
		char numbuf[5];
		sprintf(numbuf, "%%%02X", *p );
		iobuf_writestr(a, numbuf );
	    }
	}
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "urlencode_filter";
    return rc;
}


int
hkp_refresh_keys (void)
{
    KEYDB_HANDLE hd;
    KBNODE node, keyblock = NULL;
    PKT_public_key *pk;
    u32 keyid[2];
    u32 *keys = NULL;
    size_t n, nkeys=0, maxkeys=0;
    void *stats_handle;
    int rc = 0;

    /* fist take a snapshot of all keys */
    hd = keydb_new(0);
    rc = keydb_search_first(hd);
    if (rc) {
        if (rc != -1)
            log_error ("keydb_search_first failed: %s\n", g10_errstr(rc));
        goto leave;
    }
	
    do {
        if (!keys) {
            maxkeys = 10000;
            keys = m_alloc (maxkeys * sizeof *keys);
            nkeys = 0;
        }
        else if ( nkeys == maxkeys ) {
            maxkeys += 10000;
            keys = m_realloc (keys, maxkeys * sizeof *keys);
        }

        rc = keydb_get_keyblock (hd, &keyblock);
        if (rc) {
            log_error ("keydb_get_keyblock failed: %s\n", g10_errstr(rc));
            goto leave;
        }

        node = keyblock;
        if ( node->pkt->pkttype != PKT_PUBLIC_KEY) {
            log_debug ("invalid pkttype %d encountered\n",
                       node->pkt->pkttype);
            dump_kbnode (node);
            release_kbnode(keyblock);
            continue;
        }
        pk = node->pkt->pkt.public_key;
        keyid_from_pk(pk, keyid);
        release_kbnode(keyblock);
        keyblock = NULL;
        /* fixme: replace the linear search */
        for (n=0; n < nkeys; n++) {
            if (keys[n] == keyid[1]) {
                log_info (_("duplicate (short) key ID %08lX\n"),
                          (ulong)keyid[1]);
                break;
            }
        }
        if (n == nkeys) /* not a duplicate */
            keys[nkeys++] = keyid[1];
    } while ( !(rc = keydb_search_next(hd)) );
    if (rc == -1)
        rc = 0;
    if (rc)
        log_error ("keydb_search_next failed: %s\n", g10_errstr(rc));
    keydb_release(hd);
    hd = NULL;
    
    /* and now refresh them */
    stats_handle = import_new_stats_handle ();
    log_info (_("%lu key(s) to refresh\n"), (ulong)nkeys);
    for (n=0; n < nkeys; n++) {
        /* Note: We do only use the short keyID */
        keyid[0] = 0;
        keyid[1] = keys[n];
        if ( hkp_ask_import(keyid, stats_handle) )
            log_inc_errorcount();
    }
    import_print_stats (stats_handle);
    import_release_stats_handle (stats_handle);

 leave:
    m_free (keys);
    if (keyblock)
        release_kbnode(keyblock);
    keydb_release(hd);
    return rc;
}

