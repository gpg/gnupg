/* kbxfile.c - KBX file handling
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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

/****************
 * We will change the whole system to use only KBX.  This file here
 * will implement the methods needed to operate on plain KBXfiles.
 * Most stuff from getkey and ringedit will be replaced by stuff here.
 * To make things even more easier we will only allow one updateable kbxfile
 * and optionally some read-only files.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <gcrypt.h>

#include "kbx.h"
#include "options.h"
#include "util.h"
#include "i18n.h"
#include "main.h"

/****************
 * Read the blob at the current fileposition and return an allocated
 * pointer nto the blob if it was found.
 * Fixme: return a blob object.
 */
static int
do_search_by_fpr ( const char *filename, FILE *a, const char *fpr,
						  KBXBLOB *r_blob )
{
    KBXBLOB blob;
    int rc;

    *r_blob = NULL;
    rc = kbx_read_blob ( &blob, a );
    if ( rc && rc != -1 ) {
	log_error (_("file `%s': error reading blob\n"), filename );
    }
    else if ( !rc ) {
	rc = kbx_blob_has_fpr ( blob, fpr );
    }
    else
	log_info ("eof\n");

    if ( !rc ) {
	*r_blob = blob;
    }
    else {
	kbx_release_blob ( blob );
    }
    return rc;
}

int
kbxfile_search_by_fpr( const char *filename, const byte *fpr )
{
    FILE *fp;
    KBXBLOB blob;
    int rc;

    fp = fopen ( filename, "rb" );
    if( !fp ) {
	log_error(_("can't open `%s': %s\n"), filename, strerror(errno) );
	return 1;
    }

    while ( (rc=do_search_by_fpr ( filename, fp, fpr, &blob )) == -1 )
	;
    if ( !rc ) {
	fputs ("FOUND\n", stderr );
	kbx_dump_blob ( stderr, blob );
	kbx_release_blob ( blob );
    }

    fclose (fp);
    return -1;
}


/****************
 * Read the blob at the current fileposition and return an allocated
 * pointer nto the blob if it was found.
 * Fixme: return a blob object.
 */
static int
do_search_by_keyid ( const char *filename, FILE *a,
		     const byte *keyidbuf, size_t keyidlen, KBXBLOB *r_blob )
{
    KBXBLOB blob;
    int rc;

    *r_blob = NULL;
    rc = kbx_read_blob ( &blob, a );
    if ( rc && rc != -1 ) {
	log_error (_("file `%s': error reading blob\n"), filename );
    }
    else if ( !rc ) {
	rc = kbx_blob_has_kid ( blob, keyidbuf, keyidlen );
    }
    else
	rc = GPGERR_GENERAL;  /* eof */

    if ( !rc ) {
	*r_blob = blob;
    }
    else {
	kbx_release_blob ( blob );
    }
    return rc;
}

/****************
 * Look for a KBX described by an keyid.  This function will in
 * turn return each matching keyid because there may me duplicates
 * (which can't happen for fingerprints)
 * mode 10 = short keyid
 *	11 = long keyid
 */
int
kbxfile_search_by_kid ( const char *filename, u32 *kid, int mode )
{
    FILE *fp;
    KBXBLOB blob;
    int rc;
    byte kbuf[8], *kbufptr;
    int kbuflen;

    fp = fopen ( filename, "rb" );
    if( !fp ) {
	log_error(_("can't open `%s': %s\n"), filename, strerror(errno) );
	return 1;
    }

    kbuf[0] = kid[0] >> 24;
    kbuf[1] = kid[0] >> 16;
    kbuf[2] = kid[0] >> 8;
    kbuf[3] = kid[0];
    kbuf[4] = kid[1] >> 24;
    kbuf[5] = kid[1] >> 16;
    kbuf[6] = kid[1] >> 8;
    kbuf[7] = kid[1];
    if ( mode == 10 ) {
	kbufptr=kbuf+4;
	kbuflen = 4;
    }
    else if (mode == 11 ) {
	kbufptr=kbuf;
	kbuflen = 8;
    }
    else {
	BUG();
    }

    do {
	while ( (rc=do_search_by_keyid ( filename, fp,
					 kbufptr, kbuflen, &blob )) == -1 )
	    ;
	if ( !rc ) {
	    fputs ("FOUND:\n", stderr );
	    kbx_dump_blob ( stderr, blob );
	    kbx_release_blob ( blob );
	}
    } while ( !rc );

    fclose (fp);
    return -1;
}


static int
do_search_by_uid ( const char *filename, FILE *a,
		    int (*cmpfnc)(const byte*,size_t,void*), void *cmpdata,
							   KBXBLOB *r_blob )
{
    KBXBLOB blob;
    int rc;

    *r_blob = NULL;
    rc = kbx_read_blob ( &blob, a );
    if ( rc && rc != -1 ) {
	log_error (_("file `%s': error reading blob\n"), filename );
    }
    else if ( !rc ) {
	rc = kbx_blob_has_uid ( blob, cmpfnc, cmpdata );
    }
    else
	rc = GPGERR_GENERAL;  /* eof */

    if ( !rc ) {
	*r_blob = blob;
    }
    else {
	kbx_release_blob ( blob );
    }
    return rc;
}


static int
substr_compare ( const byte *buf, size_t buflen, void *opaque )
{
    return !!memistr ( buf, buflen, opaque );
}


int
kbxfile_search_by_uid ( const char *filename, const char *name )
{
    FILE *fp;
    KBXBLOB blob;
    int rc;
    byte kbuf[8], *kbufptr;
    int kbuflen;

    fp = fopen ( filename, "rb" );
    if( !fp ) {
	log_error(_("can't open `%s': %s\n"), filename, strerror(errno) );
	return 1;
    }


    do {
	while ( (rc=do_search_by_uid ( filename, fp,
					substr_compare, name, &blob )) == -1 )
	    ;
	if ( !rc ) {
	    fputs ("FOUND:\n", stderr );
	    kbx_dump_blob ( stderr, blob );
	    kbx_release_blob ( blob );
	}
    } while ( !rc );

    fclose ( fp );
    return -1;
}



void
export_as_kbxfile(void)
{

    KBPOS kbpos;
    KBNODE keyblock = NULL;
    int rc=0;

    rc = enum_keyblocks( 0, &kbpos, &keyblock );
    if( rc ) {
	if( rc != -1 )
	    log_error("enum_keyblocks(open) failed: %s\n", gpg_errstr(rc) );
	goto leave;
    }

    while( !(rc = enum_keyblocks( 1, &kbpos, &keyblock )) ) {
	KBXBLOB blob;
	const char *p;
	size_t n;

	merge_keys_and_selfsig( keyblock );
	rc = kbx_create_blob ( &blob, keyblock );
	if( rc ) {
	    log_error("kbx_create_blob failed: %s\n", gpg_errstr(rc) );
	    goto leave;
	}
	p = kbx_get_blob_image ( blob, &n );
	fwrite( p, n, 1, stdout );
	kbx_release_blob ( blob );
    }

    if( rc && rc != -1 )
	log_error("enum_keyblocks(read) failed: %s\n", gpg_errstr(rc));

  leave:
    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
}


static int
do_print_kbxfile( const char *filename, FILE *a )
{
    KBXBLOB blob;
    int rc;

    rc = kbx_read_blob ( &blob, a );
    if ( rc && rc != -1 ) {
	log_error (_("file `%s': error reading blob\n"), filename );
    }
    else if ( ! rc )
	kbx_dump_blob ( stdout, blob );
    kbx_release_blob ( blob );
    return rc;
}

void
print_kbxfile( const char *filename )
{
    FILE *fp;

    fp = fopen ( filename, "rb" );
    if( !fp ) {
	log_error(_("can't open `%s': %s\n"), filename, strerror(errno) );
	return;
    }

    while ( !do_print_kbxfile( filename, fp ) )
	;

    fclose (fp);
}

