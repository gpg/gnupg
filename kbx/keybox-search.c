/* keybox-search.c - Search operations
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "keybox-defs.h"


/****************
 * Check whether the given fingerprint (20 bytes) is in the
 * given keyblob.  fpr is always 20 bytes.
 * Return: 0 = found
 *	   -1 = not found
	  other = error  (fixme: do not always reurn gpgerr_general)
 */
int
keybox_blob_has_fpr ( KEYBOXBLOB blob, const byte *fpr )
{
    ulong n, nkeys, keyinfolen;
    const byte *p, *pend;
    byte *buffer = blob->blob;
    size_t buflen = blob->bloblen;

    if ( buflen < 40 )
	return GPGERR_GENERAL; /* blob too short */
    n = get32( buffer );
    if ( n > buflen )
	return GPGERR_GENERAL; /* blob larger than announced length */
    buflen = n;  /* ignore trailing stuff */
    pend = buffer + n - 1;

    if ( buffer[4] != 2 )
	return GPGERR_GENERAL; /* invalid blob type */
    if ( buffer[5] != 1 )
	return GPGERR_GENERAL; /* invalid blob format version */

    nkeys = get16( buffer + 16 );
    keyinfolen = get16( buffer + 18 );
    p = buffer + 20;
    for(n=0; n < nkeys; n++, p += keyinfolen ) {
	if ( p+20 > pend )
	    return GPGERR_GENERAL; /* blob shorter than required */
	if (!memcmp ( p, fpr, 20 ) )
	    return 0; /* found */
    }
    return -1;
}

/****************
 * Check whether the given keyID (20 bytes) is in the
 * given keyblob.
 * Return: 0 = found
 *	   -1 = not found
	  other = error  (fixme: do not always return gpgerr_general)
 */
int
keybox_blob_has_kid ( KEYBOXBLOB blob, const byte *keyidbuf, size_t keyidlen )
{
    ulong n, nkeys, keyinfolen, off;
    const byte *p, *pend;
    byte *buffer = blob->blob;
    size_t buflen = blob->bloblen;

    if ( buflen < 40 )
	return GPGERR_GENERAL; /* blob too short */
    n = get32( buffer );
    if ( n > buflen )
	return GPGERR_GENERAL; /* blob larger than announced length */
    buflen = n;  /* ignore trailing stuff */
    pend = buffer + n - 1;

    if ( buffer[4] != 2 )
	return GPGERR_GENERAL; /* invalid blob type */
    if ( buffer[5] != 1 )
	return GPGERR_GENERAL; /* invalid blob format version */

    nkeys = get16( buffer + 16 );
    keyinfolen = get16( buffer + 18 );
    p = buffer + 20;
    for(n=0; n < nkeys; n++, p += keyinfolen ) {
	if ( p+24 > pend )
	    return GPGERR_GENERAL; /* blob shorter than required */
	off = get32 ( p + 20 );
	if (keyidlen < 8 ) /* actually keyidlen may either be 4 or 8 */
	    off +=4;
	if ( off+keyidlen > buflen )
	    return GPGERR_GENERAL; /* offset out of bounds */
	if ( !memcmp ( buffer+off, keyidbuf, keyidlen ) )
	    return 0; /* found */
    }
    return -1;
}



int
keybox_blob_has_uid ( KEYBOXBLOB blob,
		   int (*cmp)(const byte *, size_t, void *), void *opaque )
{
    ulong n, nuids, uidinfolen, off, len;
    const byte *p, *pend;
    byte *buffer = blob->blob;
    size_t buflen = blob->bloblen;

    if ( buflen < 40 )
	return GPGERR_GENERAL; /* blob too short */
    n = get32( buffer );
    if ( n > buflen )
	return GPGERR_GENERAL; /* blob larger than announced length */
    buflen = n;  /* ignore trailing stuff */
    pend = buffer + n - 1;

    if ( buffer[4] != 2 )
	return GPGERR_GENERAL; /* invalid blob type */
    if ( buffer[5] != 1 )
	return GPGERR_GENERAL; /* invalid blob format version */

    p = buffer + 20 + get16( buffer + 16 ) * get16( buffer + 18 );
    if ( p+4 > pend )
	return GPGERR_GENERAL; /* blob shorter than required */

    nuids = get16( p ); p+= 2;
    uidinfolen = get16( p ); p+=2;
    for(n=0; n < nuids; n++, p += uidinfolen ) {
	if ( p+8 > pend )
	    return GPGERR_GENERAL; /* blob shorter than required */
	off = get32 ( p );
	len = get32 ( p + 4 );
	if ( off+len > buflen )
	    return GPGERR_GENERAL; /* offset out of bounds */
	if ( (*cmp) ( buffer+off, len, opaque ) )
	    return 0; /* found */
    }

    return -1;
}


