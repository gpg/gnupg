/* misc.c  -  utility functions
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
#include "util.h"
#include "cipher.h"


static struct { const char *name; int algo;} pubkey_names[] = {
    { "RSA",           PUBKEY_ALGO_RSA     },
    { "RSA-E",         PUBKEY_ALGO_RSA_E   },
    { "RSA-S",         PUBKEY_ALGO_RSA_S   },
    { "ELGAMAL",       PUBKEY_ALGO_ELGAMAL },
    { "ELG",           PUBKEY_ALGO_ELGAMAL },
    { "DSA",           PUBKEY_ALGO_DSA     },
    {NULL} };

static struct { const char *name; int algo;} digest_names[] = {
    { "MD5",           DIGEST_ALGO_MD5    },
    { "SHA1",          DIGEST_ALGO_SHA1   },
    { "SHA-1",         DIGEST_ALGO_SHA1   },
    { "RMD160",        DIGEST_ALGO_RMD160 },
    { "RMD-160",       DIGEST_ALGO_RMD160 },
    { "RIPE-MD-160",   DIGEST_ALGO_RMD160 },
    {NULL} };





/****************
 * Map a string to the pubkey algo
 */
int
string_to_pubkey_algo( const char *string )
{
    int i;
    const char *s;

    for(i=0; (s=pubkey_names[i].name); i++ )
	if( !stricmp( s, string ) )
	    return pubkey_names[i].algo;
    return 0;
}


/****************
 * Map a pubkey algo to a string
 */
const char *
pubkey_algo_to_string( int algo )
{
    int i;

    for(i=0; pubkey_names[i].name; i++ )
	if( pubkey_names[i].algo == algo )
	    return pubkey_names[i].name;
    return NULL;
}



/****************
 * Map a string to the digest algo
 */
int
string_to_digest_algo( const char *string )
{
    int i;
    const char *s;

    for(i=0; (s=digest_names[i].name); i++ )
	if( !stricmp( s, string ) )
	    return digest_names[i].algo;
    return 0;
}


/****************
 * Map a digest algo to a string
 */
const char *
digest_algo_to_string( int algo )
{
    int i;

    for(i=0; digest_names[i].name; i++ )
	if( digest_names[i].algo == algo )
	    return digest_names[i].name;
    return NULL;
}




int
check_pubkey_algo( int algo )
{
    return check_pubkey_algo2( algo, 0 );
}

/****************
 * a usage of 0 means: don't care
 */
int
check_pubkey_algo2( int algo, unsigned usage )
{
    switch( algo ) {
      case PUBKEY_ALGO_DSA:
	if( usage & 2 )
	    return G10ERR_WR_PUBKEY_ALGO;
	return 0;

      case PUBKEY_ALGO_ELGAMAL:
	return 0;

    #ifdef HAVE_RSA_CIPHER
      case PUBKEY_ALGO_RSA:
	return 0;
    #endif
      default:
	return G10ERR_PUBKEY_ALGO;
    }
}


int
check_digest_algo( int algo )
{
    switch( algo ) {
      case DIGEST_ALGO_MD5:
      case DIGEST_ALGO_RMD160:
      case DIGEST_ALGO_SHA1:
	return 0;
      default:
	return G10ERR_DIGEST_ALGO;
    }
}



