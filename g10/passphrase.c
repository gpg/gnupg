/* passphrase.c -  Get a passphrase
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
#include <unistd.h>
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "options.h"
#include "ttyio.h"
#include "cipher.h"
#include "keydb.h"
#include "main.h"
#include "i18n.h"

static int pwfd = -1;
static char *next_pw = NULL;
static char *last_pw = NULL;

static void hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k, int create );

void
set_passphrase_fd( int fd )
{
    pwfd = fd;
}

int
get_passphrase_fd()
{
    return pwfd;
}

/****************
 * Set the passphrase to be used for the next query and only for the next
 * one.
 */
void
set_next_passphrase( const char *s )
{
    m_free(next_pw);
    next_pw = NULL;
    if( s ) {
	next_pw = m_alloc_secure( strlen(s)+1 );
	strcpy(next_pw, s );
    }
}

/****************
 * Get the last passphrase used in passphrase_to_dek.
 * Note: This removes the passphrase from this modules and
 * the caller must free the result.  May return NULL:
 */
char *
get_last_passphrase()
{
    char *p = last_pw;
    last_pw = NULL;
    return p;
}


/****************
 * Get a passphrase for the secret key with KEYID, display TEXT
 * if the user needs to enter the passphrase.
 * mode 0 = standard, 2 = create new passphrase
 * Returns: a DEK with a session key; caller must free
 *	    or NULL if the passphrase was not correctly repeated.
 *	    (only for mode 2)
 *	    a dek->keylen of 0 means: no passphrase entered.
 *	    (only for mode 2)
 */
DEK *
passphrase_to_dek( u32 *keyid, int cipher_algo, STRING2KEY *s2k, int mode )
{
    char *pw = NULL;
    DEK *dek;
    STRING2KEY help_s2k;

    if( !s2k ) {
	s2k = &help_s2k;
	s2k->mode = 0;
	/* this should be MD5 if cipher is IDEA, but because we do
	 * not have IDEA, we use the default one, the user
	 * can select it from the commandline
	 */
	s2k->hash_algo = opt.def_digest_algo?opt.def_digest_algo
					    :DEFAULT_DIGEST_ALGO;
    }

    if( keyid && !opt.batch && !next_pw ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	size_t n;
	char *p;

	tty_printf(_("\nYou need a passphrase to unlock the secret key for\n"
		     "user: \"") );
	p = get_user_id( keyid, &n );
	tty_print_string( p, n );
	m_free(p);
	tty_printf("\"\n");

	if( !get_pubkey( pk, keyid ) ) {
	    const char *s = pubkey_algo_to_string( pk->pubkey_algo );
	    tty_printf( _("(%u-bit %s key, ID %08lX, created %s)\n"),
		       nbits_from_pk( pk ), s?s:"?", (ulong)keyid[1],
		       strtimestamp(pk->timestamp) );
	}
	tty_printf("\n");
	free_public_key( pk );
    }
    if( next_pw ) {
	pw = next_pw;
	next_pw = NULL;
    }
    else if( pwfd != -1 ) { /* read the passphrase from the file */
	int i, len;

	if( !opt.batch )
	    tty_printf("Reading from file descriptor %d ...", pwfd );
	for( pw = NULL, i = len = 100; ; i++ ) {
	    if( i >= len-1 ) {
		char *pw2 = pw;
		len += 100;
		pw = m_alloc_secure( len );
		if( pw2 )
		    memcpy(pw, pw2, i );
		i=0;
	    }
	    if( read( pwfd, pw+i, 1) != 1 || pw[i] == '\n' )
		break;
	}
	pw[i] = 0;
	if( !opt.batch )
	    tty_printf("\b\b\b   \n" );
    }
    else if( opt.batch )
	log_fatal("Can't query password in batchmode\n");
    else {
	pw = tty_get_hidden("Enter pass phrase: " );
	tty_kill_prompt();
	if( mode == 2 ) {
	    char *pw2 = tty_get_hidden("Repeat pass phrase: " );
	    tty_kill_prompt();
	    if( strcmp(pw, pw2) ) {
		m_free(pw2);
		m_free(pw);
		return NULL;
	    }
	    m_free(pw2);
	}
    }
    dek = m_alloc_secure( sizeof *dek );
    dek->algo = cipher_algo;
    if( !*pw && mode == 2 )
	dek->keylen = 0;
    else
	hash_passphrase( dek, pw, s2k, mode==2 );
    m_free(last_pw);
    last_pw = pw;
    return dek;
}


/****************
 * Hash a passphrase using the supplied s2k. If create is true, create
 * a new salt or whatelse must be filled into the s2k for a new key.
 * always needs: dek->algo, s2k->mode, s2k->hash_algo.
 */
static void
hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k, int create )
{
    MD_HANDLE md;

    assert( s2k->hash_algo );
    dek->keylen = 0;
    md = md_open( s2k->hash_algo, 1);
    if( s2k->mode == 1 || s2k->mode == 3 ) {
	ulong count = 0;
	int len = strlen(pw);
	int len2 = len + 8;

	if( create )
	    randomize_buffer(s2k->salt, 8, 1);

	if( s2k->mode == 3 ) {
	    count = (16ul + (s2k->count & 15)) << ((s2k->count >> 4) + 6);
	    log_info("s2k iteration count=%lu\n", count );
	}
	for(;;) {
	    md_write( md, s2k->salt, 8 );
	    md_write( md, pw, len );
	    if( count <= len2 )
		break;
	    count -= len2;
	}
	if( count ) {
	    if( count < 8 )
		md_write( md, s2k->salt, count );
	    else {
		md_write( md, s2k->salt, 8 );
		count -= 8;
		assert( count <= len );
		md_write( md, pw, count );
	    }
	}
    }
    else
	md_write( md, pw, strlen(pw) );
    md_final( md );
    dek->keylen = cipher_get_keylen( dek->algo ) / 8;
    assert(dek->keylen > 0 && dek->keylen <= DIM(dek->key) );
    memcpy( dek->key, md_read(md,0), dek->keylen );
    md_close(md);
}

