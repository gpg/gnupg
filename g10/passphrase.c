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

static int pwfd = -1;

static void hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k );

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
 * Get a passphrase for the secret key with KEYID, display TEXT
 * if the user needs to enter the passphrase.
 * Returns: m_alloced md5 passphrase hash; caller must free
 */
DEK *
get_passphrase_hash( u32 *keyid, char *text, byte *salt )
{
    char *pw;
    DEK *dek;

    if( keyid && !opt.batch ) {
	char *ustr;
	tty_printf("Need a pass phrase to unlock the secret key for:\n");
	tty_printf("  \"" );
	ustr = get_user_id_string( keyid );
	tty_print_string( ustr, strlen(ustr) );
	m_free(ustr);
	tty_printf("\"\n\n");

    }
    if( pwfd != -1 ) { /* read the passphrase from the given descriptor */
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
    }
    dek = m_alloc_secure( sizeof *dek );
    dek->algo = CIPHER_ALGO_BLOWFISH; /* fixme: allow others ciphers */
    if( hash_passphrase( dek, pw, salt ) )
	log_bug("get_passphrase_hash\n");
    m_free(pw); /* is allocated in secure memory, so it will be burned */
    return dek;
}


/****************
 * This function is used to construct a DEK from a user input.
 * It uses the default CIPHER.
 * Returns: 0 = okay, -1 No passphrase entered, > 0 error
 */
int
make_dek_from_passphrase( DEK *dek, int mode, STRING2KEY *s2k )
{
    char *pw, *pw2;
    int rc=0;

    pw = tty_get_hidden("Enter pass phrase: " );
    tty_kill_prompt();
    if( mode == 2 ) {
	pw2 = tty_get_hidden("Repeat pass phrase: " );
	tty_kill_prompt();
	if( strcmp(pw, pw2) ) {
	    m_free(pw2);
	    m_free(pw);
	    return G10ERR_PASSPHRASE;
	}
	m_free(pw2);
    }
    if( !*pw )
	rc = -1;
    else
	hash_passphrase( dek, pw, s2k, mode==2 );
    m_free(pw);
    return rc;
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
    int rc = 0;

    assert( s2k->hash_algo );
    dek->keylen = 0;
    md = md_open( s2k->hash_algo, 1);
    if( s2k->mode == 1 || s2k->mode == 4 ) {
	if( create )
	    randomize_buffer(&s2k->salt, 8, 1);
	md_write( md, s2k->salt, 8 );
    }
    md_write( md, pw, strlen(pw) );
    md_final( md );
    dek->keylen = cipher_get_keylen( dek->algo );
    assert(dek->keylen > 0 && dek->keylen < DIM(dek->key) );
    memcpy( dek->key, md_read(md,0), dek->keylen );
    md_close(md);
}

