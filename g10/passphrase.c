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

static int pwfd = -1;

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
    char *pw;
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
    m_free(pw); /* is allocated in secure memory, so it will be burned */
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
    if( s2k->mode == 1 || s2k->mode == 4 ) {
	if( create )
	    randomize_buffer(s2k->salt, 8, 1);
	md_write( md, s2k->salt, 8 );
    }
    md_write( md, pw, strlen(pw) );
    md_final( md );
    dek->keylen = cipher_get_keylen( dek->algo ) / 8;
    assert(dek->keylen > 0 && dek->keylen <= DIM(dek->key) );
    memcpy( dek->key, md_read(md,0), dek->keylen );
    md_close(md);
}

