/* passphrase.c -  Get a passphrase
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "ttyio.h"
#include "cipher.h"
#include "keydb.h"


static int hash_passphrase( DEK *dek, char *pw );


/****************
 * Get a passphrase for the secret key with KEYID, display TEXT
 * if the user needs to enter the passphrase.
 * Returns: m_alloced md5 passphrase hash; caller must free
 */
DEK *
get_passphrase_hash( u32 *keyid, char *text )
{
    char *p=NULL, *pw;
    DEK *dek;

    if( keyid ) {
	char *ustr;
	tty_printf("\nNeed a pass phrase to unlock the secret key!\n");
	tty_printf("KeyID: " );
	ustr = get_user_id_string( keyid );
	tty_print_string( ustr, strlen(ustr) );
	m_free(ustr);
	tty_printf("\n\n");

    }
    if( keyid && (p=getenv("G10PASSPHRASE")) ) {
	pw = m_alloc_secure(strlen(p)+1);
	strcpy(pw,p);
	tty_printf("Taking it from $G10PASSPHRASE !\n",  keyid[1] );
    }
    else
	pw = tty_get_hidden("Enter pass phrase: " );
    dek = m_alloc_secure( sizeof *dek );
    dek->algo = CIPHER_ALGO_BLOWFISH;
    if( hash_passphrase( dek, pw ) )
	log_bug("get_passphrase_hash\n");
    m_free(pw); /* is allocated in secure memory, so it will be burned */
    if( !p ) {
	tty_kill_prompt();
	tty_printf("\n");
    }
    return dek;
}


/****************
 * This function is used to construct a DEK from a user input.
 * It uses the default CIPHER
 * Returns: 0 = okay, -1 No passphrase entered, > 0 error
 */
int
make_dek_from_passphrase( DEK *dek, int mode )
{
    char *pw, *pw2;
    int rc=0;

    pw = tty_get_hidden("Enter pass phrase: " );
    tty_kill_prompt();
    if( mode == 2 ) {
	pw2 = tty_get_hidden("Repeat pass phrase: " );
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
	rc = hash_passphrase( dek, pw );
    m_free(pw);
    return rc;
}


static int
hash_passphrase( DEK *dek, char *pw )
{
    int rc = 0;

    dek->keylen = 0;
    if( dek->algo == CIPHER_ALGO_BLOWFISH ) {
	RMDHANDLE rmd;

	rmd = rmd160_open(1);
	rmd160_write( rmd, pw, strlen(pw) );
	dek->keylen = 20;
	memcpy( dek->key, rmd160_final(rmd), dek->keylen );
	rmd160_close(rmd);
    }
    else
	rc = G10ERR_UNSUPPORTED;
    return rc;
}

