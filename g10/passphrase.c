/* passphrase.c -  Get a passphrase
 *	Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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
#include "status.h"

static char *fd_passwd = NULL;
static char *next_pw = NULL;
static char *last_pw = NULL;

static void hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k, int create );

int
have_static_passphrase()
{
    return !!fd_passwd;
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


void
read_passphrase_from_fd( int fd )
{
    int i, len;
    char *pw;

    if( !opt.batch )
	tty_printf("Reading passphrase from file descriptor %d ...", fd );
    for( pw = NULL, i = len = 100; ; i++ ) {
	if( i >= len-1 ) {
	    char *pw2 = pw;
	    len += 100;
	    pw = m_alloc_secure( len );
	    if( pw2 )
		memcpy(pw, pw2, i );
	    else
		i=0;
	}
	if( read( fd, pw+i, 1) != 1 || pw[i] == '\n' )
	    break;
    }
    pw[i] = 0;
    if( !opt.batch )
	tty_printf("\b\b\b   \n" );

    m_free( fd_passwd );
    fd_passwd = pw;
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
 * pubkey_algo is only informational.
 */
DEK *
passphrase_to_dek( u32 *keyid, int pubkey_algo,
		   int cipher_algo, STRING2KEY *s2k, int mode )
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

    if( !next_pw && is_status_enabled() ) {
	char buf[50];
	if( keyid ) {
	    sprintf( buf, "%08lX%08lX", (ulong)keyid[0], (ulong)keyid[1] );
	    if( keyid[2] && keyid[3] && keyid[0] != keyid[2]
				     && keyid[1] != keyid[3] )
		sprintf( buf+strlen(buf), " %08lX%08lX %d 0",
			   (ulong)keyid[2], (ulong)keyid[3], pubkey_algo );
	    write_status_text( STATUS_NEED_PASSPHRASE, buf );
	}
	else {
	    sprintf( buf, "%d %d %d", cipher_algo, s2k->mode, s2k->hash_algo );
	    write_status_text( STATUS_NEED_PASSPHRASE_SYM, buf );
	}
    }

    if( keyid && !opt.batch && !next_pw ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	size_t n;
	char *p;

	tty_printf(_("\nYou need a passphrase to unlock the secret key for\n"
		     "user: \"") );
	p = get_user_id( keyid, &n );
	tty_print_utf8_string( p, n );
	m_free(p);
	tty_printf("\"\n");

	if( !get_pubkey( pk, keyid ) ) {
	    const char *s = pubkey_algo_to_string( pk->pubkey_algo );
	    tty_printf( _("%u-bit %s key, ID %08lX, created %s"),
		       nbits_from_pk( pk ), s?s:"?", (ulong)keyid[1],
		       strtimestamp(pk->timestamp) );
	    if( keyid[2] && keyid[3] && keyid[0] != keyid[2]
				     && keyid[1] != keyid[3] )
		tty_printf( _(" (main key ID %08lX)"), (ulong)keyid[3] );
	    tty_printf("\n");
	}

	tty_printf("\n");
	free_public_key( pk );
    }

    if( next_pw ) {
	pw = next_pw;
	next_pw = NULL;
    }
    else if( fd_passwd ) {
	pw = m_alloc_secure( strlen(fd_passwd)+1 );
	strcpy( pw, fd_passwd );
    }
    else if( opt.batch ) {
	log_error(_("can't query password in batchmode\n"));
	pw = m_strdup( "" ); /* return an empty passphrase */
    }
    else {
	pw = cpr_get_hidden("passphrase.enter", _("Enter passphrase: ") );
	tty_kill_prompt();
	if( mode == 2 && !cpr_enabled() ) {
	    char *pw2 = cpr_get_hidden("passphrase.repeat",
				       _("Repeat passphrase: ") );
	    tty_kill_prompt();
	    if( strcmp(pw, pw2) ) {
		m_free(pw2);
		m_free(pw);
		return NULL;
	    }
	    m_free(pw2);
	}
    }

    if( !pw || !*pw )
	write_status( STATUS_MISSING_PASSPHRASE );

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
 * a new salt or what else must be filled into the s2k for a new key.
 * always needs: dek->algo, s2k->mode, s2k->hash_algo.
 */
static void
hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k, int create )
{
    MD_HANDLE md;
    int pass, i;
    int used = 0;
    int pwlen = strlen(pw);

    assert( s2k->hash_algo );
    dek->keylen = cipher_get_keylen( dek->algo ) / 8;
    if( !(dek->keylen > 0 && dek->keylen <= DIM(dek->key)) )
	BUG();

    md = md_open( s2k->hash_algo, 1);
    for(pass=0; used < dek->keylen ; pass++ ) {
	if( pass ) {
	    if( (opt.emulate_bugs & EMUBUG_3DESS2K)) {
		int tmp = md->finalized;
		md_reset( md );
		md->finalized = tmp;
	    }
	    else
		md_reset(md);
	    for(i=0; i < pass; i++ ) /* preset the hash context */
		md_putc(md, 0 );
	}

	if( s2k->mode == 1 || s2k->mode == 3 ) {
	    int len2 = pwlen + 8;
	    ulong count = len2;

	    if( create && !pass ) {
		randomize_buffer(s2k->salt, 8, 1);
		if( s2k->mode == 3 )
		    s2k->count = 96; /* 65536 iterations */
	    }

	    if( s2k->mode == 3 ) {
		count = (16ul + (s2k->count & 15)) << ((s2k->count >> 4) + 6);
		if( count < len2 )
		    count = len2;
	    }
	    /* a little bit complicated because we need a ulong for count */
	    while( count > len2 ) { /* maybe iterated+salted */
		md_write( md, s2k->salt, 8 );
		md_write( md, pw, pwlen );
		count -= len2;
	    }
	    if( count < 8 )
		md_write( md, s2k->salt, count );
	    else {
		md_write( md, s2k->salt, 8 );
		count -= 8;
                md_write( md, pw, count );
	    }
	}
	else
	    md_write( md, pw, pwlen );
	md_final( md );
	i = md_digest_length( s2k->hash_algo );
	if( i > dek->keylen - used )
	    i = dek->keylen - used;
	memcpy( dek->key+used, md_read(md, s2k->hash_algo), i );
	used += i;
    }
    md_close(md);
}

