/* keygen.c - generate a key pair
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
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"
#include "ttyio.h"
#include "options.h"

static int
answer_is_yes( const char *s )
{
    if( !stricmp(s, "yes") )
	return 1;
    if( *s == 'y' && !s[1] )
	return 1;
    if( *s == 'Y' && !s[1] )
	return 1;
    return 0;
}


static void
write_comment( IOBUF out, const char *s )
{
    PACKET pkt;
    size_t n = strlen(s);
    int rc;

    pkt.pkttype = PKT_COMMENT;
    pkt.pkt.comment = m_alloc( sizeof *pkt.pkt.comment + n - 1 );
    pkt.pkt.comment->len = n;
    strcpy(pkt.pkt.comment->data, s);
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet(comment) failed: %s\n", g10_errstr(rc) );
    free_packet( &pkt );
}

static void
write_uid( IOBUF out, const char *s )
{
    PACKET pkt;
    size_t n = strlen(s);
    int rc;

    pkt.pkttype = PKT_USER_ID;
    pkt.pkt.user_id = m_alloc( sizeof *pkt.pkt.user_id + n - 1 );
    pkt.pkt.user_id->len = n;
    strcpy(pkt.pkt.user_id->name, s);
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet(user_id) failed: %s\n", g10_errstr(rc) );
    free_packet( &pkt );
}


static int
gen_rsa(unsigned nbits, IOBUF pub_io, IOBUF sec_io)
{
    int rc;
    PACKET pkt1, pkt2;
    PKT_seckey_cert *skc;
    PKT_pubkey_cert *pkc;
    RSA_public_key pk;
    RSA_secret_key sk;

    rsa_generate( &pk, &sk, nbits );

    skc = m_alloc( sizeof *skc );
    pkc = m_alloc( sizeof *pkc );
    skc->timestamp = pkc->timestamp = make_timestamp();
    skc->valid_days = pkc->valid_days = 0; /* fixme: make it configurable*/
    skc->pubkey_algo = pkc->pubkey_algo = PUBKEY_ALGO_RSA;
		       memset(&pkc->mfx, 0, sizeof pkc->mfx);
		       pkc->d.rsa.rsa_n = pk.n;
		       pkc->d.rsa.rsa_e = pk.e;
    skc->d.rsa.rsa_n = sk.n;
    skc->d.rsa.rsa_e = sk.e;
    skc->d.rsa.rsa_d = sk.d;
    skc->d.rsa.rsa_p = sk.p;
    skc->d.rsa.rsa_q = sk.q;
    skc->d.rsa.rsa_u = sk.u;
    skc->d.rsa.calc_csum = 0;
    skc->d.rsa.is_protected = 0; /* FIXME!!! */
    skc->d.rsa.protect_algo = 0; /* should be blowfish */
    /*memcpy(skc->d.rsa.protect.blowfish.iv,"12345678", 8);*/

    init_packet(&pkt1);
    pkt1.pkttype = PKT_PUBKEY_CERT;
    pkt1.pkt.pubkey_cert = pkc;
    init_packet(&pkt2);
    pkt2.pkttype = PKT_SECKEY_CERT;
    pkt2.pkt.seckey_cert = skc;

    if( (rc = build_packet( pub_io, &pkt1 )) ) {
	log_error("build pubkey_cert packet failed: %s\n", g10_errstr(rc) );
	goto leave;
    }
    if( (rc = build_packet( sec_io, &pkt2 )) ) {
	log_error("build seckey_cert packet failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

  leave:
    free_packet(&pkt1);
    free_packet(&pkt2);
    return rc;
}


/****************
 * Generate a keypair
 */
void
generate_keypair()
{
    char *answer;
    unsigned nbits;
    char *pub_fname = "./pubring.g10";
    char *sec_fname = "./secring.g10";
    char *uid = NULL;
    IOBUF pub_io = NULL;
    IOBUF sec_io = NULL;
    int rc;

    if( opt.batch || opt.answer_yes || opt.answer_no )
	log_fatal("Key generation can only be used in interactive mode\n");

    tty_printf("About to generate a new keypair:\n"
	       "              minimum keysize is  768 bits\n"
	       "              default keysize is 1024 bits\n"
	       "    highest suggested keysize is 2048 bits\n" );
    for(;;) {
	answer = tty_get("What keysize do you want? (256) ");
	tty_kill_prompt();
	nbits = *answer? atoi(answer): 256;
	m_free(answer);
	if( nbits < 128 ) /* FIXME: change this to 768 */
	    tty_printf("keysize too small; please select a larger one\n");
	else if( nbits > 2048 ) {
	    tty_printf("Keysizes larger than 2048 are not suggested, because "
		       "computations take REALLY long!\n");
	    answer = tty_get("Are you sure, that you want this keysize? ");
	    tty_kill_prompt();
	    if( answer_is_yes(answer) ) {
		m_free(answer);
		tty_printf("Okay, but keep in mind that your monitor "
			   "and keyboard radiation is also very vulnerable "
			   "to attacks!\n");
		break;
	    }
	    m_free(answer);
	}
	else
	    break;
    }
    tty_printf("Requested keysize is %u bits\n", nbits );
    if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	tty_printf("rounded up to %u bits\n", nbits );
    }
    tty_printf( "\nYou need a User-ID to identify your key; please use your name and your\n"
		"email address in this suggested format:\n"
		"    \"Heinrich Heine <heinrichh@uni-duesseldorf.de>\n" );
    uid = NULL;
    for(;;) {
	m_free(uid);
	tty_printf("\n");
	uid = tty_get("Your User-ID: ");
	tty_kill_prompt();
	if( strlen(uid) < 5 )
	    tty_printf("Please enter a string of at least 5 characters\n");
	else  {
	    tty_printf("You selected this USER-ID:\n    \"%s\"\n\n", uid);
	    answer = tty_get("Is this correct? ");
	    tty_kill_prompt();
	    if( answer_is_yes(answer) ) {
		m_free(answer);
		break;
	    }
	    m_free(answer);
	}
    }

    /* now check wether we a are allowed to write the keyrings */
    if( !(rc=overwrite_filep( pub_fname )) ) {
	if( !(pub_io = iobuf_create( pub_fname )) )
	    log_error("can't create %s: %s\n", pub_fname, strerror(errno) );
	else if( opt.verbose )
	    log_info("writing to '%s'\n", pub_fname );
    }
    else if( rc != -1 ) {
	log_error("Oops: overwrite_filep(%s): %s\n", pub_fname, g10_errstr(rc) );
	m_free(uid);
	return;
    }
    else {
	m_free(uid);
	return;
    }
    if( !(rc=overwrite_filep( sec_fname )) ) {
	if( !(sec_io = iobuf_create( sec_fname )) )
	    log_error("can't create %s: %s\n", sec_fname, strerror(errno) );
	else if( opt.verbose )
	    log_info("writing to '%s'\n", sec_fname );
    }
    else if( rc != -1 ) {
	log_error("Oops: overwrite_filep(%s): %s\n", sec_fname, g10_errstr(rc) );
	m_free(uid);
	return;
    }
    else {
	iobuf_cancel(pub_io);
	m_free(uid);
	return;
    }


    write_comment( pub_io, "#public key created by G10 pre-release " VERSION );
    write_comment( sec_io, "#secret key created by G10 pre-release " VERSION );

    gen_rsa(nbits, pub_io, sec_io);
    write_uid(pub_io, uid );
    write_uid(sec_io, uid );
    m_free(uid);

    iobuf_close(pub_io);
    iobuf_close(sec_io);
}

