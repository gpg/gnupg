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
#include "keydb.h"

#if 0
  #define TEST_ALGO  1
  #define TEST_NBITS 256
  #define TEST_UID   "Karl Test"
#endif


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


static u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    a |= n & 0xff;
    return a;
}

static u16
checksum( byte *p, unsigned n )
{
    u16 a;

    for(a=0; n; n-- )
	a += *p++;
    return a;
}

static u16
checksum_mpi( MPI a )
{
    u16 csum;
    byte *buffer;
    unsigned nbytes;

    buffer = mpi_get_buffer( a, &nbytes, NULL );
    csum = checksum_u16( nbytes*8 );
    csum += checksum( buffer, nbytes );
    m_free( buffer );
    return csum;
}



static void
write_uid( KBNODE root, const char *s )
{
    PACKET *pkt = m_alloc_clear(sizeof *pkt );
    size_t n = strlen(s);

    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = m_alloc( sizeof *pkt->pkt.user_id + n - 1 );
    pkt->pkt.user_id->len = n;
    strcpy(pkt->pkt.user_id->name, s);
    add_kbnode( root, new_kbnode( pkt ) );
}


static int
write_selfsig( KBNODE root, KBNODE pub_root, PKT_secret_cert *skc )
{
    PACKET *pkt;
    PKT_signature *sig;
    PKT_user_id *uid;
    int rc=0;
    KBNODE kbctx, node;
    PKT_public_cert *pkc;

    if( opt.verbose )
	log_info("writing self signature\n");

    /* get the uid packet from the tree */
    for( kbctx=NULL; (node=walk_kbtree( root, &kbctx)) ; ) {
	if( node->pkt->pkttype == PKT_USER_ID )
	    break;
    }
    if( !node )
	log_bug(NULL); /* no user id packet in tree */
    uid = node->pkt->pkt.user_id;
    /* get the pkc packet from the pub_tree */
    for( kbctx=NULL; (node=walk_kbtree( pub_root, &kbctx)) ; ) {
	if( node->pkt->pkttype == PKT_PUBLIC_CERT )
	    break;
    }
    if( !node )
	log_bug(NULL);
    pkc = node->pkt->pkt.public_cert;

    /* and make the signature */
    rc = make_keysig_packet( &sig, pkc, uid, skc, 0x13, DIGEST_ALGO_RMD160 );
    if( rc ) {
	log_error("make_keysig_packet failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    pkt = m_alloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = sig;
    add_kbnode( root, new_kbnode( pkt ) );
    return rc;
}


static int
gen_elg(unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	PKT_secret_cert **ret_skc )
{
    int rc;
    PACKET *pkt;
    PKT_secret_cert *skc;
    PKT_public_cert *pkc;
    ELG_public_key pk;
    ELG_secret_key sk;
    unsigned nbytes;

    elg_generate( &pk, &sk, nbits );

    skc = m_alloc( sizeof *skc );
    pkc = m_alloc( sizeof *pkc );
    skc->timestamp = pkc->timestamp = make_timestamp();
    skc->valid_days = pkc->valid_days = 0; /* fixme: make it configurable*/
    skc->pubkey_algo = pkc->pubkey_algo = PUBKEY_ALGO_ELGAMAL;
		       memset(&pkc->mfx, 0, sizeof pkc->mfx);
		       pkc->d.elg.p = pk.p;
		       pkc->d.elg.g = pk.g;
		       pkc->d.elg.y = pk.y;
    skc->d.elg.p = sk.p;
    skc->d.elg.g = sk.g;
    skc->d.elg.y = sk.y;
    skc->d.elg.x = sk.x;

    skc->d.elg.csum = checksum_mpi( skc->d.elg.x );
    /* return an unprotected version of the skc */
    *ret_skc = copy_secret_cert( NULL, skc );

    if( !dek ) {
	skc->d.elg.is_protected = 0;
	skc->d.elg.protect_algo = 0;
    }
    else {
	skc->d.elg.is_protected = 0;
	skc->d.elg.protect_algo = CIPHER_ALGO_BLOWFISH;
	randomize_buffer(skc->d.elg.protect.blowfish.iv, 8, 1);
	rc = protect_secret_key( skc, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_cert(pkc);
	    free_secret_cert(skc);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = PKT_PUBLIC_CERT;
    pkt->pkt.public_cert = pkc;
    add_kbnode(pub_root, new_kbnode( pkt ));

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = PKT_SECRET_CERT;
    pkt->pkt.secret_cert = skc;
    add_kbnode(sec_root, new_kbnode( pkt ));

    return 0;
}



#ifdef HAVE_RSA_CIPHER
static int
gen_rsa(unsigned nbits, IOBUF pub_io, IOBUF sec_io, DEK *dek,
	PKT_public_cert **ret_pkc, PKT_secret_cert **ret_skc )
{
    int rc;
    PACKET pkt1, pkt2;
    PKT_secret_cert *skc;
    PKT_public_cert *pkc;
    RSA_public_key pk;
    RSA_secret_key sk;

    init_packet(&pkt1);
    init_packet(&pkt2);

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
    skc->d.rsa.csum  = checksum_mpi( skc->d.rsa.rsa_d );
    skc->d.rsa.csum += checksum_mpi( skc->d.rsa.rsa_p );
    skc->d.rsa.csum += checksum_mpi( skc->d.rsa.rsa_q );
    skc->d.rsa.csum += checksum_mpi( skc->d.rsa.rsa_u );
    if( !dek ) {
	skc->d.rsa.is_protected = 0;
	skc->d.rsa.protect_algo = 0;
    }
    else {
	skc->d.rsa.is_protected = 1;
	skc->d.rsa.protect_algo = CIPHER_ALGO_BLOWFISH;
	randomize_buffer( skc->d.rsa.protect.blowfish.iv, 8, 1);
	skc->d.rsa.csum += checksum( skc->d.rsa.protect.blowfish.iv, 8 );
	rc = protect_secret_key( skc, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    goto leave;
	}
    }

    pkt1.pkttype = PKT_PUBLIC_CERT;
    pkt1.pkt.public_cert = pkc;
    pkt2.pkttype = PKT_SECRET_CERT;
    pkt2.pkt.secret_cert = skc;

    if( (rc = build_packet( pub_io, &pkt1 )) ) {
	log_error("build public_cert packet failed: %s\n", g10_errstr(rc) );
	goto leave;
    }
    if( (rc = build_packet( sec_io, &pkt2 )) ) {
	log_error("build secret_cert packet failed: %s\n", g10_errstr(rc) );
	goto leave;
    }
    *ret_pkc = pkt1.pkt.public_cert;
    pkt1.pkt.public_cert = NULL;
    *ret_skc = pkt1.pkt.secret_cert;
    pkt1.pkt.secret_cert = NULL;

  leave:
    free_packet(&pkt1);
    free_packet(&pkt2);
    return rc;
}
#endif /*HAVE_RSA_CIPHER*/


static int
gen_dsa(unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	PKT_secret_cert **ret_skc )
{
    return G10ERR_GENERAL;
}



/****************
 * Generate a keypair
 */
void
generate_keypair()
{
    char *answer;
    unsigned nbits;
    char *pub_fname = NULL;
    char *sec_fname = NULL;
    char *uid = NULL;
    IOBUF pub_io = NULL;
    IOBUF sec_io = NULL;
    KBNODE pub_root = NULL;
    KBNODE sec_root = NULL;
    PKT_secret_cert *skc = NULL;
    DEK *dek = NULL;
    int rc;
    int algo;
    const char *algo_name;

  #ifndef TEST_ALGO
    if( opt.batch || opt.answer_yes || opt.answer_no )
	log_fatal("Key generation can only be used in interactive mode\n");

    tty_printf("Please select the algorithm to use:\n"
	       "   (1) ElGamal is the suggested one.\n"
	   #ifdef HAVE_RSA_CIPHER
	       "   (2) RSA cannot be used in the U.S.\n"
	   #endif
	       "   (3) DSA can only be used for signatures.\n"
	       );
  #endif

    for(;;) {
      #ifdef TEST_ALGO
	algo = TEST_ALGO;
      #else
	answer = tty_get("Your selection? (1"
					   #ifdef HAVE_RSA_CIPHER
					     ",2"
					   #endif
					       ",3) ");
	tty_kill_prompt();
	algo = *answer? atoi(answer): 1;
	m_free(answer);
      #endif
	if( algo == 1 ) {
	    algo = PUBKEY_ALGO_ELGAMAL;
	    algo_name = "ElGamal";
	    break;
	}
      #ifdef HAVE_RSA_CIPHER
	else if( algo == 2 ) {
	    algo = PUBKEY_ALGO_RSA;
	    algo_name = "RSA";
	    break;
	}
      #endif
	else if( algo == 3 ) {
	    algo = PUBKEY_ALGO_DSA;
	    algo_name = "DSA";
	    break;
	}
    }



    tty_printf("About to generate a new %s keypair.\n"
	  #ifndef TEST_NBITS
	       "              minimum keysize is  768 bits\n"
	       "              default keysize is 1024 bits\n"
	       "    highest suggested keysize is 2048 bits\n"
	  #endif
							     , algo_name );
    for(;;) {
      #ifdef TEST_NBITS
	nbits = TEST_NBITS;
      #else
	answer = tty_get("What keysize do you want? (1024) ");
	tty_kill_prompt();
	nbits = *answer? atoi(answer): 1024;
	m_free(answer);
      #endif
	if( algo == PUBKEY_ALGO_DSA && (nbits < 512 || nbits > 1024) )
	    tty_printf("DSA does only allow keysizes from 512 to 1024\n");
	else if( nbits < 128 ) /* FIXME: change this to 768 */
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
    if( algo == PUBKEY_ALGO_DSA && (nbits % 64) ) {
	nbits = ((nbits + 63) / 64) * 64;
	tty_printf("rounded up to %u bits\n", nbits );
    }
    else if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	tty_printf("rounded up to %u bits\n", nbits );
    }

  #ifdef TEST_UID
    uid = m_alloc(strlen(TEST_UID)+1);
    strcpy(uid, TEST_UID);
  #else
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
  #endif


    tty_printf( "You need a Passphrase to protect your secret key.\n\n" );

    dek = m_alloc_secure( sizeof *dek );
    dek->algo = CIPHER_ALGO_BLOWFISH;
    rc = make_dek_from_passphrase( dek , 2 );
    if( rc == -1 ) {
	m_free(dek); dek = NULL;
	tty_printf(
	    "You don't what a passphrase - this is probably a *bad* idea!\n"
	    "I will do it anyway.  You can change your passphrase at anytime,\n"
	    "using this program with the option \"--change-passphrase\"\n\n" );
    }
    else if( rc ) {
	m_free(dek); dek = NULL;
	m_free(uid);
	log_error("Error getting the passphrase: %s\n", g10_errstr(rc) );
	return;
    }


    /* now check wether we a are allowed to write to the keyrings */
    pub_fname = make_filename("~/.g10", "pubring.g10", NULL );
    sec_fname = make_filename("~/.g10", "secring.g10", NULL );
    if( opt.verbose ) {
	tty_printf("writing public certificate to '%s'\n", pub_fname );
	tty_printf("writing secret certificate to '%s'\n", sec_fname );
    }

    /* we create the packets as a tree of kbnodes. Because the structure
     * we create is known in advance we simply generate a linked list
     * The first packet is a comment packet, followed by the userid and
     * the self signature.
     */
    pub_root = make_comment_node("#created by G10 pre-release " VERSION );
    sec_root = make_comment_node("#created by G10 pre-release " VERSION );

    if( algo == PUBKEY_ALGO_ELGAMAL )
	rc = gen_elg(nbits, pub_root, sec_root, dek, &skc );
  #ifdef HAVE_RSA_CIPHER
    else if( algo == PUBKEY_ALGO_RSA )
	rc = gen_rsa(nbits, pub_io, sec_io, dek, &skc );
  #endif
    else if( algo == PUBKEY_ALGO_DSA )
	rc = gen_dsa(nbits, pub_root, sec_root, dek, &skc );
    else
	log_bug(NULL);
    if( !rc )
	write_uid(pub_root, uid );
    if( !rc )
	write_uid(sec_root, uid );
    if( !rc )
	rc = write_selfsig(pub_root, pub_root, skc);
    if( !rc )
	rc = write_selfsig(sec_root, pub_root, skc);

    if( !rc ) {
	KBPOS pub_kbpos;
	KBPOS sec_kbpos;
	int rc1 = -1;
	int rc2 = -1;

	/* we can now write the certificates */
	/* FIXME: should we check wether the user-id already exists? */

	if( get_keyblock_handle( pub_fname, &pub_kbpos ) ) {
	    if( add_keyblock_resource( pub_fname, 1 ) ) {
		log_error("can add keyblock file '%s'\n", pub_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( get_keyblock_handle( pub_fname, &pub_kbpos ) ) {
		log_error("can get keyblock handle for '%s'\n", pub_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	}
	if( rc )
	    ;
	else if( get_keyblock_handle( sec_fname, &sec_kbpos ) ) {
	    if( add_keyblock_resource( sec_fname, 1 ) ) {
		log_error("can add keyblock file '%s'\n", sec_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( get_keyblock_handle( sec_fname, &sec_kbpos ) ) {
		log_error("can get keyblock handle for '%s'\n", sec_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	}

	if( rc )
	    ;
	else if( (rc=rc1=lock_keyblock( &pub_kbpos )) )
	    log_error("can't lock public keyring: %s\n", g10_errstr(rc) );
	else if( (rc=rc2=lock_keyblock( &sec_kbpos )) )
	    log_error("can't lock secret keyring: %s\n", g10_errstr(rc) );
	else if( (rc=insert_keyblock( &pub_kbpos, pub_root )) )
	    log_error("can't write public key: %s\n", g10_errstr(rc) );
	else if( (rc=insert_keyblock( &sec_kbpos, sec_root )) )
	    log_error("can't write secret key: %s\n", g10_errstr(rc) );
	else {
	    tty_printf("public and secret key created and signed.\n" );
	}

	if( !rc1 )
	    unlock_keyblock( &pub_kbpos );
	if( !rc2 )
	    unlock_keyblock( &sec_kbpos );
    }


    if( rc )
	tty_printf("Key generation failed: %s\n", g10_errstr(rc) );
    release_kbnode( pub_root );
    release_kbnode( sec_root );
    if( skc ) /* the unprotected  secret certificate */
	free_secret_cert(skc);
    m_free(uid);
    m_free(dek);
    m_free(pub_fname);
    m_free(sec_fname);
}

