/* keygen.c - generate a key pair
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
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"
#include "ttyio.h"
#include "options.h"
#include "keydb.h"
#include "i18n.h"


#if defined(HAVE_RSA_CIPHER) && 0
  #define ENABLE_RSA_KEYGEN 1
#endif


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
    KBNODE node;
    PKT_public_cert *pkc;

    if( opt.verbose )
	log_info(_("writing self signature\n"));

    /* get the uid packet from the list */
    node = find_kbnode( root, PKT_USER_ID );
    if( !node )
	BUG(); /* no user id packet in tree */
    uid = node->pkt->pkt.user_id;
    /* get the pkc packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_CERT );
    if( !node )
	BUG();
    pkc = node->pkt->pkt.public_cert;

    /* and make the signature */
    rc = make_keysig_packet( &sig, pkc, uid, NULL, skc, 0x13, 0 );
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
write_keybinding( KBNODE root, KBNODE pub_root, PKT_secret_cert *skc )
{
    PACKET *pkt;
    PKT_signature *sig;
    int rc=0;
    KBNODE node;
    PKT_public_cert *pkc, *subpkc;

    if( opt.verbose )
	log_info(_("writing key binding signature\n"));

    /* get the pkc packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_CERT );
    if( !node )
	BUG();
    pkc = node->pkt->pkt.public_cert;
    /* find the last subkey */
    subpkc = NULL;
    for(node=pub_root; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBKEY_SUBCERT )
	    subpkc = node->pkt->pkt.public_cert;
    }
    if( !subpkc )
	BUG();

    /* and make the signature */
    rc = make_keysig_packet( &sig, pkc, NULL, subpkc, skc, 0x18, 0 );
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
	STRING2KEY *s2k, PKT_secret_cert **ret_skc, u16 valid_days,
							int version )
{
    int rc;
    int i;
    PACKET *pkt;
    PKT_secret_cert *skc;
    PKT_public_cert *pkc;
    ELG_public_key pk;
    ELG_secret_key sk;
    MPI *factors;

    elg_generate( &pk, &sk, nbits, &factors );

    skc = m_alloc_clear( sizeof *skc );
    pkc = m_alloc_clear( sizeof *pkc );
    skc->timestamp = pkc->timestamp = make_timestamp();
    skc->version = pkc->version = version;
    skc->valid_days = pkc->valid_days = valid_days;
    skc->pubkey_algo = pkc->pubkey_algo = PUBKEY_ALGO_ELGAMAL;
		       pkc->d.elg.p = pk.p;
		       pkc->d.elg.g = pk.g;
		       pkc->d.elg.y = pk.y;
    skc->d.elg.p = sk.p;
    skc->d.elg.g = sk.g;
    skc->d.elg.y = sk.y;
    skc->d.elg.x = sk.x;
    skc->is_protected = 0;
    skc->protect.algo = 0;

    skc->csum = checksum_mpi( skc->d.elg.x );
    if( ret_skc ) /* not a subkey: return an unprotected version of the skc */
	*ret_skc = copy_secret_cert( NULL, skc );

    if( dek ) {
	skc->protect.algo = dek->algo;
	skc->protect.s2k = *s2k;
	rc = protect_secret_key( skc, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_cert(pkc);
	    free_secret_cert(skc);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_skc ? PKT_PUBLIC_CERT : PKT_PUBKEY_SUBCERT;
    pkt->pkt.public_cert = pkc;
    add_kbnode(pub_root, new_kbnode( pkt ));

    /* don't know whether it makes sense to have the factors, so for now
     * we store them in the secret keyring (but they are not secret) */
    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_skc ? PKT_SECRET_CERT : PKT_SECKEY_SUBCERT;
    pkt->pkt.secret_cert = skc;
    add_kbnode(sec_root, new_kbnode( pkt ));
    for(i=0; factors[i]; i++ )
	add_kbnode( sec_root,
		    make_mpi_comment_node("#:ELG_factor:", factors[i] ));

    return 0;
}



#ifdef ENABLE_RSA_KEYGEN
static int
gen_rsa(unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	STRING2KEY *s2k, PKT_secret_cert **ret_skc, u16 valid_days )
{
    int rc;
    PACKET *pkt;
    PKT_secret_cert *skc;
    PKT_public_cert *pkc;
    RSA_public_key pk;
    RSA_secret_key sk;

    rsa_generate( &pk, &sk, nbits );

    skc = m_alloc_clear( sizeof *skc );
    pkc = m_alloc_clear( sizeof *pkc );
    skc->timestamp = pkc->timestamp = make_timestamp();
    skc->valid_days = pkc->valid_days = valid_days;
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

    if( ret_skc ) /* not a subkey: return an unprotected version of the skc */
	*ret_skc = copy_secret_cert( NULL, skc );

    if( dek ) {
	skc->d.rsa.is_protected = 1;
	skc->d.rsa.protect_algo = CIPHER_ALGO_BLOWFISH;
	randomize_buffer( skc->d.rsa.protect.blowfish.iv, 8, 1);
	skc->d.rsa.csum += checksum( skc->d.rsa.protect.blowfish.iv, 8 );
	rc = protect_secret_key( skc, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_cert(pkc);
	    free_secret_cert(skc);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_skc ? PKT_PUBLIC_CERT : PKT_PUBKEY_SUBCERT;
    pkt->pkt.public_cert = pkc;
    add_kbnode(pub_root, new_kbnode( pkt ));

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_skc ? PKT_SECRET_CERT : PKT_SECKEY_SUBCERT;
    pkt->pkt.secret_cert = skc;
    add_kbnode(sec_root, new_kbnode( pkt ));

    return rc;
}
#endif /*ENABLE_RSA_KEYGEN*/


/****************
 * Generate a DSA key
 */
static int
gen_dsa(unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	    STRING2KEY *s2k, PKT_secret_cert **ret_skc, u16 valid_days )
{
    int rc;
    int i;
    PACKET *pkt;
    PKT_secret_cert *skc;
    PKT_public_cert *pkc;
    DSA_public_key pk;
    DSA_secret_key sk;
    MPI *factors;

    if( nbits > 1024 )
	nbits = 1024;

    dsa_generate( &pk, &sk, nbits, &factors );

    skc = m_alloc_clear( sizeof *skc );
    pkc = m_alloc_clear( sizeof *pkc );
    skc->timestamp = pkc->timestamp = make_timestamp();
    skc->version = pkc->version = 4;
    /* valid days are not stored in the packet, but it is
     * used here to put it into the signature.
     */
    skc->valid_days = pkc->valid_days = valid_days;
    skc->pubkey_algo = pkc->pubkey_algo = PUBKEY_ALGO_DSA;
		       pkc->d.dsa.p = pk.p;
		       pkc->d.dsa.q = pk.q;
		       pkc->d.dsa.g = pk.g;
		       pkc->d.dsa.y = pk.y;
    skc->d.dsa.p = sk.p;
    skc->d.dsa.q = sk.q;
    skc->d.dsa.g = sk.g;
    skc->d.dsa.y = sk.y;
    skc->d.dsa.x = sk.x;
    skc->is_protected = 0;
    skc->protect.algo = 0;

    skc->csum = checksum_mpi( skc->d.dsa.x );
    if( ret_skc ) /* not a subkey: return an unprotected version of the skc */
	 *ret_skc = copy_secret_cert( NULL, skc );

    if( dek ) {
	skc->protect.algo = dek->algo;
	skc->protect.s2k = *s2k;
	rc = protect_secret_key( skc, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_cert(pkc);
	    free_secret_cert(skc);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_skc ? PKT_PUBLIC_CERT : PKT_PUBKEY_SUBCERT;
    pkt->pkt.public_cert = pkc;
    add_kbnode(pub_root, new_kbnode( pkt ));

    /* don't know whether it makes sense to have the factors, so for now
     * we store them in the secret keyring (but they are not secret)
     * p = 2 * q * f1 * f2 * ... * fn
     * We store only f1 to f_n-1;  fn can be calculated because p and q
     * are known.
     */
    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_skc ? PKT_SECRET_CERT : PKT_SECKEY_SUBCERT;
    pkt->pkt.secret_cert = skc;
    add_kbnode(sec_root, new_kbnode( pkt ));
    for(i=1; factors[i]; i++ )	/* the first one is q */
	add_kbnode( sec_root,
		    make_mpi_comment_node("#:DSA_factor:", factors[i] ));

    return 0;
}



/****************
 * check valid days:
 * return 0 on error or the multiplier
 */
static int
check_valid_days( const char *s )
{
    if( !isdigit(*s) )
	return 0;
    for( s++; *s; s++)
	if( !isdigit(*s) )
	    break;
    if( !*s )
	return 1;
    if( s[1] )
	return 0; /* e.g. "2323wc" */
    if( *s == 'd' || *s == 'D' )
	return 1;
    if( *s == 'w' || *s == 'W' )
	return 7;
    if( *s == 'm' || *s == 'M' )
	return 30;
    if( *s == 'y' || *s == 'Y' )
	return 365;
    return 0;
}


static int
ask_algo( int *ret_v4 )
{
    char *answer;
    int algo;

    tty_printf(_("Please select the algorithm to use:\n"
		 "   (1) ElGamal is the suggested one.\n"
		 "   (2) ElGamal using v4 packets (OpenPGP)\n"
		 "   (3) DSA can only be used for signatures.\n"));
  #ifdef ENABLE_RSA_KEYGEN
    tty_printf(_("   (4) RSA cannot be used in the U.S.\n"));
  #endif

    *ret_v4 = 0;
    for(;;) {
      #ifdef ENABLE_RSA_KEYGEN
	answer = tty_get(_("Your selection? (1,2,3,4) "));
      #else
	answer = tty_get(_("Your selection? (1,2,3) "));
      #endif
	tty_kill_prompt();
	algo = *answer? atoi(answer): 1;
	m_free(answer);
	if( algo == 1 || algo == 2 ) {
	    if( algo == 2 )
		*ret_v4 = 1;
	    algo = PUBKEY_ALGO_ELGAMAL;
	    break;
	}
	else if( algo == 3 ) {
	    *ret_v4 = 1;
	    algo = PUBKEY_ALGO_DSA;
	    break;
	}
      #ifdef ENABLE_RSA_KEYGEN
	else if( algo == 4 ) {
	    algo = PUBKEY_ALGO_RSA;
	    break;
	}
      #endif
    }
    return algo;
}


static unsigned
ask_keysize( int algo )
{
    char *answer;
    unsigned nbits;

    tty_printf(_("About to generate a new %s keypair.\n"
		 "              minimum keysize is  768 bits\n"
		 "              default keysize is 1024 bits\n"
		 "    highest suggested keysize is 2048 bits\n"),
					pubkey_algo_to_string(algo) );
    for(;;) {
	answer = tty_get(_("What keysize do you want? (1024) "));
	tty_kill_prompt();
	nbits = *answer? atoi(answer): 1024;
	m_free(answer);
	if( algo == PUBKEY_ALGO_DSA && (nbits < 512 || nbits > 1024) )
	    tty_printf(_("DSA only allows keysizes from 512 to 1024\n"));
	else if( nbits < 768 )
	    tty_printf(_("keysize too small; 768 is smallest value allowed.\n"));
	else if( nbits > 2048 ) {
	    tty_printf(_("Keysizes larger than 2048 are not suggested, because "
			 "computations take REALLY long!\n"));
	    answer = tty_get(_("Are you sure, that you want this keysize? "));
	    tty_kill_prompt();
	    if( answer_is_yes(answer) ) {
		m_free(answer);
		tty_printf(_("Okay, but keep in mind that your monitor "
			     "and keyboard radiation is also very vulnerable "
			     "to attacks!\n"));
		break;
	    }
	    m_free(answer);
	}
	else if( nbits > 1536 ) {
	    answer = tty_get(_("Do you really need such a large keysize? "));
	    tty_kill_prompt();
	    if( answer_is_yes(answer) ) {
		m_free(answer);
		break;
	    }
	    m_free(answer);
	}
	else
	    break;
    }
    tty_printf(_("Requested keysize is %u bits\n"), nbits );
    if( algo == PUBKEY_ALGO_DSA && (nbits % 64) ) {
	nbits = ((nbits + 63) / 64) * 64;
	tty_printf(_("rounded up to %u bits\n"), nbits );
    }
    else if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	tty_printf(_("rounded up to %u bits\n"), nbits );
    }
    return nbits;
}


static int
ask_valid_days()
{
    char *answer;
    int valid_days=0;

    tty_printf(_("Please specify how long the key should be valid.\n"
		 "         0 = key does not expire\n"
		 "      <n>  = key expires in n days\n"
		 "      <n>w = key expires in n weeks\n"
		 "      <n>m = key expires in n months\n"
		 "      <n>y = key expires in n years\n"));
    /* Note: The elgamal subkey for DSA has no exiration date because
     * is must be signed with the DSA key and this one has the expiration
     * date */

    answer = NULL;
    for(;;) {
	int mult;

	m_free(answer);
	answer = tty_get(_("Key is valid for? (0) "));
	tty_kill_prompt();
	trim_spaces(answer);
	if( !*answer )
	    valid_days = 0;
	else if( (mult=check_valid_days(answer)) ) {
	    valid_days = atoi(answer) * mult;
	    if( valid_days < 0 || valid_days > 32767 )
		valid_days = 0;
	}
	else {
	    tty_printf(_("invalid value\n"));
	    continue;
	}

	if( !valid_days )
	    tty_printf(_("Key does not expire at all\n"));
	else {
	    tty_printf(_("Key expires at %s\n"), strtimestamp(
		       add_days_to_timestamp( make_timestamp(), valid_days )));
	}

	m_free(answer);
	answer = tty_get(_("Is this correct (y/n)? "));
	tty_kill_prompt();
	if( answer_is_yes(answer) )
	    break;
    }
    m_free(answer);
    return valid_days;
}


static char *
ask_user_id()
{
    char *answer;
    char *aname, *acomment, *amail, *uid;

    tty_printf( _("\n"
"You need a User-ID to identify your key; the software constructs the user id\n"
"from Real Name, Comment and Email Address in this form:\n"
"    \"Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>\"\n\n") );
    uid = aname = acomment = amail = NULL;
    for(;;) {
	char *p;

	if( !aname ) {
	    for(;;) {
		m_free(aname);
		aname = tty_get(_("Real name: "));
		trim_spaces(aname);
		tty_kill_prompt();
		if( strpbrk( aname, "<([])>" ) )
		    tty_printf(_("Invalid character in name\n"));
		else if( isdigit(*aname) )
		    tty_printf(_("Name may not start with a digit\n"));
		else if( strlen(aname) < 5 )
		    tty_printf(_("Name must be at least 5 characters long\n"));
		else
		    break;
	    }
	}
	if( !amail ) {
	    for(;;) {
		m_free(amail);
		amail = tty_get(_("Email address: "));
		trim_spaces(amail);
		strlwr(amail);
		tty_kill_prompt();
		if( !*amail )
		    break;   /* no email address is okay */
		else if( strcspn( amail, "abcdefghijklmnopqrstuvwxyz_-.@" )
			 || string_count_chr(amail,'@') != 1
			 || *amail == '@'
			 || amail[strlen(amail)-1] == '@'
			 || amail[strlen(amail)-1] == '.'
			 || strstr(amail, "..") )
		    tty_printf(_("Not a valid email address\n"));
		else
		    break;
	    }
	}
	if( !acomment ) {
	    for(;;) {
		m_free(acomment);
		acomment = tty_get(_("Comment: "));
		trim_spaces(acomment);
		tty_kill_prompt();
		if( !*acomment )
		    break;   /* no comment is okay */
		else if( strpbrk( acomment, "()" ) )
		    tty_printf(_("Invalid character in comment\n"));
		else
		    break;
	    }
	}

	m_free(uid);
	uid = p = m_alloc(strlen(aname)+strlen(amail)+strlen(acomment)+12+10);
	p = stpcpy(p, aname );
	if( *acomment )
	    p = stpcpy(stpcpy(stpcpy(p," ("), acomment),")");
	if( *amail )
	    p = stpcpy(stpcpy(stpcpy(p," <"), amail),">");

	/* append a warning if we do not have dev/random
	 * or it is switched into  quick testmode */
	if( quick_random_gen(-1) )
	    strcpy(p, " (INSECURE!)" );


	tty_printf(_("You selected this USER-ID:\n    \"%s\"\n\n"), uid);
	/* fixme: add a warning if this user-id already exists */
	for(;;) {
	    answer = tty_get(_("Edit (N)ame, (C)omment, (E)mail or (O)kay? "));
	    tty_kill_prompt();
	    if( strlen(answer) > 1 )
		;
	    else if( *answer == 'N' || *answer == 'n' ) {
		m_free(aname); aname = NULL;
		break;
	    }
	    else if( *answer == 'C' || *answer == 'c' ) {
		m_free(acomment); acomment = NULL;
		break;
	    }
	    else if( *answer == 'E' || *answer == 'e' ) {
		m_free(amail); amail = NULL;
		break;
	    }
	    else if( *answer == 'O' || *answer == 'o' ) {
		m_free(aname); aname = NULL;
		m_free(acomment); acomment = NULL;
		m_free(amail); amail = NULL;
		break;
	    }
	    m_free(answer);
	}
	m_free(answer);
	if( !amail && !acomment && !amail )
	    break;
	m_free(uid); uid = NULL;
    }
    return uid;
}


static DEK *
ask_passphrase( STRING2KEY **ret_s2k )
{
    DEK *dek = NULL;
    STRING2KEY *s2k;

    tty_printf(_("You need a Passphrase to protect your secret key.\n\n") );

    s2k = m_alloc_secure( sizeof *s2k );
    for(;;) {
	s2k->mode = 1;
	s2k->hash_algo = DIGEST_ALGO_RMD160;
	dek = passphrase_to_dek( NULL, CIPHER_ALGO_BLOWFISH, s2k, 2 );
	if( !dek ) {
	    tty_printf(_("passphrase not correctly repeated; try again.\n"));
	}
	else if( !dek->keylen ) {
	    m_free(dek); dek = NULL;
	    m_free(s2k); s2k = NULL;
	    tty_printf(_(
	    "You don't want a passphrase - this is probably a *bad* idea!\n"
	    "I will do it anyway.  You can change your passphrase at any time,\n"
	    "using this program with the option \"--change-passphrase\"\n\n"));
	    break;
	}
	else
	    break; /* okay */
    }
    *ret_s2k = s2k;
    return dek;
}


static int
do_create( int algo, unsigned nbits, KBNODE pub_root, KBNODE sec_root,
	   DEK *dek, STRING2KEY *s2k, PKT_secret_cert **skc, int valid_days,
							     int v4_packet )
{
    int rc=0;

    tty_printf(_(
"We need to generate a lot of random bytes. It is a good idea to perform\n"
"some other action (work in another window, move the mouse, utilize the\n"
"network and the disks) during the prime generation; this gives the random\n"
"number generator a better chance to gain enough entropy.\n") );

    if( algo == PUBKEY_ALGO_ELGAMAL )
	rc = gen_elg(nbits, pub_root, sec_root, dek, s2k,
			   skc, valid_days, v4_packet? 4:3 );
  #ifdef ENABLE_RSA_KEYGEN
    else if( algo == PUBKEY_ALGO_RSA )
	rc = gen_rsa(nbits, pub_root, sec_root, dek, s2k, skc, valid_days  );
  #endif
    else if( algo == PUBKEY_ALGO_DSA )
	rc = gen_dsa(nbits, pub_root, sec_root, dek, s2k, skc, valid_days);
    else
	BUG();
    if( !rc ) {
	add_kbnode( pub_root,
		make_comment_node("#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")"));
	add_kbnode( sec_root,
		make_comment_node("#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")"));
    }
    return rc;
}


/****************
 * Generate a keypair
 */
void
generate_keypair()
{
    unsigned nbits;
    char *pub_fname = NULL;
    char *sec_fname = NULL;
    char *uid = NULL;
    KBNODE pub_root = NULL;
    KBNODE sec_root = NULL;
    PKT_secret_cert *skc = NULL;
    DEK *dek;
    STRING2KEY *s2k;
    int rc;
    int algo;
    int ndays;
    int v4;

    if( opt.batch || opt.answer_yes || opt.answer_no ) {
	log_error(_("Key generation can only be used in interactive mode\n"));
	return;
    }

    algo = ask_algo( &v4 );
    nbits = ask_keysize( algo );
    ndays = ask_valid_days();
    uid = ask_user_id();
    dek = ask_passphrase( &s2k );


    /* now check whether we are allowed to write to the keyrings */
    pub_fname = make_filename(opt.homedir, "pubring.gpg", NULL );
    sec_fname = make_filename(opt.homedir, "secring.gpg", NULL );
    if( opt.verbose ) {
	tty_printf(_("writing public certificate to '%s'\n"), pub_fname );
	tty_printf(_("writing secret certificate to '%s'\n"), sec_fname );
    }

    /* we create the packets as a tree of kbnodes. Because the structure
     * we create is known in advance we simply generate a linked list
     * The first packet is a dummy comment packet which we flag
     * as deleted.  The very first packet must always be a CERT packet.
     */
    pub_root = make_comment_node("#"); delete_kbnode(pub_root);
    sec_root = make_comment_node("#"); delete_kbnode(sec_root);

    rc = do_create( algo, nbits, pub_root, sec_root, dek, s2k, &skc, ndays, v4);
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

	if( get_keyblock_handle( pub_fname, 0, &pub_kbpos ) ) {
	    if( add_keyblock_resource( pub_fname, 1, 0 ) ) {
		log_error("can add keyblock file '%s'\n", pub_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( get_keyblock_handle( pub_fname, 0, &pub_kbpos ) ) {
		log_error("can get keyblock handle for '%s'\n", pub_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	}
	if( rc )
	    ;
	else if( get_keyblock_handle( sec_fname, 1, &sec_kbpos ) ) {
	    if( add_keyblock_resource( sec_fname, 1, 1 ) ) {
		log_error("can add keyblock file '%s'\n", sec_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( get_keyblock_handle( sec_fname, 1, &sec_kbpos ) ) {
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
	    tty_printf(_("public and secret key created and signed.\n") );
	    if( algo == PUBKEY_ALGO_DSA )
		tty_printf(_("Note that this key cannot be used for "
			     "encryption.  You may want to use\n"
			     "the command \"--add-key\" to generate a "
			     "secondary key for this purpose.\n") );
	}

	if( !rc1 )
	    unlock_keyblock( &pub_kbpos );
	if( !rc2 )
	    unlock_keyblock( &sec_kbpos );
    }


    if( rc )
	tty_printf(_("Key generation failed: %s\n"), g10_errstr(rc) );
    release_kbnode( pub_root );
    release_kbnode( sec_root );
    if( skc ) /* the unprotected  secret certificate */
	free_secret_cert(skc);
    m_free(uid);
    m_free(dek);
    m_free(s2k);
    m_free(pub_fname);
    m_free(sec_fname);
}


/****************
 * add a new subkey to an existing key.
 */
void
generate_subkeypair( const char *username )
{
    int rc=0;
    KBPOS pub_kbpos, sec_kbpos;
    KBNODE pub_keyblock = NULL;
    KBNODE sec_keyblock = NULL;
    KBNODE node;
    PKT_secret_cert *skc = NULL; /* this is the primary skc */
    u32 keyid[2];
    int v4, algo, ndays;
    unsigned nbits;
    char *passphrase = NULL;
    DEK *dek = NULL;
    STRING2KEY *s2k = NULL;

    if( opt.batch || opt.answer_yes || opt.answer_no ) {
	log_error(_("Key generation can only be used in interactive mode\n"));
	return;
    }

    /* search the userid */
    rc = find_secret_keyblock_byname( &sec_kbpos, username );
    if( rc ) {
	log_error("user '%s' not found\n", username );
	goto leave;
    }
    rc = read_keyblock( &sec_kbpos, &sec_keyblock );
    if( rc ) {
	log_error("error reading the secret key: %s\n", g10_errstr(rc) );
	goto leave;
    }
    /* and the public key */
    rc = find_keyblock_byname( &pub_kbpos, username );
    if( rc ) {
	log_error("user '%s' not found in public ring\n", username );
	goto leave;
    }
    rc = read_keyblock( &pub_kbpos, &pub_keyblock );
    if( rc ) {
	log_error("error reading the public key: %s\n", g10_errstr(rc) );
	goto leave;
    }

    /* break out the primary key */
    node = find_kbnode( sec_keyblock, PKT_SECRET_CERT );
    if( !node ) {
	log_error("Oops; secret key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    /* make a copy of the skc to keep the protected one in the keyblock */
    skc = copy_secret_cert( NULL, node->pkt->pkt.secret_cert );
    keyid_from_skc( skc, keyid );
    /* display primary and all secondary keys */
    tty_printf("sec  %4u%c/%08lX %s   ",
	      nbits_from_skc( skc ),
	      pubkey_letter( skc->pubkey_algo ),
	      keyid[1], datestr_from_skc(skc) );
    {
	size_t n;
	char *p = get_user_id( keyid, &n );
	tty_print_string( p, n );
	m_free(p);
	tty_printf("\n");
    }
    for(node=sec_keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_SECKEY_SUBCERT ) {
	    PKT_secret_cert *subskc = node->pkt->pkt.secret_cert;
	    keyid_from_skc( subskc, keyid );
	    tty_printf("sub  %4u%c/%08lX %s\n",
		      nbits_from_skc( subskc ),
		      pubkey_letter( subskc->pubkey_algo ),
		      keyid[1], datestr_from_skc(subskc) );
	}
    }
    tty_printf("\n");



    /* unprotect to get the passphrase */
    switch( is_secret_key_protected( skc ) ) {
      case -1:
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf("This key is not protected.\n");
	break;
      default:
	tty_printf("Key is protected.\n");
	rc = check_secret_key( skc );
	if( !rc )
	    passphrase = get_last_passphrase();
	break;
    }
    if( rc )
	goto leave;


    algo = ask_algo( &v4 );
    nbits = ask_keysize( algo );
    ndays = ask_valid_days();

    if( passphrase ) {
	s2k = m_alloc_secure( sizeof *s2k );
	s2k->mode = 1;
	s2k->hash_algo = DIGEST_ALGO_RMD160;
	set_next_passphrase( passphrase );
	dek = passphrase_to_dek( NULL, CIPHER_ALGO_BLOWFISH, s2k, 2 );
    }

    rc = do_create( algo, nbits, pub_keyblock, sec_keyblock,
				      dek, s2k, NULL, ndays, v4 );
    if( !rc )
	rc = write_keybinding(pub_keyblock, pub_keyblock, skc);
    if( !rc )
	rc = write_keybinding(sec_keyblock, pub_keyblock, skc);
    /* write back */
    if( !rc ) {
	rc = update_keyblock( &pub_kbpos, pub_keyblock );
	if( rc )
	    log_error("update_public_keyblock failed\n" );
    }
    if( !rc ) {
	rc = update_keyblock( &sec_kbpos, sec_keyblock );
	if( rc )
	    log_error("update_secret_keyblock failed\n" );
    }
    if( !rc )
	tty_printf(_("public and secret subkey created.\n") );


  leave:
    if( rc )
	tty_printf(_("Key generation failed: %s\n"), g10_errstr(rc) );
    m_free( passphrase );
    m_free( dek );
    m_free( s2k );
    if( skc ) /* release the copy of the (now unprotected) secret key */
	free_secret_cert(skc);
    release_kbnode( sec_keyblock );
    release_kbnode( pub_keyblock );
    set_next_passphrase( NULL );
}

