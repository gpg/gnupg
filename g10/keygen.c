/* keygen.c - generate a key pair
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include "status.h"
#include "i18n.h"

enum para_name {
  pKEYTYPE,
  pKEYLENGTH,
  pSUBKEYTYPE,
  pSUBKEYLENGTH,
  pNAMEREAL,
  pNAMEEMAIL,
  pNAMECOMMENT,
  pUSERID,
  pEXPIREDATE,
  pKEYEXPIRE, /* in n seconds */
  pSUBKEYEXPIRE, /* in n seconds */
  pPASSPHRASE,
  pPASSPHRASE_DEK,
  pPASSPHRASE_S2K
};

struct para_data_s {
    struct para_data_s *next;
    int lnr;
    enum para_name key;
    union {
       DEK *dek;
       STRING2KEY *s2k;
       u32 expire;
       char value[1];
    } u;
};

struct output_control_s {
    int lnr;
    int dryrun;
    int use_files;
    struct {
	char  *fname;
	char  *newfname;
	IOBUF stream;
	armor_filter_context_t afx;
    } pub;
    struct {
	char  *fname;
	char  *newfname;
	IOBUF stream;
	armor_filter_context_t afx;
    } sec;
};


static void do_generate_keypair( struct para_data_s *para,
				 struct output_control_s *outctrl );
static int  write_keyblock( IOBUF out, KBNODE node );


static void
write_uid( KBNODE root, const char *s )
{
    PACKET *pkt = m_alloc_clear(sizeof *pkt );
    size_t n = strlen(s);

    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = m_alloc_clear( sizeof *pkt->pkt.user_id + n - 1 );
    pkt->pkt.user_id->len = n;
    strcpy(pkt->pkt.user_id->name, s);
    add_kbnode( root, new_kbnode( pkt ) );
}



int
keygen_add_key_expire( PKT_signature *sig, void *opaque )
{
    PKT_public_key *pk = opaque;
    byte buf[8];
    u32  u;

    if( pk->expiredate ) {
	u = pk->expiredate > pk->timestamp? pk->expiredate - pk->timestamp
					  : pk->timestamp;
	buf[0] = (u >> 24) & 0xff;
	buf[1] = (u >> 16) & 0xff;
	buf[2] = (u >>	8) & 0xff;
	buf[3] = u & 0xff;
	build_sig_subpkt( sig, SIGSUBPKT_KEY_EXPIRE, buf, 4 );
    }

    return 0;
}


/****************
 * Add preference to the self signature packet.
 * This is only called for packets with version > 3.
 */
int
keygen_add_std_prefs( PKT_signature *sig, void *opaque )
{
    byte buf[8];

    keygen_add_key_expire( sig, opaque );

    buf[0] = CIPHER_ALGO_RIJNDAEL;
    buf[1] = CIPHER_ALGO_TWOFISH;
    buf[2] = CIPHER_ALGO_CAST5;
    buf[3] = CIPHER_ALGO_BLOWFISH;
    build_sig_subpkt( sig, SIGSUBPKT_PREF_SYM, buf, 4 );

    buf[0] = DIGEST_ALGO_RMD160;
    buf[1] = DIGEST_ALGO_SHA1;
    build_sig_subpkt( sig, SIGSUBPKT_PREF_HASH, buf, 2 );

    buf[0] = 2;
    buf[1] = 1;
    build_sig_subpkt( sig, SIGSUBPKT_PREF_COMPR, buf, 2 );

    buf[0] = 0x80; /* no modify - It is reasonable that a key holder
		    * has the possibility to reject signatures from users
		    * who are known to sign everything without any
		    * validation - so a signed key should be send
		    * to the holder who in turn can put it on a keyserver
		    */
    build_sig_subpkt( sig, SIGSUBPKT_KS_FLAGS, buf, 1 );

    return 0;
}



static int
write_selfsig( KBNODE root, KBNODE pub_root, PKT_secret_key *sk )
{
    PACKET *pkt;
    PKT_signature *sig;
    PKT_user_id *uid;
    int rc=0;
    KBNODE node;
    PKT_public_key *pk;

    if( opt.verbose )
	log_info(_("writing self signature\n"));

    /* get the uid packet from the list */
    node = find_kbnode( root, PKT_USER_ID );
    if( !node )
	BUG(); /* no user id packet in tree */
    uid = node->pkt->pkt.user_id;
    /* get the pk packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_KEY );
    if( !node )
	BUG();
    pk = node->pkt->pkt.public_key;
    /* we have to cache the key, so that the verification of the signature
     * creation is able to retrieve the public key */
    cache_public_key (pk);

    /* and make the signature */
    rc = make_keysig_packet( &sig, pk, uid, NULL, sk, 0x13, 0,
			     keygen_add_std_prefs, pk );
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
write_keybinding( KBNODE root, KBNODE pub_root, PKT_secret_key *sk )
{
    PACKET *pkt;
    PKT_signature *sig;
    int rc=0;
    KBNODE node;
    PKT_public_key *pk, *subpk;

    if( opt.verbose )
	log_info(_("writing key binding signature\n"));

    /* get the pk packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_KEY );
    if( !node )
	BUG();
    pk = node->pkt->pkt.public_key;
    /* we have to cache the key, so that the verification of the signature
     * creation is able to retrieve the public key */
    cache_public_key (pk);
 
    /* find the last subkey */
    subpk = NULL;
    for(node=pub_root; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    subpk = node->pkt->pkt.public_key;
    }
    if( !subpk )
	BUG();

    /* and make the signature */
    rc = make_keysig_packet( &sig, pk, NULL, subpk, sk, 0x18, 0,
				    keygen_add_key_expire, subpk );
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
gen_elg(int algo, unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	STRING2KEY *s2k, PKT_secret_key **ret_sk, u32 expireval )
{
    int rc;
    int i;
    PACKET *pkt;
    PKT_secret_key *sk;
    PKT_public_key *pk;
    MPI skey[4];
    MPI *factors;

    assert( is_ELGAMAL(algo) );

    if( nbits < 512 ) {
	nbits = 1024;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

    if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

    rc = pubkey_generate( algo, nbits, skey, &factors );
    if( rc ) {
	log_error("pubkey_generate failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    sk = m_alloc_clear( sizeof *sk );
    pk = m_alloc_clear( sizeof *pk );
    sk->timestamp = pk->timestamp = make_timestamp();
    sk->version = pk->version = 4;
    if( expireval ) {
	sk->expiredate = pk->expiredate = sk->timestamp + expireval;
    }
    sk->pubkey_algo = pk->pubkey_algo = algo;
		       pk->pkey[0] = mpi_copy( skey[0] );
		       pk->pkey[1] = mpi_copy( skey[1] );
		       pk->pkey[2] = mpi_copy( skey[2] );
    sk->skey[0] = skey[0];
    sk->skey[1] = skey[1];
    sk->skey[2] = skey[2];
    sk->skey[3] = skey[3];
    sk->is_protected = 0;
    sk->protect.algo = 0;

    sk->csum = checksum_mpi_counted_nbits( sk->skey[3] );
    if( ret_sk ) /* not a subkey: return an unprotected version of the sk */
	*ret_sk = copy_secret_key( NULL, sk );

    if( dek ) {
	sk->protect.algo = dek->algo;
	sk->protect.s2k = *s2k;
	rc = protect_secret_key( sk, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_key(pk);
	    free_secret_key(sk);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_sk ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
    pkt->pkt.public_key = pk;
    add_kbnode(pub_root, new_kbnode( pkt ));

    /* don't know whether it makes sense to have the factors, so for now
     * we store them in the secret keyring (but they are not secret) */
    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_sk ? PKT_SECRET_KEY : PKT_SECRET_SUBKEY;
    pkt->pkt.secret_key = sk;
    add_kbnode(sec_root, new_kbnode( pkt ));
    for(i=0; factors[i]; i++ )
	add_kbnode( sec_root,
		    make_mpi_comment_node("#:ELG_factor:", factors[i] ));

    return 0;
}


/****************
 * Generate a DSA key
 */
static int
gen_dsa(unsigned int nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	    STRING2KEY *s2k, PKT_secret_key **ret_sk, u32 expireval )
{
    int rc;
    int i;
    PACKET *pkt;
    PKT_secret_key *sk;
    PKT_public_key *pk;
    MPI skey[5];
    MPI *factors;

    if( nbits > 1024 || nbits < 512 ) {
	nbits = 1024;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

    if( (nbits % 64) ) {
	nbits = ((nbits + 63) / 64) * 64;
	log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

    rc = pubkey_generate( PUBKEY_ALGO_DSA, nbits, skey, &factors );
    if( rc ) {
	log_error("pubkey_generate failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    sk = m_alloc_clear( sizeof *sk );
    pk = m_alloc_clear( sizeof *pk );
    sk->timestamp = pk->timestamp = make_timestamp();
    sk->version = pk->version = 4;
    if( expireval ) {
	sk->expiredate = pk->expiredate = sk->timestamp + expireval;
    }
    sk->pubkey_algo = pk->pubkey_algo = PUBKEY_ALGO_DSA;
		       pk->pkey[0] = mpi_copy( skey[0] );
		       pk->pkey[1] = mpi_copy( skey[1] );
		       pk->pkey[2] = mpi_copy( skey[2] );
		       pk->pkey[3] = mpi_copy( skey[3] );
    sk->skey[0] = skey[0];
    sk->skey[1] = skey[1];
    sk->skey[2] = skey[2];
    sk->skey[3] = skey[3];
    sk->skey[4] = skey[4];
    sk->is_protected = 0;
    sk->protect.algo = 0;

    sk->csum = checksum_mpi_counted_nbits( sk->skey[4] );
    if( ret_sk ) /* not a subkey: return an unprotected version of the sk */
	*ret_sk = copy_secret_key( NULL, sk );

    if( dek ) {
	sk->protect.algo = dek->algo;
	sk->protect.s2k = *s2k;
	rc = protect_secret_key( sk, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_key(pk);
	    free_secret_key(sk);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_sk ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
    pkt->pkt.public_key = pk;
    add_kbnode(pub_root, new_kbnode( pkt ));

    /* don't know whether it makes sense to have the factors, so for now
     * we store them in the secret keyring (but they are not secret)
     * p = 2 * q * f1 * f2 * ... * fn
     * We store only f1 to f_n-1;  fn can be calculated because p and q
     * are known.
     */
    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_sk ? PKT_SECRET_KEY : PKT_SECRET_SUBKEY;
    pkt->pkt.secret_key = sk;
    add_kbnode(sec_root, new_kbnode( pkt ));
    for(i=1; factors[i]; i++ )	/* the first one is q */
	add_kbnode( sec_root,
		    make_mpi_comment_node("#:DSA_factor:", factors[i] ));

    return 0;
}

#if 0
/* we can't enable generation right now, becuase we first need to
 * implement the keyflags - the problem is that we need to change all
 * signature editing function to keep the ketflags associated with an
 * RSA key.  */
static int
gen_rsa(int algo, unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	STRING2KEY *s2k, PKT_secret_key **ret_sk, u32 expireval )
{
    int rc;
    PACKET *pkt;
    PKT_secret_key *sk;
    PKT_public_key *pk;
    MPI skey[4];
    MPI *factors;

    assert( is_RSA(algo) );

    if( nbits < 1024 ) {
	nbits = 1024;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

    if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

    rc = pubkey_generate( algo, nbits, skey, &factors );
    if( rc ) {
	log_error("pubkey_generate failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    sk = m_alloc_clear( sizeof *sk );
    pk = m_alloc_clear( sizeof *pk );
    sk->timestamp = pk->timestamp = make_timestamp();
    sk->version = pk->version = 4;
    if( expireval ) {
	sk->expiredate = pk->expiredate = sk->timestamp + expireval;
    }
    sk->pubkey_algo = pk->pubkey_algo = algo;
		       pk->pkey[0] = mpi_copy( skey[0] );
		       pk->pkey[1] = mpi_copy( skey[1] );
    sk->skey[0] = skey[0];
    sk->skey[1] = skey[1];
    sk->skey[2] = skey[2];
    sk->skey[3] = skey[3];
    sk->skey[4] = skey[4];
    sk->skey[5] = skey[5];
    sk->is_protected = 0;
    sk->protect.algo = 0;

    sk->csum  = checksum_mpi_counted_nbits( sk->skey[2] );
    sk->csum += checksum_mpi_counted_nbits( sk->skey[3] );
    sk->csum += checksum_mpi_counted_nbits( sk->skey[4] );
    sk->csum += checksum_mpi_counted_nbits( sk->skey[5] );
    if( ret_sk ) /* not a subkey: return an unprotected version of the sk */
	*ret_sk = copy_secret_key( NULL, sk );

    if( dek ) {
	sk->protect.algo = dek->algo;
	sk->protect.s2k = *s2k;
	rc = protect_secret_key( sk, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_key(pk);
	    free_secret_key(sk);
	    return rc;
	}
    }

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_sk ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
    pkt->pkt.public_key = pk;
    add_kbnode(pub_root, new_kbnode( pkt ));

    pkt = m_alloc_clear(sizeof *pkt);
    pkt->pkttype = ret_sk ? PKT_SECRET_KEY : PKT_SECRET_SUBKEY;
    pkt->pkt.secret_key = sk;
    add_kbnode(sec_root, new_kbnode( pkt ));

    return 0;
}
#endif


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


/****************
 * Returns: 0 to create both a DSA and a ElGamal key.
 */
static int
ask_algo( int addmode )
{
    char *answer;
    int algo;

    tty_printf(_("Please select what kind of key you want:\n"));
    if( !addmode )
	tty_printf(_("   (%d) DSA and ElGamal (default)\n"), 1 );
    tty_printf(    _("   (%d) DSA (sign only)\n"), 2 );
    if( addmode )
	tty_printf(    _("   (%d) ElGamal (encrypt only)\n"), 3 );
    tty_printf(    _("   (%d) ElGamal (sign and encrypt)\n"), 4 );
  #if 0
    tty_printf(    _("   (%d) RSA (sign and encrypt)\n"), 5 );
  #endif

    for(;;) {
	answer = cpr_get("keygen.algo",_("Your selection? "));
	cpr_kill_prompt();
	algo = *answer? atoi(answer): 1;
	m_free(answer);
	if( algo == 1 && !addmode ) {
	    algo = 0;	/* create both keys */
	    break;
	}
      #if 0
	else if( algo == 5 ) {
	    if( cpr_get_answer_is_yes("keygen.algo.rsa_se",_(
		"Do you really want to create a sign and encrypt key? "))) {
		algo = PUBKEY_ALGO_RSA;
		break;
	    }
	}
      #endif
	else if( algo == 4 ) {
	    if( cpr_get_answer_is_yes("keygen.algo.elg_se",_(
		"The use of this algorithm is deprecated - create anyway? "))){
		algo = PUBKEY_ALGO_ELGAMAL;
		break;
	    }
	}
	else if( algo == 3 && addmode ) {
	    algo = PUBKEY_ALGO_ELGAMAL_E;
	    break;
	}
	else if( algo == 2 ) {
	    algo = PUBKEY_ALGO_DSA;
	    break;
	}
	else
	    tty_printf(_("Invalid selection.\n"));
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
	answer = cpr_get("keygen.size",
			  _("What keysize do you want? (1024) "));
	cpr_kill_prompt();
	nbits = *answer? atoi(answer): 1024;
	m_free(answer);
	if( algo == PUBKEY_ALGO_DSA && (nbits < 512 || nbits > 1024) )
	    tty_printf(_("DSA only allows keysizes from 512 to 1024\n"));
	else if( nbits < 768 )
	    tty_printf(_("keysize too small; 768 is smallest value allowed.\n"));
	else if( algo == PUBKEY_ALGO_RSA && nbits < 1024 )
	    tty_printf(_("keysize too small;"
			 " 1024 is smallest value allowed for RSA.\n"));
	else if( nbits > 4096 ) {
	    /* It is ridiculous and an annoyance to use larger key sizes!
	     * GnuPG can handle much larger sizes; but it takes an eternity
	     * to create such a key (but less than the time the Sirius
	     * Computer Corporation needs to process one of the usual
	     * complaints) and {de,en}cryption although needs some time.
	     * So, before you complain about this limitation, I suggest that
	     * you start a discussion with Marvin about this theme and then
	     * do whatever you want. */
	    tty_printf(_("keysize too large; %d is largest value allowed.\n"),
									 4096);
	}
	else if( nbits > 2048 && !cpr_enabled() ) {
	    tty_printf(
		_("Keysizes larger than 2048 are not suggested because\n"
		  "computations take REALLY long!\n"));
	    if( cpr_get_answer_is_yes("keygen.size.huge.okay",_(
			"Are you sure that you want this keysize? ")) ) {
		tty_printf(_("Okay, but keep in mind that your monitor "
			     "and keyboard radiation is also very vulnerable "
			     "to attacks!\n"));
		break;
	    }
	}
	else if( nbits > 1536 && !cpr_enabled() && algo != PUBKEY_ALGO_RSA ) {
	    if( cpr_get_answer_is_yes("keygen.size.large.okay",_(
		    "Do you really need such a large keysize? ")) )
		break;
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


/****************
 * Parse an expire string and return it's value in days.
 * Returns -1 on error.
 */
static int
parse_expire_string( const char *string )
{
    int mult;
    u32 abs_date=0;
    u32 curtime = make_timestamp();
    int valid_days;

    if( !*string )
	valid_days = 0;
    else if( (abs_date = scan_isodatestr(string)) && abs_date > curtime ) {
	/* This calculation is not perfectly okay because we
	 * are later going to simply multiply by 86400 and don't
	 * correct for leapseconds.  A solution would be to change
	 * the whole implemenation to work with dates and not intervals
	 * which are required for v3 keys.
	 */
	valid_days = abs_date/86400-curtime/86400+1;
    }
    else if( (mult=check_valid_days(string)) ) {
	valid_days = atoi(string) * mult;
	if( valid_days < 0 || valid_days > 39447 )
	    valid_days = 0;
    }
    else {
	valid_days = -1;
    }
    return valid_days;
}


static u32
ask_expire_interval(void)
{
    char *answer;
    int valid_days=0;
    u32 interval = 0;

    tty_printf(_("Please specify how long the key should be valid.\n"
		 "         0 = key does not expire\n"
		 "      <n>  = key expires in n days\n"
		 "      <n>w = key expires in n weeks\n"
		 "      <n>m = key expires in n months\n"
		 "      <n>y = key expires in n years\n"));
    /* Note: The elgamal subkey for DSA has no expiration date because
     * it must be signed with the DSA key and this one has the expiration
     * date */

    answer = NULL;
    for(;;) {
	u32 curtime=make_timestamp();

	m_free(answer);
	answer = cpr_get("keygen.valid",_("Key is valid for? (0) "));
	cpr_kill_prompt();
	trim_spaces(answer);
	valid_days = parse_expire_string( answer );
	if( valid_days < 0 ) {
	    tty_printf(_("invalid value\n"));
	    continue;
	}

	if( !valid_days ) {
	    tty_printf(_("Key does not expire at all\n"));
	    interval = 0;
	}
	else {
	    interval = valid_days * 86400L;
	    /* print the date when the key expires */
	    tty_printf(_("Key expires at %s\n"),
			asctimestamp((ulong)(curtime + interval) ) );
	    if( (time_t)((ulong)(curtime+interval)) < 0 )
		tty_printf(_("Your system can't display dates beyond 2038.\n"
		    "However, it will be correctly handled up to 2106.\n"));
	}

	if( cpr_enabled() || cpr_get_answer_is_yes("keygen.valid.okay",
					    _("Is this correct (y/n)? ")) )
	    break;
    }
    m_free(answer);
    return interval;
}

u32
ask_expiredate()
{
    u32 x = ask_expire_interval();
    return x? make_timestamp() + x : 0;
}

static int
has_invalid_email_chars( const char *s )
{
    int at_seen=0;
    static char valid_chars[] = "01234567890_-."
				"abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for( ; *s; s++ ) {
	if( *s & 0x80 )
	    return 1;
	if( *s == '@' )
	    at_seen=1;
	else if( !at_seen && !( !!strchr( valid_chars, *s ) || *s == '+' ) )
	    return 1;
	else if( at_seen && !strchr( valid_chars, *s ) )
	    return 1;
    }
    return 0;
}


static char *
ask_user_id( int mode )
{
    char *answer;
    char *aname, *acomment, *amail, *uid;

    if( !mode )
	tty_printf( _("\n"
"You need a User-ID to identify your key; the software constructs the user id\n"
"from Real Name, Comment and Email Address in this form:\n"
"    \"Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>\"\n\n") );
    uid = aname = acomment = amail = NULL;
    for(;;) {
	char *p;
	int fail=0;

	if( !aname ) {
	    for(;;) {
		m_free(aname);
		aname = cpr_get("keygen.name",_("Real name: "));
		trim_spaces(aname);
		cpr_kill_prompt();

		if( opt.allow_freeform_uid )
		    break;

		if( strpbrk( aname, "<>" ) )
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
		amail = cpr_get("keygen.email",_("Email address: "));
		trim_spaces(amail);
		cpr_kill_prompt();
		if( !*amail )
		    break;   /* no email address is okay */
		else if( has_invalid_email_chars(amail)
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
		acomment = cpr_get("keygen.comment",_("Comment: "));
		trim_spaces(acomment);
		cpr_kill_prompt();
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

	/* print a note in case that UTF8 mapping has to be done */
	for(p=uid; *p; p++ ) {
	    if( *p & 0x80 ) {
		tty_printf(_("You are using the `%s' character set.\n"),
			   get_native_charset() );
		break;
	    }
	}

	tty_printf(_("You selected this USER-ID:\n    \"%s\"\n\n"), uid);
	/* fixme: add a warning if this user-id already exists */
	if( !*amail && (strchr( aname, '@' ) || strchr( acomment, '@'))) {
	    fail = 1;
	    tty_printf(_("Please don't put the email address "
			  "into the real name or the comment\n") );
	}

	for(;;) {
	    char *ansstr = _("NnCcEeOoQq");

	    if( strlen(ansstr) != 10 )
		BUG();
	    if( cpr_enabled() ) {
		answer = m_strdup(ansstr+6);
		answer[1] = 0;
	    }
	    else {
		answer = cpr_get("keygen.userid.cmd", fail?
		  _("Change (N)ame, (C)omment, (E)mail or (Q)uit? ") :
		  _("Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? "));
		cpr_kill_prompt();
	    }
	    if( strlen(answer) > 1 )
		;
	    else if( *answer == ansstr[0] || *answer == ansstr[1] ) {
		m_free(aname); aname = NULL;
		break;
	    }
	    else if( *answer == ansstr[2] || *answer == ansstr[3] ) {
		m_free(acomment); acomment = NULL;
		break;
	    }
	    else if( *answer == ansstr[4] || *answer == ansstr[5] ) {
		m_free(amail); amail = NULL;
		break;
	    }
	    else if( *answer == ansstr[6] || *answer == ansstr[7] ) {
		if( fail ) {
		    tty_printf(_("Please correct the error first\n"));
		}
		else {
		    m_free(aname); aname = NULL;
		    m_free(acomment); acomment = NULL;
		    m_free(amail); amail = NULL;
		    break;
		}
	    }
	    else if( *answer == ansstr[8] || *answer == ansstr[9] ) {
		m_free(aname); aname = NULL;
		m_free(acomment); acomment = NULL;
		m_free(amail); amail = NULL;
		m_free(uid); uid = NULL;
		break;
	    }
	    m_free(answer);
	}
	m_free(answer);
	if( !amail && !acomment && !amail )
	    break;
	m_free(uid); uid = NULL;
    }
    if( uid ) {
	char *p = native_to_utf8( uid );
	m_free( uid );
	uid = p;
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
	s2k->mode = opt.s2k_mode;
	s2k->hash_algo = opt.s2k_digest_algo;
	dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k, 2 );
	if( !dek ) {
	    tty_printf(_("passphrase not correctly repeated; try again.\n"));
	}
	else if( !dek->keylen ) {
	    m_free(dek); dek = NULL;
	    m_free(s2k); s2k = NULL;
	    tty_printf(_(
	    "You don't want a passphrase - this is probably a *bad* idea!\n"
	    "I will do it anyway.  You can change your passphrase at any time,\n"
	    "using this program with the option \"--edit-key\".\n\n"));
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
	   DEK *dek, STRING2KEY *s2k, PKT_secret_key **sk, u32 expiredate )
{
    int rc=0;

    if( !opt.batch )
	tty_printf(_(
"We need to generate a lot of random bytes. It is a good idea to perform\n"
"some other action (type on the keyboard, move the mouse, utilize the\n"
"disks) during the prime generation; this gives the random number\n"
"generator a better chance to gain enough entropy.\n") );

    if( algo == PUBKEY_ALGO_ELGAMAL || algo == PUBKEY_ALGO_ELGAMAL_E )
	rc = gen_elg(algo, nbits, pub_root, sec_root, dek, s2k, sk, expiredate);
    else if( algo == PUBKEY_ALGO_DSA )
	rc = gen_dsa(nbits, pub_root, sec_root, dek, s2k, sk, expiredate);
  #if 0
    else if( algo == PUBKEY_ALGO_RSA )
	rc = gen_rsa(algo, nbits, pub_root, sec_root, dek, s2k, sk, expiredate);
  #endif
    else
	BUG();

  #ifdef ENABLE_COMMENT_PACKETS
    if( !rc ) {
	add_kbnode( pub_root,
		make_comment_node("#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")"));
	add_kbnode( sec_root,
		make_comment_node("#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")"));
    }
  #endif
    return rc;
}


/****************
 * Generate a new user id packet, or return NULL if canceled
 */
PKT_user_id *
generate_user_id()
{
    PKT_user_id *uid;
    char *p;
    size_t n;

    p = ask_user_id( 1 );
    if( !p )
	return NULL;
    n = strlen(p);
    uid = m_alloc_clear( sizeof *uid + n - 1 );
    uid->len = n;
    strcpy(uid->name, p);
    return uid;
}


static void
release_parameter_list( struct para_data_s *r )
{
    struct para_data_s *r2;

    for( ; r ; r = r2 ) {
	r2 = r->next;
	if( r->key == pPASSPHRASE_DEK )
	    m_free( r->u.dek );
	else if( r->key == pPASSPHRASE_S2K )
	    m_free( r->u.s2k );

	m_free(r);
    }
}

static struct para_data_s *
get_parameter( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r;

    for( r = para; r && r->key != key; r = r->next )
	;
    return r;
}

static const char *
get_parameter_value( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return (r && *r->u.value)? r->u.value : NULL;
}

static int
get_parameter_algo( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    if( !r )
	return -1;
    if( isdigit( *r->u.value ) )
	return atoi( r->u.value );
    return string_to_pubkey_algo( r->u.value );
}


static u32
get_parameter_u32( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );

    if( !r )
	return 0;
    if( r->key == pKEYEXPIRE || r->key == pSUBKEYEXPIRE )
	return r->u.expire;

    return (unsigned int)strtoul( r->u.value, NULL, 10 );
}

static unsigned int
get_parameter_uint( struct para_data_s *para, enum para_name key )
{
    return get_parameter_u32( para, key );
}

static DEK *
get_parameter_dek( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return r? r->u.dek : NULL;
}

static STRING2KEY *
get_parameter_s2k( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return r? r->u.s2k : NULL;
}


static int
proc_parameter_file( struct para_data_s *para, const char *fname,
				       struct output_control_s *outctrl )
{
    struct para_data_s *r;
    const char *s1, *s2, *s3;
    size_t n;
    char *p;
    int i;

    /* check that we have all required parameters */
    assert( get_parameter( para, pKEYTYPE ) );
    i = get_parameter_algo( para, pKEYTYPE );
    if( i < 1 || check_pubkey_algo2( i, PUBKEY_USAGE_SIG ) ) {
	r = get_parameter( para, pKEYTYPE );
	log_error("%s:%d: invalid algorithm\n", fname, r->lnr );
	return -1;
    }

    i = get_parameter_algo( para, pSUBKEYTYPE );
    if( i > 1 && check_pubkey_algo( i ) ) {
	r = get_parameter( para, pSUBKEYTYPE );
	log_error("%s:%d: invalid algorithm\n", fname, r->lnr );
	return -1;
    }

    if( !get_parameter_value( para, pUSERID ) ) {
	/* create the formatted user ID */
	s1 = get_parameter_value( para, pNAMEREAL );
	s2 = get_parameter_value( para, pNAMECOMMENT );
	s3 = get_parameter_value( para, pNAMEEMAIL );
	if( s1 || s2 || s3 ) {
	    n = (s1?strlen(s1):0) + (s2?strlen(s2):0) + (s3?strlen(s3):0);
	    r = m_alloc_clear( sizeof *r + n + 20 );
	    r->key = pUSERID;
	    p = r->u.value;
	    if( s1 )
		p = stpcpy(p, s1 );
	    if( s2 )
		p = stpcpy(stpcpy(stpcpy(p," ("), s2 ),")");
	    if( s3 )
		p = stpcpy(stpcpy(stpcpy(p," <"), s3 ),">");
	    r->next = para;
	    para = r;
	}
    }

    /* make DEK and S2K from the Passphrase */
    r = get_parameter( para, pPASSPHRASE );
    if( r && *r->u.value ) {
	/* we have a plain text passphrase - create a DEK from it.
	 * It is a little bit ridiculous to keep it ih secure memory
	 * but becuase we do this alwasy, why not here */
	STRING2KEY *s2k;
	DEK *dek;

	s2k = m_alloc_secure( sizeof *s2k );
	s2k->mode = opt.s2k_mode;
	s2k->hash_algo = opt.s2k_digest_algo;
	set_next_passphrase( r->u.value );
	dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k, 2 );
	set_next_passphrase( NULL );
	assert( dek );
	memset( r->u.value, 0, strlen(r->u.value) );

	r = m_alloc_clear( sizeof *r );
	r->key = pPASSPHRASE_S2K;
	r->u.s2k = s2k;
	r->next = para;
	para = r;
	r = m_alloc_clear( sizeof *r );
	r->key = pPASSPHRASE_DEK;
	r->u.dek = dek;
	r->next = para;
	para = r;
    }

    /* make KEYEXPIRE from Expire-Date */
    r = get_parameter( para, pEXPIREDATE );
    if( r && *r->u.value ) {
	i = parse_expire_string( r->u.value );
	if( i < 0 ) {
	    log_error("%s:%d: invalid expire date\n", fname, r->lnr );
	    return -1;
	}
	r->u.expire = i * 86400L;
	r->key = pKEYEXPIRE;  /* change hat entry */
	/* also set it for the subkey */
	r = m_alloc_clear( sizeof *r + 20 );
	r->key = pSUBKEYEXPIRE;
	r->u.expire = i * 86400L;
	r->next = para;
	para = r;
    }

    if( !!outctrl->pub.newfname ^ !!outctrl->sec.newfname ) {
	log_error("%s:%d: only one ring name is set\n", fname, outctrl->lnr );
	return -1;
    }

    do_generate_keypair( para, outctrl );
    return 0;
}


/****************
 * Kludge to allow non interactive key generation controlled
 * by a parameter file (which currently is only stdin)
 * Note, that string parameters are expected to be in UTF-8
 */
static void
read_parameter_file( const char *fname )
{
    static struct { const char *name;
		    enum para_name key;
    } keywords[] = {
	{ "Key-Type",       pKEYTYPE},
	{ "Key-Length",     pKEYLENGTH },
	{ "Subkey-Type",    pSUBKEYTYPE },
	{ "Subkey-Length",  pSUBKEYLENGTH },
	{ "Name-Real",      pNAMEREAL },
	{ "Name-Email",     pNAMEEMAIL },
	{ "Name-Comment",   pNAMECOMMENT },
	{ "Expire-Date",    pEXPIREDATE },
	{ "Passphrase",     pPASSPHRASE },
	{ NULL, 0 }
    };
    FILE *fp;
    char line[1024], *p;
    int lnr;
    const char *err = NULL;
    struct para_data_s *para, *r;
    int i;
    struct output_control_s outctrl;

    memset( &outctrl, 0, sizeof( outctrl ) );

    if( !fname || !*fname || !strcmp(fname,"-") ) {
	fp = stdin;
	fname = "-";
    }
    else {
	fp = fopen( fname, "r" );
	if( !fp ) {
	    log_error(_("can't open `%s': %s\n"), fname, strerror(errno) );
	    return;
	}
    }

    lnr = 0;
    err = NULL;
    para = NULL;
    while( fgets( line, DIM(line)-1, fp ) ) {
	char *keyword, *value;

	lnr++;
	if( *line && line[strlen(line)-1] != '\n' ) {
	    err = "line too long";
	    break;
	}
	for( p = line; isspace(*(byte*)p); p++ )
	    ;
	if( !*p || *p == '#' )
	    continue;
	keyword = p;
	if( *keyword == '%' ) {
	    for( ; !isspace(*(byte*)p); p++ )
		;
	    if( *p )
		*p++ = 0;
	    for( ; isspace(*(byte*)p); p++ )
		;
	    value = p;
	    trim_trailing_ws( value, strlen(value) );
	    if( !stricmp( keyword, "%echo" ) )
		log_info("%s\n", value );
	    else if( !stricmp( keyword, "%dry-run" ) )
		outctrl.dryrun = 1;
	    else if( !stricmp( keyword, "%commit" ) ) {
		outctrl.lnr = lnr;
		proc_parameter_file( para, fname, &outctrl );
		release_parameter_list( para );
		para = NULL;
	    }
	    else if( !stricmp( keyword, "%pubring" ) ) {
		if( outctrl.pub.fname && !strcmp( outctrl.pub.fname, value ) )
		    ; /* still the same file - ignore it */
		else {
		    m_free( outctrl.pub.newfname );
		    outctrl.pub.newfname = m_strdup( value );
		    outctrl.use_files = 1;
		}
	    }
	    else if( !stricmp( keyword, "%secring" ) ) {
		if( outctrl.sec.fname && !strcmp( outctrl.sec.fname, value ) )
		    ; /* still the same file - ignore it */
		else {
		   m_free( outctrl.sec.newfname );
		   outctrl.sec.newfname = m_strdup( value );
		   outctrl.use_files = 1;
		}
	    }
	    else
		log_info("skipping control `%s' (%s)\n", keyword, value );


	    continue;
	}


	if( !(p = strchr( p, ':' )) || p == keyword ) {
	    err = "missing colon";
	    break;
	}
	if( *p )
	    *p++ = 0;
	for( ; isspace(*(byte*)p); p++ )
	    ;
	if( !*p ) {
	    err = "missing argument";
	    break;
	}
	value = p;
	trim_trailing_ws( value, strlen(value) );

	for(i=0; keywords[i].name; i++ ) {
	    if( !stricmp( keywords[i].name, keyword ) )
		break;
	}
	if( !keywords[i].name ) {
	    err = "unknown keyword";
	    break;
	}
	if( keywords[i].key != pKEYTYPE && !para ) {
	    err = "parameter block does not start with \"Key-Type\"";
	    break;
	}

	if( keywords[i].key == pKEYTYPE && para ) {
	    outctrl.lnr = lnr;
	    proc_parameter_file( para, fname, &outctrl );
	    release_parameter_list( para );
	    para = NULL;
	}
	else {
	    for( r = para; r; r = r->next ) {
		if( r->key == keywords[i].key )
		    break;
	    }
	    if( r ) {
		err = "duplicate keyword";
		break;
	    }
	}
	r = m_alloc_clear( sizeof *r + strlen( value ) );
	r->lnr = lnr;
	r->key = keywords[i].key;
	strcpy( r->u.value, value );
	r->next = para;
	para = r;
    }
    if( err )
	log_error("%s:%d: %s\n", fname, lnr, err );
    else if( ferror(fp) ) {
	log_error("%s:%d: read error: %s\n", fname, lnr, strerror(errno) );
    }
    else if( para ) {
	outctrl.lnr = lnr;
	proc_parameter_file( para, fname, &outctrl );
    }

    if( outctrl.use_files ) { /* close open streams */
	iobuf_close( outctrl.pub.stream );
	iobuf_close( outctrl.sec.stream );
	m_free( outctrl.pub.fname );
	m_free( outctrl.pub.newfname );
	m_free( outctrl.sec.fname );
	m_free( outctrl.sec.newfname );
    }

    release_parameter_list( para );
    if( strcmp( fname, "-" ) )
	fclose(fp);
}


/****************
 * Generate a keypair
 * (fname is only used in batch mode)
 */
void
generate_keypair( const char *fname )
{
    unsigned int nbits;
    char *uid = NULL;
    DEK *dek;
    STRING2KEY *s2k;
    int algo;
    int both = 0;
    u32 expire;
    struct para_data_s *para = NULL;
    struct para_data_s *r;
    struct output_control_s outctrl;

    memset( &outctrl, 0, sizeof( outctrl ) );

    if( opt.batch ) {
	read_parameter_file( fname );
	return;
    }

    algo = ask_algo( 0 );
    if( !algo ) { /* default: DSA with ElG subkey of the specified size */
	both = 1;
	r = m_alloc_clear( sizeof *r + 20 );
	r->key = pKEYTYPE;
	sprintf( r->u.value, "%d", PUBKEY_ALGO_DSA );
	r->next = para;
	para = r;
	tty_printf(_("DSA keypair will have 1024 bits.\n"));
	r = m_alloc_clear( sizeof *r + 20 );
	r->key = pKEYLENGTH;
	strcpy( r->u.value, "1024" );
	r->next = para;
	para = r;

	algo = PUBKEY_ALGO_ELGAMAL_E;
	r = m_alloc_clear( sizeof *r + 20 );
	r->key = pSUBKEYTYPE;
	sprintf( r->u.value, "%d", algo );
	r->next = para;
	para = r;
    }
    else {
	r = m_alloc_clear( sizeof *r + 20 );
	r->key = pKEYTYPE;
	sprintf( r->u.value, "%d", algo );
	r->next = para;
	para = r;
    }

    nbits = ask_keysize( algo );
    r = m_alloc_clear( sizeof *r + 20 );
    r->key = both? pSUBKEYLENGTH : pKEYLENGTH;
    sprintf( r->u.value, "%u", nbits);
    r->next = para;
    para = r;

    expire = ask_expire_interval();
    r = m_alloc_clear( sizeof *r + 20 );
    r->key = pKEYEXPIRE;
    r->u.expire = expire;
    r->next = para;
    para = r;
    r = m_alloc_clear( sizeof *r + 20 );
    r->key = pSUBKEYEXPIRE;
    r->u.expire = expire;
    r->next = para;
    para = r;

    uid = ask_user_id(0);
    if( !uid ) {
	log_error(_("Key generation canceled.\n"));
	release_parameter_list( para );
	return;
    }
    r = m_alloc_clear( sizeof *r + strlen(uid) );
    r->key = pUSERID;
    strcpy( r->u.value, uid );
    r->next = para;
    para = r;

    dek = ask_passphrase( &s2k );
    if( dek ) {
	r = m_alloc_clear( sizeof *r );
	r->key = pPASSPHRASE_DEK;
	r->u.dek = dek;
	r->next = para;
	para = r;
	r = m_alloc_clear( sizeof *r );
	r->key = pPASSPHRASE_S2K;
	r->u.s2k = s2k;
	r->next = para;
	para = r;
    }

    proc_parameter_file( para, "[internal]", &outctrl );
    release_parameter_list( para );
}


static void
do_generate_keypair( struct para_data_s *para,
		     struct output_control_s *outctrl )
{
    char *pub_fname = NULL;
    char *sec_fname = NULL;
    KBNODE pub_root = NULL;
    KBNODE sec_root = NULL;
    PKT_secret_key *sk = NULL;
    const char *s;
    int rc;
    int did_sub = 0;

    if( outctrl->dryrun ) {
	log_info("dry-run mode - key generation skipped\n");
	return;
    }


    if( outctrl->use_files ) {
	if( outctrl->pub.newfname ) {
	    iobuf_close(outctrl->pub.stream);
	    outctrl->pub.stream = NULL;
	    m_free( outctrl->pub.fname );
	    outctrl->pub.fname =  outctrl->pub.newfname;
	    outctrl->pub.newfname = NULL;

	    outctrl->pub.stream = iobuf_create( outctrl->pub.fname );
	    if( !outctrl->pub.stream ) {
		log_error("can't create `%s': %s\n", outctrl->pub.newfname,
						     strerror(errno) );
		return;
	    }
	    if( opt.armor ) {
		outctrl->pub.afx.what = 1;
		iobuf_push_filter( outctrl->pub.stream, armor_filter,
						    &outctrl->pub.afx );
	    }
	}
	if( outctrl->sec.newfname ) {
	    iobuf_close(outctrl->sec.stream);
	    outctrl->sec.stream = NULL;
	    m_free( outctrl->sec.fname );
	    outctrl->sec.fname =  outctrl->sec.newfname;
	    outctrl->sec.newfname = NULL;

	    outctrl->sec.stream = iobuf_create( outctrl->sec.fname );
	    if( !outctrl->sec.stream ) {
		log_error("can't create `%s': %s\n", outctrl->sec.newfname,
						     strerror(errno) );
		return;
	    }
	    if( opt.armor ) {
		outctrl->sec.afx.what = 5;
		iobuf_push_filter( outctrl->sec.stream, armor_filter,
						    &outctrl->sec.afx );
	    }
	}
	pub_fname = outctrl->pub.fname; /* only for info output */
	sec_fname = outctrl->sec.fname; /* only for info output */
	assert( outctrl->pub.stream );
	assert( outctrl->sec.stream );
    }
    else {
	pub_fname = get_writable_keyblock_file( 0 );
	sec_fname = get_writable_keyblock_file( 1 );
    }

    if( opt.verbose ) {
	log_info(_("writing public key to `%s'\n"), pub_fname );
	log_info(_("writing secret key to `%s'\n"), sec_fname );
    }

    /* we create the packets as a tree of kbnodes. Because the structure
     * we create is known in advance we simply generate a linked list
     * The first packet is a dummy comment packet which we flag
     * as deleted.  The very first packet must always be a KEY packet.
     */
    pub_root = make_comment_node("#"); delete_kbnode(pub_root);
    sec_root = make_comment_node("#"); delete_kbnode(sec_root);

    rc = do_create( get_parameter_algo( para, pKEYTYPE ),
		    get_parameter_uint( para, pKEYLENGTH ),
		    pub_root, sec_root,
		    get_parameter_dek( para, pPASSPHRASE_DEK ),
		    get_parameter_s2k( para, pPASSPHRASE_S2K ),
		    &sk,
		    get_parameter_u32( para, pKEYEXPIRE ) );
    if( !rc && (s=get_parameter_value(para, pUSERID)) ) {
	write_uid(pub_root, s );
	if( !rc )
	    write_uid(sec_root, s );
	if( !rc )
	    rc = write_selfsig(pub_root, pub_root, sk);
	if( !rc )
	    rc = write_selfsig(sec_root, pub_root, sk);
    }

    if( get_parameter( para, pSUBKEYTYPE ) ) {
	rc = do_create( get_parameter_algo( para, pSUBKEYTYPE ),
			get_parameter_uint( para, pSUBKEYLENGTH ),
			pub_root, sec_root,
			get_parameter_dek( para, pPASSPHRASE_DEK ),
			get_parameter_s2k( para, pPASSPHRASE_S2K ),
			NULL,
			get_parameter_u32( para, pSUBKEYEXPIRE ) );
	if( !rc )
	    rc = write_keybinding(pub_root, pub_root, sk);
	if( !rc )
	    rc = write_keybinding(sec_root, pub_root, sk);
        did_sub = 1;
    }


    if( !rc && outctrl->use_files ) { /* direct write to specified files */
	rc = write_keyblock( outctrl->pub.stream, pub_root );
	if( rc )
	    log_error("can't write public key: %s\n", g10_errstr(rc) );
	if( !rc ) {
	    rc = write_keyblock( outctrl->sec.stream, sec_root );
	    if( rc )
		log_error("can't write secret key: %s\n", g10_errstr(rc) );
	}

    }
    else if( !rc ) { /* write to the standard keyrings */
	KBPOS pub_kbpos;
	KBPOS sec_kbpos;
	int rc1 = -1;
	int rc2 = -1;

	/* we can now write the certificates */
	if( get_keyblock_handle( pub_fname, 0, &pub_kbpos ) ) {
	    if( add_keyblock_resource( pub_fname, 1, 0 ) ) {
		log_error("can add keyblock file `%s'\n", pub_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( get_keyblock_handle( pub_fname, 0, &pub_kbpos ) ) {
		log_error("can get keyblock handle for `%s'\n", pub_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	}
	if( rc )
	    ;
	else if( get_keyblock_handle( sec_fname, 1, &sec_kbpos ) ) {
	    if( add_keyblock_resource( sec_fname, 1, 1 ) ) {
		log_error("can add keyblock file `%s'\n", sec_fname );
		rc = G10ERR_CREATE_FILE;
	    }
	    else if( get_keyblock_handle( sec_fname, 1, &sec_kbpos ) ) {
		log_error("can get keyblock handle for `%s'\n", sec_fname );
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
	    if( !opt.batch )
		 tty_printf(_("public and secret key created and signed.\n") );
	    if( !opt.batch
		&& get_parameter_algo( para, pKEYTYPE ) == PUBKEY_ALGO_DSA
		&& !get_parameter( para, pSUBKEYTYPE ) )
	    {
		tty_printf(_("Note that this key cannot be used for "
			     "encryption.  You may want to use\n"
			     "the command \"--edit-key\" to generate a "
			     "secondary key for this purpose.\n") );
	    }
	}

	if( !rc1 )
	    unlock_keyblock( &pub_kbpos );
	if( !rc2 )
	    unlock_keyblock( &sec_kbpos );
    }

    if( rc ) {
	if( opt.batch )
	    log_error("key generation failed: %s\n", g10_errstr(rc) );
	else
	    tty_printf(_("Key generation failed: %s\n"), g10_errstr(rc) );
    }
    else {
        write_status_text (STATUS_KEY_CREATED, did_sub? "B":"P");
    }
    release_kbnode( pub_root );
    release_kbnode( sec_root );
    if( sk ) /* the unprotected  secret key */
	free_secret_key(sk);
    if( !outctrl->use_files ) {
	m_free(pub_fname);
	m_free(sec_fname);
    }
}


/****************
 * add a new subkey to an existing key.
 * Returns true if a new key has been generated and put into the keyblocks.
 */
int
generate_subkeypair( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    int okay=0, rc=0;
    KBNODE node;
    PKT_secret_key *sk = NULL; /* this is the primary sk */
    int algo;
    u32 expire;
    unsigned nbits;
    char *passphrase = NULL;
    DEK *dek = NULL;
    STRING2KEY *s2k = NULL;
    u32 cur_time;

    /* break out the primary secret key */
    node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
    if( !node ) {
	log_error("Oops; secret key not found anymore!\n");
	goto leave;
    }

    /* make a copy of the sk to keep the protected one in the keyblock */
    sk = copy_secret_key( NULL, node->pkt->pkt.secret_key );

    cur_time = make_timestamp();
    if( sk->timestamp > cur_time ) {
	ulong d = sk->timestamp - cur_time;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	if( !opt.ignore_time_conflict ) {
	    rc = G10ERR_TIME_CONFLICT;
	    goto leave;
	}
    }


    /* unprotect to get the passphrase */
    switch( is_secret_key_protected( sk ) ) {
      case -1:
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf("This key is not protected.\n");
	break;
      default:
	tty_printf("Key is protected.\n");
	rc = check_secret_key( sk, 0 );
	if( !rc )
	    passphrase = get_last_passphrase();
	break;
    }
    if( rc )
	goto leave;


    algo = ask_algo( 1 );
    assert(algo);
    nbits = ask_keysize( algo );
    expire = ask_expire_interval();
    if( !cpr_enabled() && !cpr_get_answer_is_yes("keygen.sub.okay",
						  _("Really create? ") ) )
	goto leave;

    if( passphrase ) {
	s2k = m_alloc_secure( sizeof *s2k );
	s2k->mode = opt.s2k_mode;
	s2k->hash_algo = opt.s2k_digest_algo;
	set_next_passphrase( passphrase );
	dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k, 2 );
    }

    rc = do_create( algo, nbits, pub_keyblock, sec_keyblock,
				      dek, s2k, NULL, expire );
    if( !rc )
	rc = write_keybinding(pub_keyblock, pub_keyblock, sk);
    if( !rc )
	rc = write_keybinding(sec_keyblock, pub_keyblock, sk);
    if( !rc ) {
	okay = 1;
        write_status_text (STATUS_KEY_CREATED, "S");
    }

  leave:
    if( rc )
	log_error(_("Key generation failed: %s\n"), g10_errstr(rc) );
    m_free( passphrase );
    m_free( dek );
    m_free( s2k );
    if( sk ) /* release the copy of the (now unprotected) secret key */
	free_secret_key(sk);
    set_next_passphrase( NULL );
    return okay;
}

/****************
 * Write a keyblock to an output stream
 */
static int
write_keyblock( IOBUF out, KBNODE node )
{
    for( ; node ; node = node->next ) {
	int rc = build_packet( out, node->pkt );
	if( rc ) {
	    log_error("build_packet(%d) failed: %s\n",
			node->pkt->pkttype, g10_errstr(rc) );
	    return G10ERR_WRITE_FILE;
	}
    }
    return 0;
}

