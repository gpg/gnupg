/* mainproc.c - handle packets
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
#include <assert.h>

#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "util.h"
#include "cipher.h"
#include "keydb.h"
#include "filter.h"
#include "cipher.h"
#include "main.h"
#include "status.h"


/****************
 * Structure to hold the context
 */

typedef struct {
    PKT_public_cert *last_pubkey;
    PKT_secret_cert *last_seckey;
    PKT_user_id     *last_user_id;
    md_filter_context_t mfx;
    int sigs_only;   /* process only signatures and reject all other stuff */
    int encrypt_only; /* process only encrytion messages */
    STRLIST signed_data;
    DEK *dek;
    int last_was_pubkey_enc;
    KBNODE list;   /* the current list of packets */
    int have_data;
    IOBUF iobuf;    /* used to get the filename etc. */
} *CTX;


static int do_proc_packets( CTX c, IOBUF a );

static void list_node( CTX c, KBNODE node );
static void proc_tree( CTX c, KBNODE node );


static void
release_list( CTX c )
{
    if( !c->list )
	return;
    proc_tree(c, c->list );
    release_kbnode( c->list );
    c->list = NULL;
}


static int
add_onepass_sig( CTX c, PACKET *pkt )
{
    KBNODE node;

    if( c->list ) { /* add another packet */
	if( c->list->pkt->pkttype != PKT_ONEPASS_SIG ) {
	   log_error("add_onepass_sig: another packet is in the way\n");
	   release_list( c );
	}
	add_kbnode( c->list, new_kbnode( pkt ));
    }
    else /* insert the first one */
	c->list = node = new_kbnode( pkt );

    return 1;
}



static int
add_user_id( CTX c, PACKET *pkt )
{
    if( !c->list ) {
	log_error("orphaned user id\n" );
	return 0;
    }
    add_kbnode( c->list, new_kbnode( pkt ) );
    return 1;
}

static int
add_subkey( CTX c, PACKET *pkt )
{
    if( !c->list ) {
	log_error("subkey w/o mainkey\n" );
	return 0;
    }
    add_kbnode( c->list, new_kbnode( pkt ) );
    return 1;
}


static int
add_signature( CTX c, PACKET *pkt )
{
    KBNODE node;

    if( pkt->pkttype == PKT_SIGNATURE && !c->list ) {
	/* This is the first signature for the following datafile.
	 * G10 does not write such packets; instead it always uses
	 * onepass-sig packets.  The drawback of PGP's method
	 * of prepending the signature to the data is
	 * that it is not possible to make a signature from data read
	 * from stdin.	(G10 is able to read PGP stuff anyway.) */
	node = new_kbnode( pkt );
	c->list = node;
	return 1;
    }
    else if( !c->list )
	return 0; /* oops (invalid packet sequence)*/
    else if( !c->list->pkt )
	BUG();	/* so nicht */

    /* add a new signature node id at the end */
    node = new_kbnode( pkt );
    add_kbnode( c->list, node );
    return 1;
}


static void
proc_pubkey_enc( CTX c, PACKET *pkt )
{
    PKT_pubkey_enc *enc;
    int result = 0;

    c->last_was_pubkey_enc = 1;
    enc = pkt->pkt.pubkey_enc;
    /*printf("enc: encrypted by a pubkey with keyid %08lX\n", enc->keyid[1] );*/
    if( enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL
	|| enc->pubkey_algo == PUBKEY_ALGO_DSA
	|| enc->pubkey_algo == PUBKEY_ALGO_RSA	) {
	m_free(c->dek ); /* paranoid: delete a pending DEK */
	c->dek = m_alloc_secure( sizeof *c->dek );
	if( (result = get_session_key( enc, c->dek )) ) {
	    /* error: delete the DEK */
	    m_free(c->dek); c->dek = NULL;
	}
    }
    else
	result = G10ERR_PUBKEY_ALGO;

    if( result == -1 )
	;
    else if( !result ) {
	if( opt.verbose > 1 )
	    log_info( "pubkey_enc packet: Good DEK\n" );
    }
    else
	log_error( "pubkey_enc packet: %s\n", g10_errstr(result));
    free_packet(pkt);
}



static void
proc_encrypted( CTX c, PACKET *pkt )
{
    int result = 0;

    /*printf("dat: %sencrypted data\n", c->dek?"":"conventional ");*/
    if( !c->dek && !c->last_was_pubkey_enc ) {
	/* assume this is conventional encrypted data */
	c->dek = m_alloc_secure( sizeof *c->dek );
	c->dek->algo = opt.def_cipher_algo;
	result = make_dek_from_passphrase( c->dek, 0, NULL );
    }
    else if( !c->dek )
	result = G10ERR_NO_SECKEY;
    if( !result )
	result = decrypt_data( pkt->pkt.encrypted, c->dek );
    m_free(c->dek); c->dek = NULL;
    if( result == -1 )
	;
    else if( !result ) {
	if( opt.verbose > 1 )
	    log_info("encryption okay\n");
    }
    else {
	log_error("encryption failed: %s\n", g10_errstr(result));
    }
    free_packet(pkt);
    c->last_was_pubkey_enc = 0;
}


static void
proc_plaintext( CTX c, PACKET *pkt )
{
    PKT_plaintext *pt = pkt->pkt.plaintext;
    int rc;

    if( opt.verbose )
	log_info("original file name='%.*s'\n", pt->namelen, pt->name);
    free_md_filter_context( &c->mfx );
    /* fixme: take the digest algo(s) to use from the
     * onepass_sig packet (if we have these)
     * And look at the sigclass to check whether we should use the
     * textmode filter (sigclass 0x01)
     */
    c->mfx.md = md_open( DIGEST_ALGO_RMD160, 0);
    md_enable( c->mfx.md, DIGEST_ALGO_SHA1 );
    md_enable( c->mfx.md, DIGEST_ALGO_MD5 );
    rc = handle_plaintext( pt, &c->mfx );
    if( rc )
	log_error( "handle plaintext failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_pubkey_enc = 0;
}


static int
proc_compressed_cb( IOBUF a, void *info )
{
    return proc_signature_packets( a, ((CTX)info)->signed_data );
}

static int
proc_encrypt_cb( IOBUF a, void *info )
{
    return proc_encryption_packets( a );
}

static void
proc_compressed( CTX c, PACKET *pkt )
{
    PKT_compressed *zd = pkt->pkt.compressed;
    int rc;

    /*printf("zip: compressed data packet\n");*/
    if( c->sigs_only )
	rc = handle_compressed( zd, proc_compressed_cb, c );
    else if( c->encrypt_only )
	rc = handle_compressed( zd, proc_encrypt_cb, c );
    else
	rc = handle_compressed( zd, NULL, NULL );
    if( rc )
	log_error("uncompressing failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_pubkey_enc = 0;
}




/****************
 * check the signature
 * Returns: 0 = valid signature or an error code
 */
static int
do_check_sig( CTX c, KBNODE node )
{
    PKT_signature *sig;
    MD_HANDLE md;
    int algo, rc;

    assert( node->pkt->pkttype == PKT_SIGNATURE );
    sig = node->pkt->pkt.signature;

    algo = digest_algo_from_sig( sig );
    if( !algo )
	return G10ERR_PUBKEY_ALGO;
    if( (rc=check_digest_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x00 ) {
	if( c->mfx.md )
	    md = md_copy( c->mfx.md );
	else /* detached signature */
	    md = md_open( 0, 0 ); /* signature_check() will enable the md*/
    }
    else if( sig->sig_class == 0x01 ) {
	/* how do we know that we have to hash the (already hashed) text
	 * in canonical mode ??? (calculating both modes???) */
	if( c->mfx.md )
	    md = md_copy( c->mfx.md );
	else /* detached signature */
	    md = md_open( 0, 0 ); /* signature_check() will enable the md*/
    }
    else if( (sig->sig_class&~3) == 0x10
	     || sig->sig_class == 0x18
	     || sig->sig_class == 0x20
	     || sig->sig_class == 0x30	) { /* classes 0x10..0x17,0x20,0x30 */
	if( c->list->pkt->pkttype == PKT_PUBLIC_CERT
	    || c->list->pkt->pkttype == PKT_PUBKEY_SUBCERT ) {
	    return check_key_signature( c->list, node, NULL );
	}
	else {
	    log_error("invalid root packet for sigclass %02x\n",
							sig->sig_class);
	    return G10ERR_SIG_CLASS;
	}
    }
    else
	return G10ERR_SIG_CLASS;
    rc = signature_check( sig, md );
    md_close(md);

    return rc;
}



static void
print_userid( PACKET *pkt )
{
    if( !pkt )
	BUG();
    if( pkt->pkttype != PKT_USER_ID ) {
	printf("ERROR: unexpected packet type %d", pkt->pkttype );
	return;
    }
    print_string( stdout,  pkt->pkt.user_id->name, pkt->pkt.user_id->len,
							opt.with_colons );
}


static void
print_fingerprint( PKT_public_cert *pkc, PKT_secret_cert *skc )
{
    byte *array, *p;
    size_t i, n;

    p = array = skc? fingerprint_from_skc( skc, &n )
		   : fingerprint_from_pkc( pkc, &n );
    if( opt.with_colons ) {
	printf("fpr:::::::::");
	for(i=0; i < n ; i++, p++ )
	    printf("%02X", *p );
	putchar(':');
    }
    else {
	printf("     Key fingerprint =");
	if( n == 20 ) {
	    for(i=0; i < n ; i++, i++, p += 2 ) {
		if( i == 10 )
		    putchar(' ');
		printf(" %02X%02X", *p, p[1] );
	    }
	}
	else {
	    for(i=0; i < n ; i++, p++ ) {
		if( i && !(i%8) )
		    putchar(' ');
		printf(" %02X", *p );
	    }
	}
    }
    putchar('\n');
    m_free(array);
}


/****************
 * List the certificate in a user friendly way
 */

static void
list_node( CTX c, KBNODE node )
{
    int any=0;
    int mainkey;

    if( !node )
	;
    else if( (mainkey = (node->pkt->pkttype == PKT_PUBLIC_CERT) )
	     || node->pkt->pkttype == PKT_PUBKEY_SUBCERT ) {
	PKT_public_cert *pkc = node->pkt->pkt.public_cert;

	if( opt.with_colons ) {
	    u32 keyid[2];
	    keyid_from_pkc( pkc, keyid );
	    printf("%s::%u:%d:%08lX%08lX:%s:%u:::",
		    mainkey? "pub":"sub",
		    /* fixme: add trust value here */
		    nbits_from_pkc( pkc ),
		    pkc->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_pkc( pkc ),
		    (unsigned)pkc->valid_days
		    /* fixme: add LID and ownertrust here */
					    );
	}
	else
	    printf("%s  %4u%c/%08lX %s ",
				      mainkey? "pub":"sub",
				      nbits_from_pkc( pkc ),
				      pubkey_letter( pkc->pubkey_algo ),
				      (ulong)keyid_from_pkc( pkc, NULL ),
				      datestr_from_pkc( pkc )	  );
	/* and now list all userids with their signatures */
	for( node = node->next; node; node = node->next ) {
	    if( any != 2 && node->pkt->pkttype == PKT_SIGNATURE ) {
		if( !any ) {
		    if( node->pkt->pkt.signature->sig_class == 0x20 )
			puts("[revoked]");
		    else
			putchar('\n');
		}
		list_node(c,  node );
		any = 1;
	    }
	    else if( node->pkt->pkttype == PKT_USER_ID ) {
		KBNODE n;

		if( any ) {
		    if( opt.with_colons )
			printf("uid:::::::::");
		    else
			printf( "uid%*s", 28, "" );
		}
		print_userid( node->pkt );
		if( opt.with_colons )
		    putchar(':');
		putchar('\n');
		if( opt.fingerprint && !any )
		    print_fingerprint( pkc, NULL );
		for( n=node->next; n; n = n->next ) {
		    if( n->pkt->pkttype == PKT_USER_ID )
			break;
		    if( n->pkt->pkttype == PKT_SIGNATURE )
			list_node(c,  n );
		}
		any=2;
	    }
	    else if( mainkey && node->pkt->pkttype == PKT_PUBKEY_SUBCERT ) {
		if( !any ) {
		    putchar('\n');
		    any = 1;
		}
		list_node(c,  node );
	    }
	}
	if( any != 2 && mainkey )
	    printf("ERROR: no user id!\n");
	else if( any != 2 )
	    putchar('\n');
    }
    else if( (mainkey = (node->pkt->pkttype == PKT_SECRET_CERT) )
	     || node->pkt->pkttype == PKT_SECKEY_SUBCERT ) {
	PKT_secret_cert *skc = node->pkt->pkt.secret_cert;

	printf("%s  %4u%c/%08lX %s ",
				      mainkey? "sec":"ssb",
				       nbits_from_skc( skc ),
				      pubkey_letter( skc->pubkey_algo ),
				      (ulong)keyid_from_skc( skc, NULL ),
				      datestr_from_skc( skc )	);
	/* and now list all userids */
	while( (node = find_next_kbnode(node, PKT_USER_ID)) ) {
	    print_userid( node->pkt );
	    putchar('\n');
	    if( opt.fingerprint && !any )
		print_fingerprint( NULL, skc );
	    any=1;
	}
	if( !any && mainkey )
	    printf("ERROR: no user id!\n");
	else if( !any )
	    putchar('\n');
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE  ) {
	PKT_signature *sig = node->pkt->pkt.signature;
	int rc2=0;
	size_t n;
	char *p;
	int sigrc = ' ';

	if( !opt.list_sigs )
	    return;

	if( sig->sig_class == 0x20 || sig->sig_class == 0x30 )
	    fputs("rev", stdout);
	else
	    fputs("sig", stdout);
	if( opt.check_sigs ) {
	    fflush(stdout);
	    switch( (rc2=do_check_sig( c, node )) ) {
	      case 0:		       sigrc = '!'; break;
	      case G10ERR_BAD_SIGN:    sigrc = '-'; break;
	      case G10ERR_NO_PUBKEY:   sigrc = '?'; break;
	      default:		       sigrc = '%'; break;
	    }
	}
	if( opt.with_colons ) {
	    putchar(':');
	    if( sigrc != ' ' )
		putchar(sigrc);
	    printf(":::%08lX%08lX:%s::::", (ulong)sig->keyid[0],
		       (ulong)sig->keyid[1], datestr_from_sig(sig));
	}
	else
	    printf("%c       %08lX %s   ",
		    sigrc, (ulong)sig->keyid[1], datestr_from_sig(sig));
	if( sigrc == '%' )
	    printf("[%s] ", g10_errstr(rc2) );
	else if( sigrc == '?' )
	    ;
	else {
	    p = get_user_id( sig->keyid, &n );
	    print_string( stdout, p, n, opt.with_colons );
	    m_free(p);
	}
	if( opt.with_colons )
	    printf(":%02x:", sig->sig_class );
	putchar('\n');
    }
    else
	log_error("invalid node with packet of type %d\n", node->pkt->pkttype);
}


int
proc_packets( IOBUF a )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc = do_proc_packets( c, a );
    m_free( c );
    return rc;
}

int
proc_signature_packets( IOBUF a, STRLIST signedfiles )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;
    c->sigs_only = 1;
    c->signed_data = signedfiles;
    rc = do_proc_packets( c, a );
    m_free( c );
    return rc;
}

int
proc_encryption_packets( IOBUF a )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;
    c->encrypt_only = 1;
    rc = do_proc_packets( c, a );
    m_free( c );
    return rc;
}


int
do_proc_packets( CTX c, IOBUF a )
{
    PACKET *pkt = m_alloc( sizeof *pkt );
    int rc=0;
    int newpkt;

    c->iobuf = a;
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	/* cleanup if we have an illegal data structure */
	if( c->dek && pkt->pkttype != PKT_ENCRYPTED ) {
	    log_error("oops: valid pubkey enc packet not followed by data\n");
	    m_free(c->dek); c->dek = NULL; /* burn it */
	}

	if( rc ) {
	    free_packet(pkt);
	    if( rc == G10ERR_INVALID_PACKET )
		break;
	    continue;
	}
	newpkt = -1;
	if( opt.list_packets ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:   proc_encrypted( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	else if( c->sigs_only ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_CERT:
	      case PKT_SECRET_CERT:
	      case PKT_USER_ID:
	      case PKT_PUBKEY_ENC:
	      case PKT_ENCRYPTED:
		rc = G10ERR_UNEXPECTED;
		goto leave;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	else if( c->encrypt_only ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_CERT:
	      case PKT_SECRET_CERT:
	      case PKT_USER_ID:
		rc = G10ERR_UNEXPECTED;
		goto leave;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:   proc_encrypted( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	else {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_CERT:
	      case PKT_SECRET_CERT:
		release_list( c );
		c->list = new_kbnode( pkt );
		newpkt = 1;
		break;
	      case PKT_PUBKEY_SUBCERT:
	      case PKT_SECKEY_SUBCERT:
		newpkt = add_subkey( c, pkt );
		break;
	      case PKT_USER_ID:     newpkt = add_user_id( c, pkt ); break;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:   proc_encrypted( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	if( pkt->pkttype != PKT_SIGNATURE )
	    c->have_data = pkt->pkttype == PKT_PLAINTEXT;

	if( newpkt == -1 )
	    ;
	else if( newpkt ) {
	    pkt = m_alloc( sizeof *pkt );
	    init_packet(pkt);
	}
	else
	    free_packet(pkt);
    }
    rc = 0;

  leave:
    release_list( c );
    m_free(c->dek);
    free_packet( pkt );
    m_free( pkt );
    free_md_filter_context( &c->mfx );
    return rc;
}


static void
print_keyid( FILE *fp, u32 *keyid )
{
    size_t n;
    char *p = get_user_id( keyid, &n );
    print_string( fp, p, n, opt.with_colons );
    m_free(p);
}



static int
check_sig_and_print( CTX c, KBNODE node )
{
    PKT_signature *sig = node->pkt->pkt.signature;
    int rc;

    if( opt.skip_verify ) {
	log_info("signature verification suppressed\n");
	return 0;
    }

    rc = do_check_sig(c, node );
    if( !rc || rc == G10ERR_BAD_SIGN ) {
	char *p, *buf;

	p = get_user_id_string( sig->keyid );
	buf = m_alloc( 20 + strlen(p) );
	sprintf(buf, "%lu %s", (ulong)sig->timestamp, p );
	m_free(p);
	if( (p=strchr(buf,'\n')) )
	    *p = 0; /* just in case ... */
	write_status_text( rc? STATUS_BADSIG : STATUS_GOODSIG, buf );
	m_free(buf);
	log_info("%s signature from ", rc? "BAD":"Good");
	print_keyid( stderr, sig->keyid );
	putc('\n', stderr);
	if( opt.batch && rc )
	    g10_exit(1);
    }
    else {
	write_status( STATUS_ERRSIG );
	log_error("Can't check signature made by %08lX: %s\n",
		   (ulong)sig->keyid[1], g10_errstr(rc) );
    }
    return rc;
}


/****************
 * Process the tree which starts at node
 */
static void
proc_tree( CTX c, KBNODE node )
{
    KBNODE n1;
    int rc;

    if( opt.list_packets )
	return;

    if( node->pkt->pkttype == PKT_PUBLIC_CERT
	|| node->pkt->pkttype == PKT_PUBKEY_SUBCERT )
	list_node( c, node );
    else if( node->pkt->pkttype == PKT_SECRET_CERT )
	list_node( c, node );
    else if( node->pkt->pkttype == PKT_ONEPASS_SIG ) {
	/* check all signatures */
	if( !c->have_data ) {
	    free_md_filter_context( &c->mfx );
	    /* prepare to create all requested message digests */
	    c->mfx.md = md_open(0, 0);
	    /* fixme: why looking for the signature packet and not 1passpacket*/
	    for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); ) {
		md_enable( c->mfx.md,
			   digest_algo_from_sig(n1->pkt->pkt.signature));
	    }
	    /* ask for file and hash it */
	    if( c->sigs_only )
		rc = hash_datafiles( c->mfx.md, c->signed_data,
			    n1->pkt->pkt.onepass_sig->sig_class == 0x01 );
	    else
		rc = ask_for_detached_datafile( &c->mfx,
					    iobuf_get_fname(c->iobuf));
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return;
	    }
	}

	for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); )
	    check_sig_and_print( c, n1 );
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	PKT_signature *sig = node->pkt->pkt.signature;

	if( !c->have_data ) {
	    free_md_filter_context( &c->mfx );
	    c->mfx.md = md_open(digest_algo_from_sig(sig), 0);
	    if( c->sigs_only )
		rc = hash_datafiles( c->mfx.md, c->signed_data,
				     sig->sig_class == 0x01 );
	    else
		rc = ask_for_detached_datafile( &c->mfx,
					    iobuf_get_fname(c->iobuf));
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return;
	    }
	}
	else
	    log_info("old style signature\n");

	check_sig_and_print( c, node );
    }
    else
	log_error("proc_tree: invalid root packet\n");

}



