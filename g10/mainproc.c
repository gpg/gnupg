/* mainproc.c - handle packets
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
#include <assert.h>
#include <time.h>

#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "util.h"
#include "cipher.h"
#include "keydb.h"
#include "filter.h"
#include "main.h"
#include "status.h"
#include "i18n.h"
#include "trustdb.h"
#include "hkp.h"


struct kidlist_item {
    struct kidlist_item *next;
    u32 kid[2];
    int pubkey_algo;
    int reason;
};



/****************
 * Structure to hold the context
 */
typedef struct mainproc_context *CTX;
struct mainproc_context {
    struct mainproc_context *anchor;  /* may be useful in the future */
    PKT_public_key *last_pubkey;
    PKT_secret_key *last_seckey;
    PKT_user_id     *last_user_id;
    md_filter_context_t mfx;
    int sigs_only;   /* process only signatures and reject all other stuff */
    int encrypt_only; /* process only encrytion messages */
    STRLIST signed_data;
    const char *sigfilename;
    DEK *dek;
    int last_was_session_key;
    KBNODE list;   /* the current list of packets */
    int have_data;
    IOBUF iobuf;    /* used to get the filename etc. */
    int trustletter; /* temp usage in list_node */
    ulong local_id;    /* ditto */
    struct kidlist_item *failed_pkenc;	/* list of packets for which
					   we do not have a secret key */
};


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
    while( c->failed_pkenc ) {
	struct kidlist_item *tmp = c->failed_pkenc->next;
	m_free( c->failed_pkenc );
	c->failed_pkenc = tmp;
    }
    c->failed_pkenc = NULL;
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
	   c->list = new_kbnode( pkt );
	}
	else
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
	log_error("orphaned user ID\n" );
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
add_ring_trust( CTX c, PACKET *pkt )
{
    if( !c->list ) {
	log_error("ring trust w/o key\n" );
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
proc_symkey_enc( CTX c, PACKET *pkt )
{
    PKT_symkey_enc *enc;

    enc = pkt->pkt.symkey_enc;
    if( enc->seskeylen )
	log_error( "symkey_enc packet with session keys are not supported!\n");
    else {
	c->last_was_session_key = 2;
	c->dek = passphrase_to_dek( NULL, 0, enc->cipher_algo, &enc->s2k, 0 );
    }
    free_packet(pkt);
}

static void
proc_pubkey_enc( CTX c, PACKET *pkt )
{
    PKT_pubkey_enc *enc;
    int result = 0;

    /* check whether the secret key is available and store in this case */
    c->last_was_session_key = 1;
    enc = pkt->pkt.pubkey_enc;
    /*printf("enc: encrypted by a pubkey with keyid %08lX\n", enc->keyid[1] );*/
    /* Hmmm: why do I have this algo check here - anyway there is
     * function to check it. */
    if( opt.verbose )
	log_info(_("public key is %08lX\n"), (ulong)enc->keyid[1] );

    if( is_status_enabled() ) {
	char buf[50];
	sprintf(buf, "%08lX%08lX %d 0",
		(ulong)enc->keyid[0], (ulong)enc->keyid[1], enc->pubkey_algo );
	write_status_text( STATUS_ENC_TO, buf );
    }

    if( !opt.list_only && opt.override_session_key ) {
	/* It does not make nuch sense to store the session key in
	 * secure memory because it has already been passed on the
	 * command line and the GCHQ knows about it */
	c->dek = m_alloc( sizeof *c->dek );
	result = get_override_session_key ( c->dek, opt.override_session_key );
	if ( result ) {
	    m_free(c->dek); c->dek = NULL;
	}
    }
    else if( is_ELGAMAL(enc->pubkey_algo)
	|| enc->pubkey_algo == PUBKEY_ALGO_DSA
	|| is_RSA(enc->pubkey_algo)  ) {
	if ( !c->dek && ((!enc->keyid[0] && !enc->keyid[1])
			  || !seckey_available( enc->keyid )) ) {
	    if( opt.list_only )
		result = -1;
	    else {
		c->dek = m_alloc_secure( sizeof *c->dek );
		if( (result = get_session_key( enc, c->dek )) ) {
		    /* error: delete the DEK */
		    m_free(c->dek); c->dek = NULL;
		}
	    }
	}
	else
	    result = G10ERR_NO_SECKEY;
    }
    else
	result = G10ERR_PUBKEY_ALGO;

    if( result == -1 )
	;
    else if( !result ) {
	if( opt.verbose > 1 )
	    log_info( _("public key encrypted data: good DEK\n") );
	if ( opt.show_session_key ) {
	    int i;
	    char *buf = m_alloc ( c->dek->keylen*2 + 20 );
	    sprintf ( buf, "%d:", c->dek->algo );
	    for(i=0; i < c->dek->keylen; i++ )
		sprintf(buf+strlen(buf), "%02X", c->dek->key[i] );
	    log_info( "session key: \"%s\"\n", buf );
	    write_status_text ( STATUS_SESSION_KEY, buf );
	}
    }
    else { /* store it for later display */
	struct kidlist_item *x = m_alloc( sizeof *x );
	x->kid[0] = enc->keyid[0];
	x->kid[1] = enc->keyid[1];
	x->pubkey_algo = enc->pubkey_algo;
	x->reason = result;
	x->next = c->failed_pkenc;
	c->failed_pkenc = x;
    }
    free_packet(pkt);
}



/****************
 * Print the list of public key encrypted packets which we could
 * not decrypt.
 */
static void
print_failed_pkenc( struct kidlist_item *list )
{
    for( ; list; list = list->next ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	const char *algstr = pubkey_algo_to_string( list->pubkey_algo );

	if( !algstr )
	    algstr = "[?]";
	pk->pubkey_algo = list->pubkey_algo;
	if( !get_pubkey( pk, list->kid ) ) {
	    size_t n;
	    char *p;
	    log_info( _("encrypted with %u-bit %s key, ID %08lX, created %s\n"),
		       nbits_from_pk( pk ), algstr, (ulong)list->kid[1],
		       strtimestamp(pk->timestamp) );
	    fputs("      \"", log_stream() );
	    p = get_user_id( list->kid, &n );
	    print_string( log_stream(), p, n, '"' );
	    m_free(p);
	    fputs("\"\n", log_stream() );
	}
	else {
	    log_info(_("encrypted with %s key, ID %08lX\n"),
			algstr, (ulong) list->kid[1] );
	}
	free_public_key( pk );

	if( list->reason == G10ERR_NO_SECKEY ) {
	    log_info(_("no secret key for decryption available\n"));
	    if( is_status_enabled() ) {
		char buf[20];
		sprintf(buf,"%08lX%08lX", (ulong)list->kid[0],
					  (ulong)list->kid[1] );
		write_status_text( STATUS_NO_SECKEY, buf );
	    }
	}
	else
	    log_error(_("public key decryption failed: %s\n"),
						g10_errstr(list->reason));
    }
}


static void
proc_encrypted( CTX c, PACKET *pkt )
{
    int result = 0;

    print_failed_pkenc( c->failed_pkenc );

    write_status( STATUS_BEGIN_DECRYPTION );

    /*log_debug("dat: %sencrypted data\n", c->dek?"":"conventional ");*/
    if( opt.list_only )
	result = -1;
    else if( !c->dek && !c->last_was_session_key ) {
	/* assume this is old conventional encrypted data
	 * Actually we should use IDEA and MD5 in this case, but because
	 * IDEA is patented we can't do so */
	c->dek = passphrase_to_dek( NULL, 0,
		    opt.def_cipher_algo ? opt.def_cipher_algo
					: DEFAULT_CIPHER_ALGO, NULL, 0 );
    }
    else if( !c->dek )
	result = G10ERR_NO_SECKEY;
    if( !result )
	result = decrypt_data( c, pkt->pkt.encrypted, c->dek );

    m_free(c->dek); c->dek = NULL;
    if( result == -1 )
	;
    else if( !result ) {
	write_status( STATUS_DECRYPTION_OKAY );
	if( opt.verbose > 1 )
	    log_info(_("decryption okay\n"));
	if( pkt->pkt.encrypted->mdc_method )
	    write_status( STATUS_GOODMDC );
    }
    else if( result == G10ERR_BAD_SIGN ) {
	log_error(_("WARNING: encrypted message has been manipulated!\n"));
	write_status( STATUS_BADMDC );
    }
    else {
	write_status( STATUS_DECRYPTION_FAILED );
	log_error(_("decryption failed: %s\n"), g10_errstr(result));
	/* Hmmm: does this work when we have encrypted using multiple
	 * ways to specify the session key (symmmetric and PK)*/
    }
    free_packet(pkt);
    c->last_was_session_key = 0;
    write_status( STATUS_END_DECRYPTION );
}



static void
proc_plaintext( CTX c, PACKET *pkt )
{
    PKT_plaintext *pt = pkt->pkt.plaintext;
    int any, clearsig, only_md5, rc;
    KBNODE n;

    if( pt->namelen == 8 && !memcmp( pt->name, "_CONSOLE", 8 ) )
	log_info(_("NOTE: sender requested \"for-your-eyes-only\"\n"));
    else if( opt.verbose )
	log_info(_("original file name='%.*s'\n"), pt->namelen, pt->name);
    free_md_filter_context( &c->mfx );
    c->mfx.md = md_open( 0, 0);
    /* fixme: we may need to push the textfilter if we have sigclass 1
     * and no armoring - Not yet tested
     * Hmmm, why don't we need it at all if we have sigclass 1
     * Should we assume that plaintext in mode 't' has always sigclass 1??
     * See: Russ Allbery's mail 1999-02-09
     */
    any = clearsig = only_md5 = 0;
    for(n=c->list; n; n = n->next ) {
	if( n->pkt->pkttype == PKT_ONEPASS_SIG ) {
	    if( n->pkt->pkt.onepass_sig->digest_algo ) {
		md_enable( c->mfx.md, n->pkt->pkt.onepass_sig->digest_algo );
		if( !any && n->pkt->pkt.onepass_sig->digest_algo
						      == DIGEST_ALGO_MD5 )
		    only_md5 = 1;
		else
		    only_md5 = 0;
		any = 1;
	    }
	    if( n->pkt->pkt.onepass_sig->sig_class != 0x01 )
		only_md5 = 0;

	    /* Check whether this is a cleartext signature.  We assume that
	     * we have one if the sig_class is 1 and the keyid is 0, that
	     * are the faked packets produced by armor.c.  There is a
	     * possibility that this fails, but there is no other easy way
	     * to do it. (We could use a special packet type to indicate
	     * this, but this may also be faked - it simply can't be verified
	     * and is _no_ security issue)
	     */
	    if( n->pkt->pkt.onepass_sig->sig_class == 0x01
		&& !n->pkt->pkt.onepass_sig->keyid[0]
		&& !n->pkt->pkt.onepass_sig->keyid[1] )
		clearsig = 1;
	}
    }

    if( !any && !opt.skip_verify ) {
	/* no onepass sig packet: enable all standard algos */
	md_enable( c->mfx.md, DIGEST_ALGO_RMD160 );
	md_enable( c->mfx.md, DIGEST_ALGO_SHA1 );
	md_enable( c->mfx.md, DIGEST_ALGO_MD5 );
    }
    if( opt.pgp2_workarounds && only_md5 && !opt.skip_verify ) {
	/* This is a kludge to work around a bug in pgp2.  It does only
	 * catch those mails which are armored.  To catch the non-armored
	 * pgp mails we could see whether there is the signature packet
	 * in front of the plaintext.  If someone needs this, send me a patch.
	 */
	c->mfx.md2 = md_open( DIGEST_ALGO_MD5, 0);
    }
    if ( DBG_HASHING ) {
	md_start_debug( c->mfx.md, "verify" );
	if ( c->mfx.md2  )
	    md_start_debug( c->mfx.md2, "verify2" );
    }
    rc = handle_plaintext( pt, &c->mfx, c->sigs_only, clearsig );
    if( rc == G10ERR_CREATE_FILE && !c->sigs_only) {
	/* can't write output but we hash it anyway to
	 * check the signature */
	rc = handle_plaintext( pt, &c->mfx, 1, clearsig );
    }
    if( rc )
	log_error( "handle plaintext failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_session_key = 0;
}


static int
proc_compressed_cb( IOBUF a, void *info )
{
    return proc_signature_packets( info, a, ((CTX)info)->signed_data,
					    ((CTX)info)->sigfilename );
}

static int
proc_encrypt_cb( IOBUF a, void *info )
{
    return proc_encryption_packets( info, a );
}

static void
proc_compressed( CTX c, PACKET *pkt )
{
    PKT_compressed *zd = pkt->pkt.compressed;
    int rc;

    /*printf("zip: compressed data packet\n");*/
    if( c->sigs_only )
	rc = handle_compressed( c, zd, proc_compressed_cb, c );
    else if( c->encrypt_only )
	rc = handle_compressed( c, zd, proc_encrypt_cb, c );
    else
	rc = handle_compressed( c, zd, NULL, NULL );
    if( rc )
	log_error("uncompressing failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_session_key = 0;
}

/****************
 * check the signature
 * Returns: 0 = valid signature or an error code
 */
static int
do_check_sig( CTX c, KBNODE node, int *is_selfsig )
{
    PKT_signature *sig;
    MD_HANDLE md = NULL, md2 = NULL;
    int algo, rc;

    assert( node->pkt->pkttype == PKT_SIGNATURE );
    if( is_selfsig )
	*is_selfsig = 0;
    sig = node->pkt->pkt.signature;

    algo = sig->digest_algo;
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
	if( c->mfx.md ) {
	    md = md_copy( c->mfx.md );
	    if( c->mfx.md2 )
	       md2 = md_copy( c->mfx.md2 );
	}
	else { /* detached signature */
	  log_debug("Do we really need this here?");
	    md = md_open( 0, 0 ); /* signature_check() will enable the md*/
	    md2 = md_open( 0, 0 );
	}
    }
    else if( (sig->sig_class&~3) == 0x10
	     || sig->sig_class == 0x18
	     || sig->sig_class == 0x20
	     || sig->sig_class == 0x30	) { /* classes 0x10..0x17,0x20,0x30 */
	if( c->list->pkt->pkttype == PKT_PUBLIC_KEY
	    || c->list->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    return check_key_signature( c->list, node, is_selfsig );
	}
	else if( sig->sig_class == 0x20 ) {
	    log_info(_("standalone revocation - "
		       "use \"gpg --import\" to apply\n"));
	    return G10ERR_NOT_PROCESSED;
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
    if( rc == G10ERR_BAD_SIGN && md2 )
	rc = signature_check( sig, md2 );
    md_close(md);
    md_close(md2);

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
    if( opt.with_colons )
	print_string( stdout,  pkt->pkt.user_id->name,
				pkt->pkt.user_id->len, ':');
    else
	print_utf8_string( stdout,  pkt->pkt.user_id->name,
				     pkt->pkt.user_id->len );
}


static void
print_fingerprint( PKT_public_key *pk, PKT_secret_key *sk )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    size_t i, n;

    if( sk )
	fingerprint_from_sk( sk, array, &n );
    else
	fingerprint_from_pk( pk, array, &n );
    p = array;
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
}

static void
print_notation_data( PKT_signature *sig )
{
    size_t n, n1, n2;
    const byte *p;
    int seq = 0;

    while( (p = enum_sig_subpkt( sig->hashed_data, SIGSUBPKT_NOTATION,
				 &n, &seq )) ) {
	if( n < 8 ) {
	    log_info(_("WARNING: invalid notation data found\n"));
	    return;
	}
	if( !(*p & 0x80) )
	    return; /* not human readable */
	n1 = (p[4] << 8) | p[5];
	n2 = (p[6] << 8) | p[7];
	p += 8;
	if( 8+n1+n2 != n ) {
	    log_info(_("WARNING: invalid notation data found\n"));
	    return;
	}
	log_info(_("Notation: ") );
	print_string( log_stream(), p, n1, 0 );
	putc( '=', log_stream() );
	print_string( log_stream(), p+n1, n2, 0 );
	putc( '\n', log_stream() );
    }
    if( (p = parse_sig_subpkt( sig->hashed_data, SIGSUBPKT_POLICY, &n ) )) {
	log_info(_("Policy: ") );
	print_string( log_stream(), p, n, 0 );
	putc( '\n', log_stream() );
    }

    /* Now check wheter the key of this signature has some
     * notation data */

    /* TODO */
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
    else if( (mainkey = (node->pkt->pkttype == PKT_PUBLIC_KEY) )
	     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	PKT_public_key *pk = node->pkt->pkt.public_key;

	if( opt.with_colons ) {
	    u32 keyid[2];
	    keyid_from_pk( pk, keyid );
	    if( mainkey ) {
		c->local_id = pk->local_id;
		c->trustletter = opt.fast_list_mode?
					   0 : query_trust_info( pk, NULL );
	    }
	    printf("%s:", mainkey? "pub":"sub" );
	    if( c->trustletter )
		putchar( c->trustletter );
	    printf(":%u:%d:%08lX%08lX:%s:%s:",
		    nbits_from_pk( pk ),
		    pk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_pk( pk ),
		    pk->expiredate? strtimestamp(pk->expiredate):"" );
	    if( c->local_id )
		printf("%lu", c->local_id );
	    putchar(':');
	    if( c->local_id && !opt.fast_list_mode )
		putchar( get_ownertrust_info( c->local_id ) );
	    putchar(':');
	    if( node->next && node->next->pkt->pkttype == PKT_RING_TRUST) {
		putchar('\n'); any=1;
		if( opt.fingerprint )
		    print_fingerprint( pk, NULL );
		printf("rtv:1:%u:\n",
			    node->next->pkt->pkt.ring_trust->trustval );
	    }
	}
	else
	    printf("%s  %4u%c/%08lX %s ",
				      mainkey? "pub":"sub",
				      nbits_from_pk( pk ),
				      pubkey_letter( pk->pubkey_algo ),
				      (ulong)keyid_from_pk( pk, NULL ),
				      datestr_from_pk( pk )	);

	if( mainkey ) {
	    /* and now list all userids with their signatures */
	    for( node = node->next; node; node = node->next ) {
		if( node->pkt->pkttype == PKT_SIGNATURE ) {
		    if( !any ) {
			if( node->pkt->pkt.signature->sig_class == 0x20 )
			    puts("[revoked]");
			else
			    putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
		else if( node->pkt->pkttype == PKT_USER_ID ) {
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
			print_fingerprint( pk, NULL );
		    if( node->next
			&& node->next->pkt->pkttype == PKT_RING_TRUST ) {
			printf("rtv:2:%u:\n",
				 node->next->pkt->pkt.ring_trust->trustval );
		    }
		    any=1;
		}
		else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
		    if( !any ) {
			putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
	    }
	}
	else if( pk->expiredate ) { /* of subkey */
	    printf(_(" [expires: %s]"), expirestr_from_pk( pk ) );
	}

	if( !any )
	    putchar('\n');
	if( !mainkey && opt.fingerprint > 1 )
	    print_fingerprint( pk, NULL );
    }
    else if( (mainkey = (node->pkt->pkttype == PKT_SECRET_KEY) )
	     || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	PKT_secret_key *sk = node->pkt->pkt.secret_key;

	if( opt.with_colons ) {
	    u32 keyid[2];
	    keyid_from_sk( sk, keyid );
	    printf("%s::%u:%d:%08lX%08lX:%s:%s:::",
		    mainkey? "sec":"ssb",
		    nbits_from_sk( sk ),
		    sk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_sk( sk ),
		    sk->expiredate? strtimestamp(sk->expiredate):""
		    /* fixme: add LID */ );
	}
	else
	    printf("%s  %4u%c/%08lX %s ",
				      mainkey? "sec":"ssb",
				      nbits_from_sk( sk ),
				      pubkey_letter( sk->pubkey_algo ),
				      (ulong)keyid_from_sk( sk, NULL ),
				      datestr_from_sk( sk )   );
	if( mainkey ) {
	    /* and now list all userids with their signatures */
	    for( node = node->next; node; node = node->next ) {
		if( node->pkt->pkttype == PKT_SIGNATURE ) {
		    if( !any ) {
			if( node->pkt->pkt.signature->sig_class == 0x20 )
			    puts("[revoked]");
			else
			    putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
		else if( node->pkt->pkttype == PKT_USER_ID ) {
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
			print_fingerprint( NULL, sk );
		    any=1;
		}
		else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
		    if( !any ) {
			putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
	    }
	}
	if( !any )
	    putchar('\n');
	if( !mainkey && opt.fingerprint > 1 )
	    print_fingerprint( NULL, sk );
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE  ) {
	PKT_signature *sig = node->pkt->pkt.signature;
	int is_selfsig = 0;
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
	    switch( (rc2=do_check_sig( c, node, &is_selfsig )) ) {
	      case 0:		       sigrc = '!'; break;
	      case G10ERR_BAD_SIGN:    sigrc = '-'; break;
	      case G10ERR_NO_PUBKEY:   sigrc = '?'; break;
	      default:		       sigrc = '%'; break;
	    }
	}
	else {	/* check whether this is a self signature */
	    u32 keyid[2];

	    if( c->list->pkt->pkttype == PKT_PUBLIC_KEY
		|| c->list->pkt->pkttype == PKT_SECRET_KEY ) {
		if( c->list->pkt->pkttype == PKT_PUBLIC_KEY )
		    keyid_from_pk( c->list->pkt->pkt.public_key, keyid );
		else
		    keyid_from_sk( c->list->pkt->pkt.secret_key, keyid );

		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    is_selfsig = 1;
	    }
	}
	if( opt.with_colons ) {
	    putchar(':');
	    if( sigrc != ' ' )
		putchar(sigrc);
	    printf("::%d:%08lX%08lX:%s::::", sig->pubkey_algo,
					     (ulong)sig->keyid[0],
		       (ulong)sig->keyid[1], datestr_from_sig(sig));
	}
	else
	    printf("%c       %08lX %s   ",
		    sigrc, (ulong)sig->keyid[1], datestr_from_sig(sig));
	if( sigrc == '%' )
	    printf("[%s] ", g10_errstr(rc2) );
	else if( sigrc == '?' )
	    ;
	else if( is_selfsig ) {
	    if( opt.with_colons )
		putchar(':');
	    fputs( sig->sig_class == 0x18? "[keybind]":"[selfsig]", stdout);
	    if( opt.with_colons )
		putchar(':');
	}
	else if( !opt.fast_list_mode ) {
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
proc_packets( void *anchor, IOBUF a )
{
    int rc;
    CTX c = m_alloc_clear( sizeof *c );

    c->anchor = anchor;
    rc = do_proc_packets( c, a );
    m_free( c );
    return rc;
}



int
proc_signature_packets( void *anchor, IOBUF a,
			STRLIST signedfiles, const char *sigfilename )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;

    c->anchor = anchor;
    c->sigs_only = 1;
    c->signed_data = signedfiles;
    c->sigfilename = sigfilename;
    rc = do_proc_packets( c, a );
    m_free( c );
    return rc;
}

int
proc_encryption_packets( void *anchor, IOBUF a )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;

    c->anchor = anchor;
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
    int any_data=0;
    int newpkt;

    c->iobuf = a;
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	any_data = 1;
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
	      case PKT_SYMKEY_ENC:  proc_symkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC: proc_encrypted( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	else if( c->sigs_only ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
	      case PKT_USER_ID:
	      case PKT_SYMKEY_ENC:
	      case PKT_PUBKEY_ENC:
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC:
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
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
	      case PKT_USER_ID:
		rc = G10ERR_UNEXPECTED;
		goto leave;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_SYMKEY_ENC:  proc_symkey_enc( c, pkt ); break;
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC: proc_encrypted( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	else {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
		release_list( c );
		c->list = new_kbnode( pkt );
		newpkt = 1;
		break;
	      case PKT_PUBLIC_SUBKEY:
	      case PKT_SECRET_SUBKEY:
		newpkt = add_subkey( c, pkt );
		break;
	      case PKT_USER_ID:     newpkt = add_user_id( c, pkt ); break;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_SYMKEY_ENC:  proc_symkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC: proc_encrypted( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	      case PKT_RING_TRUST:  newpkt = add_ring_trust( c, pkt ); break;
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
    if( rc == G10ERR_INVALID_PACKET )
	write_status_text( STATUS_NODATA, "3" );
    if( any_data )
	rc = 0;
    else if( rc == -1 )
	write_status_text( STATUS_NODATA, "2" );


  leave:
    release_list( c );
    m_free(c->dek);
    free_packet( pkt );
    m_free( pkt );
    free_md_filter_context( &c->mfx );
    return rc;
}


static int
check_sig_and_print( CTX c, KBNODE node )
{
    PKT_signature *sig = node->pkt->pkt.signature;
    const char *astr, *tstr;
    int rc;

    if( opt.skip_verify ) {
	log_info(_("signature verification suppressed\n"));
	return 0;
    }

    tstr = asctimestamp(sig->timestamp);
    astr = pubkey_algo_to_string( sig->pubkey_algo );
    log_info(_("Signature made %.*s using %s key ID %08lX\n"),
	    (int)strlen(tstr), tstr, astr? astr: "?", (ulong)sig->keyid[1] );

    rc = do_check_sig(c, node, NULL );
    if( rc == G10ERR_NO_PUBKEY && opt.keyserver_name && opt.auto_key_retrieve) {
	if( !hkp_ask_import( sig->keyid ) )
	    rc = do_check_sig(c, node, NULL );
    }
    if( !rc || rc == G10ERR_BAD_SIGN ) {
	KBNODE un, keyblock;
	char *us;
	int count=0;

	keyblock = get_pubkeyblock( sig->keyid );

	us = get_long_user_id_string( sig->keyid );
	write_status_text( rc? STATUS_BADSIG : STATUS_GOODSIG, us );
	m_free(us);

	/* fixme: list only user ids which are valid and add information
	 *	  about the trustworthiness of each user id, sort them.
	 *	  Integrate this with check_signatures_trust(). */
	for( un=keyblock; un; un = un->next ) {
	    if( un->pkt->pkttype != PKT_USER_ID )
		continue;
	    if( !count++ )
		log_info(rc? _("BAD signature from \"")
			   : _("Good signature from \""));
	    else
		log_info(    _("                aka \""));
	    print_utf8_string( log_stream(), un->pkt->pkt.user_id->name,
					     un->pkt->pkt.user_id->len );
	    fputs("\"\n", log_stream() );
	    if( rc )
		break; /* print only one id in this case */
	}
	if( !count ) {	/* just in case that we have no userid */
	    log_info(rc? _("BAD signature from \"")
		       : _("Good signature from \""));
	    fputs("[?]\"\n", log_stream() );
	}
	release_kbnode( keyblock );
	if( !rc )
	    print_notation_data( sig );

	if( !rc && is_status_enabled() ) {
	    /* print a status response with the fingerprint */
	    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

	    if( !get_pubkey( pk, sig->keyid ) ) {
		byte array[MAX_FINGERPRINT_LEN], *p;
		char buf[MAX_FINGERPRINT_LEN*2+61];
		size_t i, n;

		fingerprint_from_pk( pk, array, &n );
		p = array;
		for(i=0; i < n ; i++, p++ )
		    sprintf(buf+2*i, "%02X", *p );
		sprintf(buf+strlen(buf), " %s %lu",
					 strtimestamp( sig->timestamp ),
					 (ulong)sig->timestamp );
		write_status_text( STATUS_VALIDSIG, buf );
	    }
	    free_public_key( pk );
	}

	if( !rc )
	    rc = check_signatures_trust( sig );
	if( rc )
	    g10_errors_seen = 1;
	if( opt.batch && rc )
	    g10_exit(1);
    }
    else {
	char buf[50];
	sprintf(buf, "%08lX%08lX %d %d %02x %lu %d",
		     (ulong)sig->keyid[0], (ulong)sig->keyid[1],
		     sig->pubkey_algo, sig->digest_algo,
		     sig->sig_class, (ulong)sig->timestamp, rc );
	write_status_text( STATUS_ERRSIG, buf );
	if( rc == G10ERR_NO_PUBKEY ) {
	    buf[16] = 0;
	    write_status_text( STATUS_NO_PUBKEY, buf );
	}
	if( rc != G10ERR_NOT_PROCESSED )
	    log_error(_("Can't check signature: %s\n"), g10_errstr(rc) );
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

    if( opt.list_packets || opt.list_only )
	return;

    c->local_id = 0;
    c->trustletter = ' ';
    if( node->pkt->pkttype == PKT_PUBLIC_KEY
	|| node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	merge_keys_and_selfsig( node );
	list_node( c, node );
    }
    else if( node->pkt->pkttype == PKT_SECRET_KEY ) {
	merge_keys_and_selfsig( node );
	list_node( c, node );
    }
    else if( node->pkt->pkttype == PKT_ONEPASS_SIG ) {
	/* check all signatures */
	if( !c->have_data ) {
	    free_md_filter_context( &c->mfx );
	    /* prepare to create all requested message digests */
	    c->mfx.md = md_open(0, 0);

	    /* fixme: why looking for the signature packet and not 1passpacket*/
	    for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); ) {
		md_enable( c->mfx.md, n1->pkt->pkt.signature->digest_algo);
	    }
	    /* ask for file and hash it */
	    if( c->sigs_only ) {
		rc = hash_datafiles( c->mfx.md, NULL,
				     c->signed_data, c->sigfilename,
			n1? (n1->pkt->pkt.onepass_sig->sig_class == 0x01):0 );
	    }
	    else {
		rc = ask_for_detached_datafile( c->mfx.md, c->mfx.md2,
						iobuf_get_fname(c->iobuf),
			n1? (n1->pkt->pkt.onepass_sig->sig_class == 0x01):0 );
	    }
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

	if( sig->sig_class != 0x00 && sig->sig_class != 0x01 )
	    log_info(_("standalone signature of class 0x%02x\n"),
						    sig->sig_class);
	else if( !c->have_data ) {
	    /* detached signature */
	    free_md_filter_context( &c->mfx );
	    c->mfx.md = md_open(sig->digest_algo, 0);
	    if( !opt.pgp2_workarounds )
		;
	    else if( sig->digest_algo == DIGEST_ALGO_MD5
		     && is_RSA( sig->pubkey_algo ) ) {
		/* enable a workaround for a pgp2 bug */
		c->mfx.md2 = md_open( DIGEST_ALGO_MD5, 0 );
	    }
	    else if( sig->digest_algo == DIGEST_ALGO_SHA1
		     && sig->pubkey_algo == PUBKEY_ALGO_DSA
		     && sig->sig_class == 0x01 ) {
		/* enable the workaround also for pgp5 when the detached
		 * signature has been created in textmode */
		c->mfx.md2 = md_open( sig->digest_algo, 0 );
	    }
	  #if 0 /* workaround disabled */
	    /* Here we have another hack to work around a pgp 2 bug
	     * It works by not using the textmode for detached signatures;
	     * this will let the first signature check (on md) fail
	     * but the second one (on md2) which adds an extra CR should
	     * then produce the "correct" hash.  This is very, very ugly
	     * hack but it may help in some cases (and break others)
	     */
		    /*	c->mfx.md2? 0 :(sig->sig_class == 0x01) */
	  #endif
	    if( c->sigs_only ) {
		rc = hash_datafiles( c->mfx.md, c->mfx.md2,
				     c->signed_data, c->sigfilename,
				     (sig->sig_class == 0x01) );
	    }
	    else {
		rc = ask_for_detached_datafile( c->mfx.md, c->mfx.md2,
						iobuf_get_fname(c->iobuf),
						(sig->sig_class == 0x01) );
	    }
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return;
	    }
	}
	else
	    log_info(_("old style (PGP 2.x) signature\n"));

	check_sig_and_print( c, node );
    }
    else
	log_error(_("invalid root packet detected in proc_tree()\n"));

}



