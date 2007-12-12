/* mainproc.c - handle packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include "keyserver-internal.h"
#include "photoid.h"


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
struct mainproc_context
{
  struct mainproc_context *anchor;  /* May be useful in the future. */
  PKT_public_key *last_pubkey;
  PKT_secret_key *last_seckey;
  PKT_user_id     *last_user_id;
  md_filter_context_t mfx;
  int sigs_only;    /* Process only signatures and reject all other stuff. */
  int encrypt_only; /* Process only encryption messages. */
  STRLIST signed_data;
  const char *sigfilename;
  DEK *dek;
  int last_was_session_key;
  KBNODE list;      /* The current list of packets. */
  int have_data;
  IOBUF iobuf;      /* Used to get the filename etc. */
  int trustletter;  /* Temporary usage in list_node. */
  ulong symkeys;
  struct kidlist_item *pkenc_list; /* List of encryption packets. */
  struct 
  {
    int op;
    int stop_now;
  } pipemode;
  int any_sig_seen;  /* Set to true if a signature packet has been seen. */
};


static int do_proc_packets( CTX c, IOBUF a );
static void list_node( CTX c, KBNODE node );
static void proc_tree( CTX c, KBNODE node );
static int literals_seen;

void
reset_literals_seen(void)
{
  literals_seen=0;
}

static void
release_list( CTX c )
{
    if( !c->list )
	return;
    proc_tree(c, c->list );
    release_kbnode( c->list );
    while( c->pkenc_list ) {
	struct kidlist_item *tmp = c->pkenc_list->next;
	xfree( c->pkenc_list );
	c->pkenc_list = tmp;
    }
    c->pkenc_list = NULL;
    c->list = NULL;
    c->have_data = 0;
    c->last_was_session_key = 0;
    c->pipemode.op = 0;
    c->pipemode.stop_now = 0;
    xfree(c->dek); c->dek = NULL;
}


static int
add_onepass_sig( CTX c, PACKET *pkt )
{
  KBNODE node;

  if ( c->list ) /* add another packet */
    add_kbnode( c->list, new_kbnode( pkt ));
  else /* insert the first one */
    c->list = node = new_kbnode( pkt );

  return 1;
}


static int
add_gpg_control( CTX c, PACKET *pkt )
{
    if ( pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START ) {
        /* New clear text signature.
         * Process the last one and reset everything */
        release_list(c);
    }   
    else if ( pkt->pkt.gpg_control->control == CTRLPKT_PIPEMODE ) {
        /* Pipemode control packet */
        if ( pkt->pkt.gpg_control->datalen < 2 ) 
            log_fatal ("invalid pipemode control packet length\n");
        if (pkt->pkt.gpg_control->data[0] == 1) {
            /* start the whole thing */
            assert ( !c->list ); /* we should be in a pretty virgin state */
            assert ( !c->pipemode.op );
            c->pipemode.op = pkt->pkt.gpg_control->data[1];
        }
        else if (pkt->pkt.gpg_control->data[0] == 2) {
            /* the signed material follows in a plaintext packet */
            assert ( c->pipemode.op == 'B' );
        }
        else if (pkt->pkt.gpg_control->data[0] == 3) {
            assert ( c->pipemode.op == 'B' );
            release_list (c);
            /* and tell the outer loop to terminate */
            c->pipemode.stop_now = 1;
        }
        else 
            log_fatal ("invalid pipemode control packet code\n");
        return 0; /* no need to store the packet */
    }   

    if( c->list )  /* add another packet */
        add_kbnode( c->list, new_kbnode( pkt ));
    else /* insert the first one */
	c->list = new_kbnode( pkt );

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

    c->any_sig_seen = 1;
    if( pkt->pkttype == PKT_SIGNATURE && !c->list ) {
	/* This is the first signature for the following datafile.
	 * GPG does not write such packets; instead it always uses
	 * onepass-sig packets.  The drawback of PGP's method
	 * of prepending the signature to the data is
	 * that it is not possible to make a signature from data read
	 * from stdin.	(GPG is able to read PGP stuff anyway.) */
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

static int
symkey_decrypt_seskey( DEK *dek, byte *seskey, size_t slen )
{
  CIPHER_HANDLE hd;

  if(slen < 17 || slen > 33)
    {
      log_error ( _("weird size for an encrypted session key (%d)\n"),
		  (int)slen);
      return G10ERR_BAD_KEY;
    }

  hd = cipher_open( dek->algo, CIPHER_MODE_CFB, 1 );
  cipher_setkey( hd, dek->key, dek->keylen );
  cipher_setiv( hd, NULL, 0 );
  cipher_decrypt( hd, seskey, seskey, slen );
  cipher_close( hd );

  /* now we replace the dek components with the real session key to
     decrypt the contents of the sequencing packet. */

  dek->keylen=slen-1;
  dek->algo=seskey[0];

  if(dek->keylen > DIM(dek->key))
    BUG ();

  /* This is not completely accurate, since a bad passphrase may have
     resulted in a garbage algorithm byte, but it's close enough since
     a bogus byte here will fail later. */
  if(dek->algo==CIPHER_ALGO_IDEA)
    idea_cipher_warn(0);

  memcpy(dek->key, seskey + 1, dek->keylen);

  /*log_hexdump( "thekey", dek->key, dek->keylen );*/

  return 0;
}   

static void
proc_symkey_enc( CTX c, PACKET *pkt )
{
    PKT_symkey_enc *enc;

    enc = pkt->pkt.symkey_enc;
    if (!enc)
        log_error ("invalid symkey encrypted packet\n");
    else if(!c->dek)
      {
        int algo = enc->cipher_algo;
	const char *s = cipher_algo_to_string (algo);

	if(s)
	  {
	    if(!opt.quiet)
	      {
		if(enc->seskeylen)
		  log_info(_("%s encrypted session key\n"), s );
		else
		  log_info(_("%s encrypted data\n"), s );
	      }
	  }
	else
	  log_error(_("encrypted with unknown algorithm %d\n"), algo );

	if(check_digest_algo(enc->s2k.hash_algo))
	  {
	    log_error(_("passphrase generated with unknown digest"
			" algorithm %d\n"),enc->s2k.hash_algo);
	    s=NULL;
	  }

	c->last_was_session_key = 2;
	if(!s || opt.list_only)
	  goto leave;

	if(opt.override_session_key)
	  {
	    c->dek = xmalloc_clear( sizeof *c->dek );
	    if(get_override_session_key(c->dek, opt.override_session_key))
	      {
		xfree(c->dek);
		c->dek = NULL;
	      }
	  }
	else
	  {
            int canceled;

	    c->dek = passphrase_to_dek (NULL, 0, algo, &enc->s2k, 0,
                                        NULL, &canceled);
            if (canceled)
              {
                /* For unknown reasons passphrase_to_dek does only
                   return NULL if a new passphrase has been requested
                   and has not been repeated correctly.  Thus even
                   with a cancel requested (by means of the gpg-agent)
                   it won't return NULL but an empty passphrase.  We
                   take the most conservative approach for now and
                   work around it right here. */
                xfree (c->dek);
                c->dek = NULL;
              }

	    if(c->dek)
	      {
		c->dek->symmetric=1;

		/* FIXME: This doesn't work perfectly if a symmetric
		   key comes before a public key in the message - if
		   the user doesn't know the passphrase, then there is
		   a chance that the "decrypted" algorithm will happen
		   to be a valid one, which will make the returned dek
		   appear valid, so we won't try any public keys that
		   come later. */
		if(enc->seskeylen)
		  {
		    if(symkey_decrypt_seskey(c->dek, enc->seskey,
					     enc->seskeylen))
		      {
			xfree(c->dek);
			c->dek=NULL;
		      }
		  }
		else
		  c->dek->algo_info_printed = 1;
	      }
	  }
      }

 leave:
    c->symkeys++;
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
	log_info(_("public key is %s\n"), keystr(enc->keyid) );

    if( is_status_enabled() ) {
	char buf[50];
	sprintf(buf, "%08lX%08lX %d 0",
		(ulong)enc->keyid[0], (ulong)enc->keyid[1], enc->pubkey_algo );
	write_status_text( STATUS_ENC_TO, buf );
    }

    if( !opt.list_only && opt.override_session_key ) {
	/* It does not make much sense to store the session key in
	 * secure memory because it has already been passed on the
	 * command line and the GCHQ knows about it.  */
	c->dek = xmalloc_clear( sizeof *c->dek );
	result = get_override_session_key ( c->dek, opt.override_session_key );
	if ( result ) {
	    xfree(c->dek); c->dek = NULL;
	}
    }
    else if( is_ELGAMAL(enc->pubkey_algo)
             || enc->pubkey_algo == PUBKEY_ALGO_DSA
             || is_RSA(enc->pubkey_algo)  
             || (RFC2440 && enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL)) {
      /* Note that we also allow type 20 Elgamal keys for decryption.
         There are still a couple of those keys in active use as a
         subkey.  */

      /* FIXME: Store this all in a list and process it later so that
         we can prioritize what key to use.  This gives a better user
         experience if wildcard keyids are used.  */

	if ( !c->dek && ((!enc->keyid[0] && !enc->keyid[1])
                          || opt.try_all_secrets
			  || !seckey_available( enc->keyid )) ) {
	    if( opt.list_only )
		result = -1;
	    else {
		c->dek = xmalloc_secure_clear( sizeof *c->dek );
		if( (result = get_session_key( enc, c->dek )) ) {
		    /* error: delete the DEK */
		    xfree(c->dek); c->dek = NULL;
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
    else
      {
        /* store it for later display */
	struct kidlist_item *x = xmalloc( sizeof *x );
	x->kid[0] = enc->keyid[0];
	x->kid[1] = enc->keyid[1];
	x->pubkey_algo = enc->pubkey_algo;
	x->reason = result;
	x->next = c->pkenc_list;
	c->pkenc_list = x;

        if( !result && opt.verbose > 1 )
	  log_info( _("public key encrypted data: good DEK\n") );
      }

    free_packet(pkt);
}



/****************
 * Print the list of public key encrypted packets which we could
 * not decrypt.
 */
static void
print_pkenc_list( struct kidlist_item *list, int failed )
{
    for( ; list; list = list->next ) {
	PKT_public_key *pk;
	const char *algstr;
        
        if ( failed && !list->reason )
            continue;
        if ( !failed && list->reason )
            continue;

        algstr = pubkey_algo_to_string( list->pubkey_algo );
        pk = xmalloc_clear( sizeof *pk );

	if( !algstr )
	    algstr = "[?]";
	pk->pubkey_algo = list->pubkey_algo;
	if( !get_pubkey( pk, list->kid ) )
	  {
	    char *p;
	    log_info( _("encrypted with %u-bit %s key, ID %s, created %s\n"),
		      nbits_from_pk( pk ), algstr, keystr_from_pk(pk),
		      strtimestamp(pk->timestamp) );
	    p=get_user_id_native(list->kid);
	    fprintf(log_stream(),_("      \"%s\"\n"),p);
	    xfree(p);
	  }
	else
	  log_info(_("encrypted with %s key, ID %s\n"),
		   algstr,keystr(list->kid));

	free_public_key( pk );

	if( list->reason == G10ERR_NO_SECKEY ) {
	    if( is_status_enabled() ) {
		char buf[20];
		sprintf(buf,"%08lX%08lX", (ulong)list->kid[0],
					  (ulong)list->kid[1] );
		write_status_text( STATUS_NO_SECKEY, buf );
	    }
	}
	else if (list->reason)
	    log_info(_("public key decryption failed: %s\n"),
						g10_errstr(list->reason));
    }
}


static void
proc_encrypted( CTX c, PACKET *pkt )
{
    int result = 0;

    if (!opt.quiet)
      {
	if(c->symkeys>1)
	  log_info(_("encrypted with %lu passphrases\n"),c->symkeys);
	else if(c->symkeys==1)
	  log_info(_("encrypted with 1 passphrase\n"));
        print_pkenc_list ( c->pkenc_list, 1 );
        print_pkenc_list ( c->pkenc_list, 0 );
      }

    /* FIXME: Figure out the session key by looking at all pkenc packets. */


    write_status( STATUS_BEGIN_DECRYPTION );

    /*log_debug("dat: %sencrypted data\n", c->dek?"":"conventional ");*/
    if( opt.list_only )
	result = -1;
    else if( !c->dek && !c->last_was_session_key ) {
        int algo;
        STRING2KEY s2kbuf, *s2k = NULL;

	if(opt.override_session_key)
	  {
	    c->dek = xmalloc_clear( sizeof *c->dek );
	    result=get_override_session_key(c->dek, opt.override_session_key);
	    if(result)
	      {
		xfree(c->dek);
		c->dek = NULL;
	      }
	  }
	else
	  {
	    /* assume this is old style conventional encrypted data */
	    if ( (algo = opt.def_cipher_algo))
	      log_info (_("assuming %s encrypted data\n"),
                        cipher_algo_to_string(algo));
	    else if ( check_cipher_algo(CIPHER_ALGO_IDEA) )
	      {
		algo = opt.def_cipher_algo;
		if (!algo)
		  algo = opt.s2k_cipher_algo;
		idea_cipher_warn(1);
		log_info (_("IDEA cipher unavailable, "
			    "optimistically attempting to use %s instead\n"),
			  cipher_algo_to_string(algo));
	      }
	    else
	      {
		algo = CIPHER_ALGO_IDEA;
		if (!opt.s2k_digest_algo)
		  {
		    /* If no digest is given we assume MD5 */
		    s2kbuf.mode = 0;
		    s2kbuf.hash_algo = DIGEST_ALGO_MD5;
		    s2k = &s2kbuf;
		  }
		log_info (_("assuming %s encrypted data\n"), "IDEA");
	      }

	    c->dek = passphrase_to_dek ( NULL, 0, algo, s2k, 0, NULL, NULL );
	    if (c->dek)
	      c->dek->algo_info_printed = 1;
	  }
    }
    else if( !c->dek )
	result = G10ERR_NO_SECKEY;
    if( !result )
	result = decrypt_data( c, pkt->pkt.encrypted, c->dek );

    if( result == -1 )
	;
    else if( !result || (result==G10ERR_BAD_SIGN && opt.ignore_mdc_error)) {
	write_status( STATUS_DECRYPTION_OKAY );
	if( opt.verbose > 1 )
	    log_info(_("decryption okay\n"));
	if( pkt->pkt.encrypted->mdc_method && !result )
	    write_status( STATUS_GOODMDC );
	else if(!opt.no_mdc_warn)
	    log_info (_("WARNING: message was not integrity protected\n"));
	if(opt.show_session_key)
	  {
	    int i;
	    char *buf = xmalloc ( c->dek->keylen*2 + 20 );
	    sprintf ( buf, "%d:", c->dek->algo );
	    for(i=0; i < c->dek->keylen; i++ )
	      sprintf(buf+strlen(buf), "%02X", c->dek->key[i] );
	    log_info( "session key: `%s'\n", buf );
	    write_status_text ( STATUS_SESSION_KEY, buf );
	  }
    }
    else if( result == G10ERR_BAD_SIGN ) {
	log_error(_("WARNING: encrypted message has been manipulated!\n"));
	write_status( STATUS_BADMDC );
	write_status( STATUS_DECRYPTION_FAILED );
    }
    else {
	write_status( STATUS_DECRYPTION_FAILED );
	log_error(_("decryption failed: %s\n"), g10_errstr(result));
	/* Hmmm: does this work when we have encrypted using multiple
	 * ways to specify the session key (symmmetric and PK)*/
    }
    xfree(c->dek); c->dek = NULL;
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

    literals_seen++;

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
    for(n=c->list; n; n = n->next )
      {
	if( n->pkt->pkttype == PKT_ONEPASS_SIG )
	  {
  	    /* For the onepass signature case */
	    if( n->pkt->pkt.onepass_sig->digest_algo )
	      {
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
	  }
	else if( n->pkt->pkttype == PKT_GPG_CONTROL
                 && n->pkt->pkt.gpg_control->control
		 == CTRLPKT_CLEARSIGN_START )
	  {
	    /* For the clearsigned message case */
            size_t datalen = n->pkt->pkt.gpg_control->datalen;
            const byte *data = n->pkt->pkt.gpg_control->data;

            /* check that we have at least the sigclass and one hash */
            if ( datalen < 2 )
	      log_fatal("invalid control packet CTRLPKT_CLEARSIGN_START\n"); 
            /* Note that we don't set the clearsig flag for not-dash-escaped
             * documents */
            clearsig = (*data == 0x01);
            for( data++, datalen--; datalen; datalen--, data++ )
	      md_enable( c->mfx.md, *data );
            any = 1;
            break;  /* Stop here as one-pass signature packets are not
                       expected.  */
	  }
	else if(n->pkt->pkttype==PKT_SIGNATURE)
	  {
	    /* For the SIG+LITERAL case that PGP used to use. */
	    md_enable( c->mfx.md, n->pkt->pkt.signature->digest_algo );
	    any=1;
	  }
      }

    if( !any && !opt.skip_verify )
      {
	/* This is for the old GPG LITERAL+SIG case.  It's not legal
	   according to 2440, so hopefully it won't come up that
	   often.  There is no good way to specify what algorithms to
	   use in that case, so these three are the historical
	   answer. */
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

    rc=0;

    if(literals_seen>1)
      {
	log_info(_("WARNING: multiple plaintexts seen\n"));

	if(!opt.flags.allow_multiple_messages)
	  {
            write_status_text (STATUS_ERROR, "proc_pkt.plaintext 89_BAD_DATA");
	    log_inc_errorcount();
	    rc=G10ERR_UNEXPECTED;
	  }
      }

    if(!rc)
      {
	if ( c->pipemode.op == 'B' )
	  rc = handle_plaintext( pt, &c->mfx, 1, 0 );
	else
	  {
	    rc = handle_plaintext( pt, &c->mfx, c->sigs_only, clearsig );
	    if( rc == G10ERR_CREATE_FILE && !c->sigs_only)
	      {
		/* can't write output but we hash it anyway to
		 * check the signature */
		rc = handle_plaintext( pt, &c->mfx, 1, clearsig );
	      }
	  }
      }

    if( rc )
	log_error( "handle plaintext failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_session_key = 0;

    /* We add a marker control packet instead of the plaintext packet.
     * This is so that we can later detect invalid packet sequences.
     */
    n = new_kbnode (create_gpg_control (CTRLPKT_PLAINTEXT_MARK, NULL, 0));
    if (c->list)
        add_kbnode (c->list, n);
    else 
        c->list = n;
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
    if( !zd->algorithm )
      rc=G10ERR_COMPR_ALGO;
    else if( c->sigs_only )
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
do_check_sig( CTX c, KBNODE node, int *is_selfsig,
	      int *is_expkey, int *is_revkey )
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
             || sig->sig_class == 0x1f
	     || sig->sig_class == 0x20
	     || sig->sig_class == 0x28
	     || sig->sig_class == 0x30	) { 
	if( c->list->pkt->pkttype == PKT_PUBLIC_KEY
	    || c->list->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    return check_key_signature( c->list, node, is_selfsig );
	}
	else if( sig->sig_class == 0x20 ) {
	    log_error (_("standalone revocation - "
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
    rc = signature_check2( sig, md, NULL, is_expkey, is_revkey, NULL );
    if( rc == G10ERR_BAD_SIGN && md2 )
	rc = signature_check2( sig, md2, NULL, is_expkey, is_revkey, NULL );
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
      {
	if(pkt->pkt.user_id->attrib_data)
	  printf("%u %lu",
		 pkt->pkt.user_id->numattribs,
		 pkt->pkt.user_id->attrib_len);
	else
	  print_string( stdout,  pkt->pkt.user_id->name,
			pkt->pkt.user_id->len, ':');
      }
    else
	print_utf8_string( stdout,  pkt->pkt.user_id->name,
				     pkt->pkt.user_id->len );
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

	if( opt.with_colons )
	  {
	    u32 keyid[2];
	    keyid_from_pk( pk, keyid );
	    if( mainkey )
	      c->trustletter = opt.fast_list_mode?
		0 : get_validity_info( pk, NULL );
	    printf("%s:", mainkey? "pub":"sub" );
	    if( c->trustletter )
	      putchar( c->trustletter );
	    printf(":%u:%d:%08lX%08lX:%s:%s::",
		   nbits_from_pk( pk ),
		   pk->pubkey_algo,
		   (ulong)keyid[0],(ulong)keyid[1],
		   colon_datestr_from_pk( pk ),
		   colon_strtime (pk->expiredate) );
	    if( mainkey && !opt.fast_list_mode )
	      putchar( get_ownertrust_info (pk) );
	    putchar(':');
	    if( node->next && node->next->pkt->pkttype == PKT_RING_TRUST) {
	      putchar('\n'); any=1;
	      if( opt.fingerprint )
		print_fingerprint( pk, NULL, 0 );
	      printf("rtv:1:%u:\n",
		     node->next->pkt->pkt.ring_trust->trustval );
	    }
	  }
	else
	  printf("%s  %4u%c/%s %s%s",
		 mainkey? "pub":"sub", nbits_from_pk( pk ),
		 pubkey_letter( pk->pubkey_algo ), keystr_from_pk( pk ),
		 datestr_from_pk( pk ), mainkey?" ":"");

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
			    printf("%s:::::::::",
			      node->pkt->pkt.user_id->attrib_data?"uat":"uid");
			else
			    printf( "uid%*s", 28, "" );
		    }
		    print_userid( node->pkt );
		    if( opt.with_colons )
			putchar(':');
		    putchar('\n');
		    if( opt.fingerprint && !any )
			print_fingerprint( pk, NULL, 0 );
		    if( opt.with_colons
                        && node->next
			&& node->next->pkt->pkttype == PKT_RING_TRUST ) {
			printf("rtv:2:%u:\n",
                               node->next->pkt->pkt.ring_trust?
                               node->next->pkt->pkt.ring_trust->trustval : 0);
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
	else
	  {
	    /* of subkey */
	    if( pk->is_revoked )
	      {
		printf(" [");
		printf(_("revoked: %s"),revokestr_from_pk(pk));
		printf("]");
	      }
	    else if( pk->expiredate )
	      {
		printf(" [");
		printf(_("expires: %s"),expirestr_from_pk(pk));
		printf("]");
	      }
	  }

	if( !any )
	    putchar('\n');
	if( !mainkey && opt.fingerprint > 1 )
	    print_fingerprint( pk, NULL, 0 );
    }
    else if( (mainkey = (node->pkt->pkttype == PKT_SECRET_KEY) )
	     || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	PKT_secret_key *sk = node->pkt->pkt.secret_key;

	if( opt.with_colons )
	  {
	    u32 keyid[2];
	    keyid_from_sk( sk, keyid );
	    printf("%s::%u:%d:%08lX%08lX:%s:%s:::",
		   mainkey? "sec":"ssb",
		   nbits_from_sk( sk ),
		   sk->pubkey_algo,
		   (ulong)keyid[0],(ulong)keyid[1],
		   colon_datestr_from_sk( sk ),
		   colon_strtime (sk->expiredate)
		   /* fixme: add LID */ );
	  }
	else
	  printf("%s  %4u%c/%s %s ", mainkey? "sec":"ssb",
		 nbits_from_sk( sk ), pubkey_letter( sk->pubkey_algo ),
		 keystr_from_sk( sk ), datestr_from_sk( sk ));
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
			    printf("%s:::::::::",
			      node->pkt->pkt.user_id->attrib_data?"uat":"uid");
			else
			    printf( "uid%*s", 28, "" );
		    }
		    print_userid( node->pkt );
		    if( opt.with_colons )
			putchar(':');
		    putchar('\n');
		    if( opt.fingerprint && !any )
			print_fingerprint( NULL, sk, 0 );
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
	    print_fingerprint( NULL, sk, 0 );
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE  ) {
	PKT_signature *sig = node->pkt->pkt.signature;
	int is_selfsig = 0;
	int rc2=0;
	size_t n;
	char *p;
	int sigrc = ' ';

	if( !opt.verbose )
	    return;

	if( sig->sig_class == 0x20 || sig->sig_class == 0x30 )
	    fputs("rev", stdout);
	else
	    fputs("sig", stdout);
	if( opt.check_sigs ) {
	    fflush(stdout);
	    switch( (rc2=do_check_sig( c, node, &is_selfsig, NULL, NULL )) ) {
	      case 0:		       sigrc = '!'; break;
	      case G10ERR_BAD_SIGN:    sigrc = '-'; break;
	      case G10ERR_NO_PUBKEY: 
	      case G10ERR_UNU_PUBKEY:  sigrc = '?'; break;
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
	    printf("::%d:%08lX%08lX:%s:%s:", sig->pubkey_algo,
		   (ulong)sig->keyid[0], (ulong)sig->keyid[1],
		   colon_datestr_from_sig(sig),
		   colon_expirestr_from_sig(sig));

	    if(sig->trust_depth || sig->trust_value)
	      printf("%d %d",sig->trust_depth,sig->trust_value);
	    printf(":");

	    if(sig->trust_regexp)
	      print_string(stdout,sig->trust_regexp,
			   strlen(sig->trust_regexp),':');
	    printf(":");
	}
	else
	  printf("%c       %s %s   ",
		 sigrc, keystr(sig->keyid), datestr_from_sig(sig));
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
	    xfree(p);
	}
	if( opt.with_colons )
	    printf(":%02x%c:", sig->sig_class, sig->flags.exportable?'x':'l');
	putchar('\n');
    }
    else
	log_error("invalid node with packet of type %d\n", node->pkt->pkttype);
}



int
proc_packets( void *anchor, IOBUF a )
{
    int rc;
    CTX c = xmalloc_clear( sizeof *c );

    c->anchor = anchor;
    rc = do_proc_packets( c, a );
    xfree( c );
    return rc;
}



int
proc_signature_packets( void *anchor, IOBUF a,
			STRLIST signedfiles, const char *sigfilename )
{
    CTX c = xmalloc_clear( sizeof *c );
    int rc;

    c->anchor = anchor;
    c->sigs_only = 1;
    c->signed_data = signedfiles;
    c->sigfilename = sigfilename;
    rc = do_proc_packets( c, a );

    /* If we have not encountered any signature we print an error
       messages, send a NODATA status back and return an error code.
       Using log_error is required because verify_files does not check
       error codes for each file but we want to terminate the process
       with an error. */ 
    if (!rc && !c->any_sig_seen)
      {
	write_status_text (STATUS_NODATA, "4");
        log_error (_("no signature found\n"));
        rc = G10ERR_NO_DATA;
      }

    /* Propagate the signature seen flag upward. Do this only on
       success so that we won't issue the nodata status several
       times. */
    if (!rc && c->anchor && c->any_sig_seen)
      c->anchor->any_sig_seen = 1;

    xfree( c );
    return rc;
}

int
proc_encryption_packets( void *anchor, IOBUF a )
{
    CTX c = xmalloc_clear( sizeof *c );
    int rc;

    c->anchor = anchor;
    c->encrypt_only = 1;
    rc = do_proc_packets( c, a );
    xfree( c );
    return rc;
}


int
do_proc_packets( CTX c, IOBUF a )
{
    PACKET *pkt = xmalloc( sizeof *pkt );
    int rc=0;
    int any_data=0;
    int newpkt;

    c->iobuf = a;
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	any_data = 1;
	if( rc ) {
	    free_packet(pkt);
            /* stop processing when an invalid packet has been encountered
             * but don't do so when we are doing a --list-packets. */
	    if( rc == G10ERR_INVALID_PACKET && opt.list_packets != 2 )
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
                write_status_text( STATUS_UNEXPECTED, "0" );
		rc = G10ERR_UNEXPECTED;
		goto leave;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
              case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
	      default: newpkt = 0; break;
	    }
	}
	else if( c->encrypt_only ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
	      case PKT_USER_ID:
                write_status_text( STATUS_UNEXPECTED, "0" );
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
	      case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
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
              case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
	      case PKT_RING_TRUST:  newpkt = add_ring_trust( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
        /* This is a very ugly construct and frankly, I don't remember why
         * I used it.  Adding the MDC check here is a hack.
         * The right solution is to initiate another context for encrypted
         * packet and not to reuse the current one ...  It works right
         * when there is a compression packet inbetween which adds just
         * an extra layer.
         * Hmmm: Rewrite this whole module here?? 
         */
	if( pkt->pkttype != PKT_SIGNATURE && pkt->pkttype != PKT_MDC )
	    c->have_data = pkt->pkttype == PKT_PLAINTEXT;

	if( newpkt == -1 )
	    ;
	else if( newpkt ) {
	    pkt = xmalloc( sizeof *pkt );
	    init_packet(pkt);
	}
	else
	    free_packet(pkt);
        if ( c->pipemode.stop_now ) {
            /* we won't get an EOF in pipemode, so we have to 
             * break the loop here */ 
            rc = -1;
            break;
        }
    }
    if( rc == G10ERR_INVALID_PACKET )
	write_status_text( STATUS_NODATA, "3" );
    if( any_data )
	rc = 0;
    else if( rc == -1 )
	write_status_text( STATUS_NODATA, "2" );


  leave:
    release_list( c );
    xfree(c->dek);
    free_packet( pkt );
    xfree( pkt );
    free_md_filter_context( &c->mfx );
    return rc;
}


/* Helper for pka_uri_from_sig to parse the to-be-verified address out
   of the notation data. */
static pka_info_t *
get_pka_address (PKT_signature *sig)
{
  pka_info_t *pka = NULL;
  struct notation *nd,*notation;

  notation=sig_to_notation(sig);

  for(nd=notation;nd;nd=nd->next)
    {
      if(strcmp(nd->name,"pka-address@gnupg.org")!=0)
        continue; /* Not the notation we want. */

      /* For now we only use the first valid PKA notation. In future
	 we might want to keep additional PKA notations in a linked
	 list. */
      if (is_valid_mailbox (nd->value))
	{
	  pka = xmalloc (sizeof *pka + strlen(nd->value));
	  pka->valid = 0;
	  pka->checked = 0;
	  pka->uri = NULL;
	  strcpy (pka->email, nd->value);
	  break;
	}
    }

  free_notation(notation);

  return pka;
}


/* Return the URI from a DNS PKA record.  If this record has already
   be retrieved for the signature we merely return it; if not we go
   out and try to get that DNS record. */
static const char *
pka_uri_from_sig (PKT_signature *sig)
{
  if (!sig->flags.pka_tried)
    {
      assert (!sig->pka_info);
      sig->flags.pka_tried = 1;
      sig->pka_info = get_pka_address (sig);
      if (sig->pka_info)
        {
          char *uri;

          uri = get_pka_info (sig->pka_info->email, sig->pka_info->fpr);
          if (uri)
            {
              sig->pka_info->valid = 1;
              if (!*uri)
                xfree (uri);
              else
                sig->pka_info->uri = uri;
            }
        }
    }
  return sig->pka_info? sig->pka_info->uri : NULL;
}


static int
check_sig_and_print( CTX c, KBNODE node )
{
  PKT_signature *sig = node->pkt->pkt.signature;
  const char *astr;
  int rc, is_expkey=0, is_revkey=0;

  if (opt.skip_verify)
    {
      log_info(_("signature verification suppressed\n"));
      return 0;
    }

  /* Check that the message composition is valid.

     Per RFC-2440bis (-15) allowed:

     S{1,n}           -- detached signature.
     S{1,n} P         -- old style PGP2 signature
     O{1,n} P S{1,n}  -- standard OpenPGP signature.
     C P S{1,n}       -- cleartext signature.

        
          O = One-Pass Signature packet.
          S = Signature packet.
          P = OpenPGP Message packet (Encrypted | Compressed | Literal)
                 (Note that the current rfc2440bis draft also allows
                  for a signed message but that does not work as it
                  introduces ambiguities.)
              We keep track of these packages using the marker packet
              CTRLPKT_PLAINTEXT_MARK.
          C = Marker packet for cleartext signatures.

     We reject all other messages.
     
     Actually we are calling this too often, i.e. for verification of
     each message but better have some duplicate work than to silently
     introduce a bug here.
  */
  {
    KBNODE n;
    int n_onepass, n_sig;

/*     log_debug ("checking signature packet composition\n"); */
/*     dump_kbnode (c->list); */

    n = c->list;
    assert (n);
    if ( n->pkt->pkttype == PKT_SIGNATURE ) 
      {
        /* This is either "S{1,n}" case (detached signature) or
           "S{1,n} P" (old style PGP2 signature). */
        for (n = n->next; n; n = n->next)
          if (n->pkt->pkttype != PKT_SIGNATURE)
            break;
        if (!n)
          ; /* Okay, this is a detached signature.  */
        else if (n->pkt->pkttype == PKT_GPG_CONTROL
                 && (n->pkt->pkt.gpg_control->control
                     == CTRLPKT_PLAINTEXT_MARK) )
          {
            if (n->next)
              goto ambiguous;  /* We only allow one P packet. */
          }
        else
          goto ambiguous;
      }
    else if (n->pkt->pkttype == PKT_ONEPASS_SIG) 
      {
        /* This is the "O{1,n} P S{1,n}" case (standard signature). */
        for (n_onepass=1, n = n->next;
             n && n->pkt->pkttype == PKT_ONEPASS_SIG; n = n->next)
          n_onepass++;
        if (!n || !(n->pkt->pkttype == PKT_GPG_CONTROL
                    && (n->pkt->pkt.gpg_control->control
                        == CTRLPKT_PLAINTEXT_MARK)))
          goto ambiguous;
        for (n_sig=0, n = n->next;
             n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
          n_sig++;
        if (!n_sig)
          goto ambiguous;

	/* If we wanted to disallow multiple sig verification, we'd do
	   something like this:

	   if (n && !opt.allow_multisig_verification)
               goto ambiguous;

	   However, now that we have --allow-multiple-messages, this
	   can stay allowable as we can't get here unless multiple
	   messages (i.e. multiple literals) are allowed. */

        if (n_onepass != n_sig)
          {
            log_info ("number of one-pass packets does not match "
                      "number of signature packets\n");
            goto ambiguous;
          }
      }
    else if (n->pkt->pkttype == PKT_GPG_CONTROL
             && n->pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START )
      {
        /* This is the "C P S{1,n}" case (clear text signature). */
        n = n->next;
        if (!n || !(n->pkt->pkttype == PKT_GPG_CONTROL
                    && (n->pkt->pkt.gpg_control->control
                        == CTRLPKT_PLAINTEXT_MARK)))
          goto ambiguous;
        for (n_sig=0, n = n->next;
             n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
          n_sig++;
        if (n || !n_sig)
          goto ambiguous;
      }
    else 
      {
      ambiguous:
        log_error(_("can't handle this ambiguous signature data\n"));
        return 0;
      }

  }

  /* (Indendation below not yet changed to GNU style.) */

    astr = pubkey_algo_to_string( sig->pubkey_algo );
    if(keystrlen()>8)
      {
	log_info(_("Signature made %s\n"),asctimestamp(sig->timestamp));
	log_info(_("               using %s key %s\n"),
		 astr? astr: "?",keystr(sig->keyid));
      }
    else
      log_info(_("Signature made %s using %s key ID %s\n"),
	       asctimestamp(sig->timestamp), astr? astr: "?",
	       keystr(sig->keyid));

    rc = do_check_sig(c, node, NULL, &is_expkey, &is_revkey );

    /* If the key isn't found, check for a preferred keyserver */

    if(rc==G10ERR_NO_PUBKEY && sig->flags.pref_ks)
      {
	const byte *p;
	int seq=0;
	size_t n;

	while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_PREF_KS,&n,&seq,NULL)))
	  {
	    /* According to my favorite copy editor, in English
	       grammar, you say "at" if the key is located on a web
	       page, but "from" if it is located on a keyserver.  I'm
	       not going to even try to make two strings here :) */
	    log_info(_("Key available at: ") );
	    print_utf8_string( log_stream(), p, n );
	    putc( '\n', log_stream() );

	    if(opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE
	       && opt.keyserver_options.options&KEYSERVER_HONOR_KEYSERVER_URL)
	      {
		struct keyserver_spec *spec;

		spec=parse_preferred_keyserver(sig);
		if(spec)
		  {
		    int res;

		    glo_ctrl.in_auto_key_retrieve++;
		    res=keyserver_import_keyid(sig->keyid,spec);
		    glo_ctrl.in_auto_key_retrieve--;
		    if(!res)
		      rc=do_check_sig(c, node, NULL, &is_expkey, &is_revkey );
		    free_keyserver_spec(spec);

		    if(!rc)
		      break;
		  }
	      }
	  }
      }

    /* If the preferred keyserver thing above didn't work, our second
       try is to use the URI from a DNS PKA record. */
    if ( rc == G10ERR_NO_PUBKEY 
	 && opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE
         && opt.keyserver_options.options&KEYSERVER_HONOR_PKA_RECORD)
      {
        const char *uri = pka_uri_from_sig (sig);
        
        if (uri)
          {
            /* FIXME: We might want to locate the key using the
               fingerprint instead of the keyid. */
            int res;
            struct keyserver_spec *spec;
            
            spec = parse_keyserver_uri (uri, 1, NULL, 0);
            if (spec)
              {
                glo_ctrl.in_auto_key_retrieve++;
                res = keyserver_import_keyid (sig->keyid, spec);
                glo_ctrl.in_auto_key_retrieve--;
                free_keyserver_spec (spec);
                if (!res)
                  rc = do_check_sig(c, node, NULL, &is_expkey, &is_revkey );
              }
          }
      }

    /* If the preferred keyserver thing above didn't work and we got
       no information from the DNS PKA, this is a third try. */

    if( rc == G10ERR_NO_PUBKEY && opt.keyserver
	&& opt.keyserver_options.options&KEYSERVER_AUTO_KEY_RETRIEVE)
      {
	int res;

	glo_ctrl.in_auto_key_retrieve++;
	res=keyserver_import_keyid ( sig->keyid, opt.keyserver );
	glo_ctrl.in_auto_key_retrieve--;
	if(!res)
	  rc = do_check_sig(c, node, NULL, &is_expkey, &is_revkey );
      }

    if( !rc || rc == G10ERR_BAD_SIGN ) {
	KBNODE un, keyblock;
	int count=0, statno;
        char keyid_str[50];
	PKT_public_key *pk=NULL;

	if(rc)
	  statno=STATUS_BADSIG;
	else if(sig->flags.expired)
	  statno=STATUS_EXPSIG;
	else if(is_expkey)
	  statno=STATUS_EXPKEYSIG;
	else if(is_revkey)
	  statno=STATUS_REVKEYSIG;
	else
	  statno=STATUS_GOODSIG;

	keyblock = get_pubkeyblock( sig->keyid );

        sprintf (keyid_str, "%08lX%08lX [uncertain] ",
                 (ulong)sig->keyid[0], (ulong)sig->keyid[1]);

        /* find and print the primary user ID */
	for( un=keyblock; un; un = un->next ) {
	    char *p;
	    int valid;
	    if(un->pkt->pkttype==PKT_PUBLIC_KEY)
	      {
	        pk=un->pkt->pkt.public_key;
		continue;
	      }
	    if( un->pkt->pkttype != PKT_USER_ID )
		continue;
	    if ( !un->pkt->pkt.user_id->created )
	        continue;
            if ( un->pkt->pkt.user_id->is_revoked )
                continue;
            if ( un->pkt->pkt.user_id->is_expired )
                continue;
	    if ( !un->pkt->pkt.user_id->is_primary )
	        continue;
	    /* We want the textual primary user ID here */
	    if ( un->pkt->pkt.user_id->attrib_data )
	        continue;

	    assert(pk);

	    /* Get it before we print anything to avoid interrupting
	       the output with the "please do a --check-trustdb"
	       line. */
	    valid=get_validity(pk,un->pkt->pkt.user_id);

            keyid_str[17] = 0; /* cut off the "[uncertain]" part */
            write_status_text_and_buffer (statno, keyid_str,
                                          un->pkt->pkt.user_id->name,
                                          un->pkt->pkt.user_id->len, 
                                          -1 );

	    p=utf8_to_native(un->pkt->pkt.user_id->name,
			     un->pkt->pkt.user_id->len,0);

	    if(rc)
	      log_info(_("BAD signature from \"%s\""),p);
	    else if(sig->flags.expired)
	      log_info(_("Expired signature from \"%s\""),p);
	    else
	      log_info(_("Good signature from \"%s\""),p);

	    xfree(p);

	    if(opt.verify_options&VERIFY_SHOW_UID_VALIDITY)
	      fprintf(log_stream()," [%s]\n",trust_value_to_string(valid));
	    else
	      fputs("\n", log_stream() );
            count++;
	}
	if( !count ) {	/* just in case that we have no valid textual
                           userid */
	    char *p;

	    /* Try for an invalid textual userid */
            for( un=keyblock; un; un = un->next ) {
                if( un->pkt->pkttype == PKT_USER_ID &&
		    !un->pkt->pkt.user_id->attrib_data )
                    break;
            }

	    /* Try for any userid at all */
	    if(!un) {
	        for( un=keyblock; un; un = un->next ) {
                    if( un->pkt->pkttype == PKT_USER_ID )
                        break;
		}
	    }

            if (opt.trust_model==TM_ALWAYS || !un)
                keyid_str[17] = 0; /* cut off the "[uncertain]" part */

            write_status_text_and_buffer (statno, keyid_str,
                                          un? un->pkt->pkt.user_id->name:"[?]",
                                          un? un->pkt->pkt.user_id->len:3, 
                                          -1 );

	    if(un)
	      p=utf8_to_native(un->pkt->pkt.user_id->name,
                               un->pkt->pkt.user_id->len,0);
	    else
	      p=xstrdup("[?]");

	    if(rc)
	      log_info(_("BAD signature from \"%s\""),p);
	    else if(sig->flags.expired)
	      log_info(_("Expired signature from \"%s\""),p);
	    else
	      log_info(_("Good signature from \"%s\""),p);
            if (opt.trust_model!=TM_ALWAYS && un)
	      {
                putc(' ', log_stream() );
                fputs(_("[uncertain]"), log_stream() );
	      }
	    fputs("\n", log_stream() );
	}

        /* If we have a good signature and already printed 
         * the primary user ID, print all the other user IDs */
        if ( count && !rc
             && !(opt.verify_options&VERIFY_SHOW_PRIMARY_UID_ONLY) ) {
	    char *p;
            for( un=keyblock; un; un = un->next ) {
                if( un->pkt->pkttype != PKT_USER_ID )
                    continue;
                if((un->pkt->pkt.user_id->is_revoked
		    || un->pkt->pkt.user_id->is_expired)
		   && !(opt.verify_options&VERIFY_SHOW_UNUSABLE_UIDS))
		  continue;
		/* Only skip textual primaries */
                if ( un->pkt->pkt.user_id->is_primary &&
		     !un->pkt->pkt.user_id->attrib_data )
		    continue;

		if(un->pkt->pkt.user_id->attrib_data)
		  {
		    dump_attribs(un->pkt->pkt.user_id,pk,NULL);

		    if(opt.verify_options&VERIFY_SHOW_PHOTOS)
		      show_photos(un->pkt->pkt.user_id->attribs,
				  un->pkt->pkt.user_id->numattribs,pk,NULL);
		  }

		p=utf8_to_native(un->pkt->pkt.user_id->name,
				 un->pkt->pkt.user_id->len,0);
		log_info(_("                aka \"%s\""),p);
		xfree(p);

		if(opt.verify_options&VERIFY_SHOW_UID_VALIDITY)
		  {
		    const char *valid;
		    if(un->pkt->pkt.user_id->is_revoked)
		      valid=_("revoked");
		    else if(un->pkt->pkt.user_id->is_expired)
		      valid=_("expired");
		    else
		      valid=trust_value_to_string(get_validity(pk,
							       un->pkt->
							       pkt.user_id));
		    fprintf(log_stream()," [%s]\n",valid);
		  }
		else
		  fputs("\n", log_stream() );
            }
	}
	release_kbnode( keyblock );

	if( !rc )
	  {
	    if(opt.verify_options&VERIFY_SHOW_POLICY_URLS)
	      show_policy_url(sig,0,1);
	    else
	      show_policy_url(sig,0,2);

	    if(opt.verify_options&VERIFY_SHOW_KEYSERVER_URLS)
	      show_keyserver_url(sig,0,1);
	    else
	      show_keyserver_url(sig,0,2);

	    if(opt.verify_options&VERIFY_SHOW_NOTATIONS)
	      show_notation(sig,0,1,
		        ((opt.verify_options&VERIFY_SHOW_STD_NOTATIONS)?1:0)+
			((opt.verify_options&VERIFY_SHOW_USER_NOTATIONS)?2:0));
	    else
	      show_notation(sig,0,2,0);
	  }

	if( !rc && is_status_enabled() ) {
	    /* print a status response with the fingerprint */
	    PKT_public_key *vpk = xmalloc_clear( sizeof *vpk );

	    if( !get_pubkey( vpk, sig->keyid ) ) {
		byte array[MAX_FINGERPRINT_LEN], *p;
		char buf[MAX_FINGERPRINT_LEN*4+90], *bufp;
		size_t i, n;

                bufp = buf;
		fingerprint_from_pk( vpk, array, &n );
		p = array;
		for(i=0; i < n ; i++, p++, bufp += 2)
                    sprintf(bufp, "%02X", *p );
		/* TODO: Replace the reserved '0' in the field below
		   with bits for status flags (policy url, notation,
		   etc.).  Remember to make the buffer larger to
		   match! */
		sprintf(bufp, " %s %lu %lu %d 0 %d %d %02X ",
                        strtimestamp( sig->timestamp ),
                        (ulong)sig->timestamp,(ulong)sig->expiredate,
			sig->version,sig->pubkey_algo,sig->digest_algo,
			sig->sig_class);
                bufp = bufp + strlen (bufp);
                if (!vpk->is_primary) {
                   u32 akid[2];
 
                   akid[0] = vpk->main_keyid[0];
                   akid[1] = vpk->main_keyid[1];
                   free_public_key (vpk);
                   vpk = xmalloc_clear( sizeof *vpk );
                   if (get_pubkey (vpk, akid)) {
                     /* impossible error, we simply return a zeroed out fpr */
                     n = MAX_FINGERPRINT_LEN < 20? MAX_FINGERPRINT_LEN : 20;
                     memset (array, 0, n);
                   }
                   else
                     fingerprint_from_pk( vpk, array, &n );
                }
		p = array;
		for(i=0; i < n ; i++, p++, bufp += 2)
                    sprintf(bufp, "%02X", *p );
		write_status_text( STATUS_VALIDSIG, buf );
	    }
	    free_public_key( vpk );
	}

	if (!rc)
          {
	    if(opt.verify_options&VERIFY_PKA_LOOKUPS)
	      pka_uri_from_sig (sig); /* Make sure PKA info is available. */
	    rc = check_signatures_trust( sig );
          }

	if(sig->flags.expired)
	  {
	    log_info(_("Signature expired %s\n"),
		     asctimestamp(sig->expiredate));
	    rc=G10ERR_GENERAL; /* need a better error here? */
	  }
	else if(sig->expiredate)
	  log_info(_("Signature expires %s\n"),asctimestamp(sig->expiredate));

	if(opt.verbose)
	  log_info(_("%s signature, digest algorithm %s\n"),
		   sig->sig_class==0x00?_("binary"):
		   sig->sig_class==0x01?_("textmode"):_("unknown"),
		   digest_algo_to_string(sig->digest_algo));

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

    /* we must skip our special plaintext marker packets here becuase
       they may be the root packet.  These packets are only used in
       addionla checks and skipping them here doesn't matter */
    while ( node
            && node->pkt->pkttype == PKT_GPG_CONTROL
            && node->pkt->pkt.gpg_control->control
                         == CTRLPKT_PLAINTEXT_MARK ) {
        node = node->next;
    }
    if (!node)
        return;

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

	    /* fixme: why looking for the signature packet and not the
               one-pass packet? */
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
						iobuf_get_real_fname(c->iobuf),
			n1? (n1->pkt->pkt.onepass_sig->sig_class == 0x01):0 );
	    }
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return;
	    }
	}
        else if ( c->signed_data ) {
            log_error (_("not a detached signature\n") );
            return;
        }

	for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); )
	    check_sig_and_print( c, n1 );
    }
    else if( node->pkt->pkttype == PKT_GPG_CONTROL
             && node->pkt->pkt.gpg_control->control
                == CTRLPKT_CLEARSIGN_START ) {
        /* clear text signed message */
	if( !c->have_data ) {
            log_error("cleartext signature without data\n" );
            return;
        }
        else if ( c->signed_data ) {
            log_error (_("not a detached signature\n") );
            return;
        }
	
	for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); )
	    check_sig_and_print( c, n1 );
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	PKT_signature *sig = node->pkt->pkt.signature;
	int multiple_ok=1;

	n1=find_next_kbnode(node, PKT_SIGNATURE);
	if(n1)
	  {
	    byte class=sig->sig_class;
	    byte hash=sig->digest_algo;

	    for(; n1; (n1 = find_next_kbnode(n1, PKT_SIGNATURE)))
	      {
		/* We can't currently handle multiple signatures of
		   different classes or digests (we'd pretty much have
		   to run a different hash context for each), but if
		   they are all the same, make an exception. */
		if(n1->pkt->pkt.signature->sig_class!=class
		   || n1->pkt->pkt.signature->digest_algo!=hash)
		  {
		    multiple_ok=0;
		    log_info(_("WARNING: multiple signatures detected.  "
			       "Only the first will be checked.\n"));
		    break;
		  }
	      }
	  }

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
            if ( DBG_HASHING ) {
                md_start_debug( c->mfx.md, "verify" );
                if ( c->mfx.md2  )
                    md_start_debug( c->mfx.md2, "verify2" );
            }
	    if( c->sigs_only ) {
		rc = hash_datafiles( c->mfx.md, c->mfx.md2,
				     c->signed_data, c->sigfilename,
				     (sig->sig_class == 0x01) );
	    }
	    else {
		rc = ask_for_detached_datafile( c->mfx.md, c->mfx.md2,
						iobuf_get_real_fname(c->iobuf),
						(sig->sig_class == 0x01) );
	    }
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return;
	    }
	}
        else if ( c->signed_data ) {
            log_error (_("not a detached signature\n") );
            return;
        }
        else if ( c->pipemode.op == 'B' )
            ; /* this is a detached signature trough the pipemode handler */
	else if (!opt.quiet)
	    log_info(_("old style (PGP 2.x) signature\n"));

	if(multiple_ok)
	  for( n1 = node; n1; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )) )
	    check_sig_and_print( c, n1 );
	else
	  check_sig_and_print( c, node );
    }
    else {
        dump_kbnode (c->list);
	log_error(_("invalid root packet detected in proc_tree()\n"));
        dump_kbnode (node);
    }
}
