/* mainproc.c - handle packets
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

#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "util.h"
#include "cipher.h"
#include "keydb.h"


static int opt_list=1;	/* and list the data packets to stdout */

int
proc_packets( IOBUF a )
{
    PACKET *pkt;
    PKT_pubkey_cert *last_pubkey = NULL;
    PKT_seckey_cert *last_seckey = NULL;
    PKT_user_id     *last_user_id = NULL;
    DEK *dek = NULL;
    PKT_signature *sig; /* CHECK: "might be used uninitialied" */
    int rc, result;
    MD_HANDLE md_handle; /* union to pass handles */
    char *ustr;
    int lvl0, lvl1;
    int last_was_pubkey_enc = 0;
    u32 keyid[2];

    lvl0 = opt.check_sigs? 1:0; /* stdout or /dev/null */
    lvl1 = opt.check_sigs? 1:3; /* stdout or error */
    pkt = m_alloc( sizeof *pkt );
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	if( dek && pkt->pkttype != PKT_ENCR_DATA ) {
	    log_error("oops: valid pubkey enc packet not followed by data\n");
	    m_free(dek); dek = NULL; /* burn it */
	}

	if( rc )
	    free_packet(pkt);
	else if( pkt->pkttype == PKT_PUBKEY_CERT ) {
	    if( last_user_id ) {
		free_user_id( last_user_id );
		last_user_id = NULL;
	    }
	    if( last_pubkey ) {
		free_pubkey_cert( last_pubkey );
		last_pubkey = NULL;
	    }
	    if( opt.check_sigs ) {
		ustr = get_user_id_string(sig->keyid);
		printstr(lvl0, "pub: %s\n", ustr );
		m_free(ustr);
	    }
	    else
		fputs( "pub: [Public Key Cerificate]\n", stdout );
	    last_pubkey = pkt->pkt.pubkey_cert;
	    pkt->pkt.pubkey_cert = NULL;
	    free_packet(pkt);
	    pkt->pkc_parent = last_pubkey; /* set this as parent */
	}
	else if( pkt->pkttype == PKT_SECKEY_CERT ) {
	    if( last_user_id ) {
		free_user_id( last_user_id );
		last_user_id = NULL;
	    }
	    if( last_seckey ) {
		free_seckey_cert( last_seckey );
		last_seckey = NULL;
	    }
	    if( opt_list )
		fputs( "sec: (secret key certificate)\n", stdout );
	    rc = check_secret_key( pkt->pkt.seckey_cert );
	    if( opt_list ) {
		if( !rc )
		    fputs( "     Secret key is good", stdout );
		else
		    fputs( g10_errstr(rc), stdout);
		putchar('\n');
	    }
	    else if( rc )
		log_error("secret key certificate error: %s\n", g10_errstr(rc));
	    last_seckey = pkt->pkt.seckey_cert;
	    pkt->pkt.seckey_cert = NULL;
	    free_packet(pkt);
	    pkt->skc_parent = last_seckey; /* set this as parent */
	}
	else if( pkt->pkttype == PKT_USER_ID ) {
	    if( last_user_id ) {
		free_user_id( last_user_id );
		last_user_id = NULL;
	    }
	    if( opt_list ) {
		 printf("uid: '%.*s'\n", pkt->pkt.user_id->len,
					 pkt->pkt.user_id->name );
		 if( !pkt->pkc_parent && !pkt->skc_parent )
		     puts("      (orphaned)");
	    }
	    if( pkt->pkc_parent ) {
		if( pkt->pkc_parent->pubkey_algo == PUBKEY_ALGO_RSA ) {
		    mpi_get_keyid( pkt->pkc_parent->d.rsa.rsa_n, keyid );
		    cache_user_id( pkt->pkt.user_id, keyid );
		}
	    }

	    last_user_id = pkt->pkt.user_id;  /* save */
	    pkt->pkt.user_id = NULL;
	    free_packet(pkt);	/* fixme: free_packet is not a good name */
	    pkt->user_parent = last_user_id;  /* and set this as user */
	}
	else if( pkt->pkttype == PKT_SIGNATURE ) {
	    sig = pkt->pkt.signature;
	    ustr = get_user_id_string(sig->keyid);
	    result = -1;
	    if( sig->sig_class != 0x10 )
		printstr(lvl1,"sig?: %s: unknown signature class %02x\n",
					ustr, sig->sig_class);
	    else if( !pkt->pkc_parent || !pkt->user_parent )
		printstr(lvl1,"sig?: %s: orphaned encoded packet\n", ustr);
	    else
		result = 0;

	    if( result )
		;
	    else if( !opt.check_sigs ) {
		result = -1;
		printstr(lvl0, "sig: from %s\n", ustr );
	    }
	    else if(sig->pubkey_algo == PUBKEY_ALGO_RSA ) {
		md_handle.algo = sig->d.rsa.digest_algo;
		if( sig->d.rsa.digest_algo == DIGEST_ALGO_RMD160 ) {
		    md_handle.u.rmd = rmd160_copy(pkt->pkc_parent->mfx.rmd160);
		    rmd160_write(md_handle.u.rmd, pkt->user_parent->name,
						  pkt->user_parent->len);
		    result = signature_check( sig, md_handle );
		    rmd160_close(md_handle.u.rmd);
		}
		else if( sig->d.rsa.digest_algo == DIGEST_ALGO_MD5 ) {
		    md_handle.u.md5 = md5_copy(pkt->pkc_parent->mfx.md5);
		    md5_write(md_handle.u.md5, pkt->user_parent->name,
					       pkt->user_parent->len);
		    result = signature_check( sig, md_handle );
		    md5_close(md_handle.u.md5);
		}
		else
		    result = G10ERR_DIGEST_ALGO;
	    }
	    else
		result = G10ERR_PUBKEY_ALGO;

	    if( result == -1 )
		;
	    else if( !result )
		printstr(lvl0, "sig: good signature from %s\n", ustr );
	    else
		printstr(lvl1, "sig? %s: %s\n", ustr, g10_errstr(result));
	    free_packet(pkt);
	    m_free(ustr);
	}
	else if( pkt->pkttype == PKT_PUBKEY_ENC ) {
	    PKT_pubkey_enc *enc;

	    last_was_pubkey_enc = 1;
	    result = 0;
	    enc = pkt->pkt.pubkey_enc;
	    printf("enc: encrypted by a pubkey with keyid %08lX\n",
							enc->keyid[1] );
	    if( enc->pubkey_algo == PUBKEY_ALGO_RSA ) {
		m_free(dek ); /* paranoid: delete a pending DEK */
		dek = m_alloc_secure( sizeof *dek );
		if( (result = get_session_key( enc, dek )) ) {
		    /* error: delete the DEK */
		    m_free(dek); dek = NULL;
		}
	    }
	    else
		result = G10ERR_PUBKEY_ALGO;

	    if( result == -1 )
		;
	    else if( !result )
		fputs(	"     DEK is good", stdout );
	    else
		printf( "     %s", g10_errstr(result));
	    putchar('\n');
	    free_packet(pkt);
	}
	else if( pkt->pkttype == PKT_ENCR_DATA ) {
	    result = 0;
	    printf("dat: %sencrypted data\n", dek?"":"conventional ");
	    if( !dek && !last_was_pubkey_enc ) {
		/* assume this is conventional encrypted data */
		dek = m_alloc_secure( sizeof *dek );
		dek->algo = DEFAULT_CIPHER_ALGO;
		result = make_dek_from_passphrase( dek, 0 );
	    }
	    else if( !dek )
		result = G10ERR_NO_SECKEY;
	    if( !result )
		result = decrypt_data( pkt->pkt.encr_data, dek );
	    m_free(dek); dek = NULL;
	    if( result == -1 )
		;
	    else if( !result )
		fputs(	"     encryption okay",stdout);
	    else
		printf( "     %s", g10_errstr(result));
	    putchar('\n');
	    free_packet(pkt);
	    last_was_pubkey_enc = 0;
	}
	else if( pkt->pkttype == PKT_PLAINTEXT ) {
	    PKT_plaintext *pt = pkt->pkt.plaintext;
	    printf("txt: plain text data name='%.*s'\n", pt->namelen, pt->name);
	    result = handle_plaintext( pt );
	    if( !result )
		fputs(	"     okay",stdout);
	    else
		printf( "     %s", g10_errstr(result));
	    putchar('\n');
	    free_packet(pkt);
	    last_was_pubkey_enc = 0;
	}
	else if( pkt->pkttype == PKT_COMPR_DATA ) {
	    PKT_compressed *zd = pkt->pkt.compressed;
	    printf("zip: compressed data packet\n");
	    result = handle_compressed( zd );
	    if( !result )
		fputs(	"     okay",stdout);
	    else
		printf( "     %s", g10_errstr(result));
	    putchar('\n');
	    free_packet(pkt);
	    last_was_pubkey_enc = 0;
	}
	else
	    free_packet(pkt);
    }

    if( last_user_id )
	free_user_id( last_user_id );
    if( last_seckey )
	free_seckey_cert( last_seckey );
    if( last_pubkey )
	free_pubkey_cert( last_pubkey );
    m_free(dek);
    free_packet( pkt );
    m_free( pkt );
    return 0;
}


