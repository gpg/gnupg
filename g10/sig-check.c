/* sig-check.c -  Check a signature
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

#include <gcrypt.h>
#include "util.h"
#include "packet.h"
#include "keydb.h"
#include "main.h"
#include "status.h"
#include "i18n.h"
#include "options.h"

struct cmp_help_context_s {
    PKT_signature *sig;
    GCRY_MD_HD md;
};


static int do_signature_check( PKT_signature *sig, GCRY_MD_HD digest,
					 u32 *r_expiredate, int *r_expired );
static int do_check( PKT_public_key *pk, PKT_signature *sig,
					 GCRY_MD_HD digest, int *r_expired );



/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
static int
pk_verify( int algo, MPI hash, MPI *data, MPI *pkey,
	   int (*cmp)(void *, MPI), void *opaque )
{
    GCRY_SEXP s_sig, s_hash, s_pkey;
    int rc;

    /* forget about cmp and opaque - we never used it */

    /* make a sexp from pkey */
    if( algo == GCRY_PK_DSA ) {
	rc = gcry_sexp_build ( &s_pkey, NULL,
			      "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
				  pkey[0], pkey[1], pkey[2], pkey[3] );
    }
    else if( algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E ) {
	rc = gcry_sexp_build ( &s_pkey, NULL,
			      "(public-key(elg(p%m)(g%m)(y%m)))",
				  pkey[0], pkey[1], pkey[2] );
    }
    else if( algo == GCRY_PK_RSA ) {
	rc = gcry_sexp_build ( &s_pkey, NULL,
			      "(public-key(rsa(n%m)(e%m)))",
				  pkey[0], pkey[1] );
    }
    else
	return GPGERR_PUBKEY_ALGO;

    if ( rc )
	BUG ();

    /* put hash into a S-Exp s_hash */
    if ( gcry_sexp_build( &s_hash, NULL, "%m", hash ) )
	BUG ();

    /* put data into a S-Exp s_sig */
    if( algo == GCRY_PK_DSA ) {
	rc = gcry_sexp_build ( &s_sig, NULL,
			      "(sig-val(dsa(r%m)(s%m)))", data[0], data[1] );
    }
    else if( algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E ) {
	rc = gcry_sexp_build ( &s_sig, NULL,
			      "(sig-val(elg(r%m)(s%m)))", data[0], data[1] );
    }
    else if( algo == GCRY_PK_RSA ) {
	rc = gcry_sexp_build ( &s_sig, NULL,
			      "(sig-val(rsa(s%m)))", data[0] );
    }
    else
	BUG();

    if ( rc )
	BUG ();


    rc = gcry_pk_verify( s_sig, s_hash, s_pkey );
    gcry_sexp_release( s_sig );
    gcry_sexp_release( s_hash );
    gcry_sexp_release( s_pkey );
    return rc;
}



/****************
 * Check the signature which is contained in SIG.
 * The GCRY_MD_HD should be currently open, so that this function
 * is able to append some data, before finalizing the digest.
 */
int
signature_check( PKT_signature *sig, GCRY_MD_HD digest )
{
    u32 dummy;
    int dum2;
    return do_signature_check( sig, digest, &dummy, &dum2 );
}

static int
do_signature_check( PKT_signature *sig, GCRY_MD_HD digest,
					u32 *r_expiredate, int *r_expired )
{
    PKT_public_key *pk = gcry_xcalloc( 1, sizeof *pk );
    int rc=0;

    *r_expiredate = 0;
    if( get_pubkey( pk, sig->keyid ) )
	rc = GPGERR_NO_PUBKEY;
    else {
	*r_expiredate = pk->expiredate;
	rc = do_check( pk, sig, digest, r_expired );
    }

    free_public_key( pk );

    if( !rc && sig->sig_class < 2 && is_status_enabled() ) {
	/* This signature id works best with DLP algorithms because
	 * they use a random parameter for every signature.  Instead of
	 * this sig-id we could have also used the hash of the document
	 * and the timestamp, but the drawback of this is, that it is
	 * not possible to sign more than one identical document within
	 * one second.	Some remote bacth processing applications might
	 * like this feature here */
	GCRY_MD_HD md;
	u32 a = sig->timestamp;
	int i, nsig = pubkey_get_nsig( sig->pubkey_algo );
	byte *p, *buffer;

	if( !(md = gcry_md_open( GCRY_MD_RMD160, 0)) )
	    BUG();
	gcry_md_putc( digest, sig->pubkey_algo );
	gcry_md_putc( digest, sig->digest_algo );
	gcry_md_putc( digest, (a >> 24) & 0xff );
	gcry_md_putc( digest, (a >> 16) & 0xff );
	gcry_md_putc( digest, (a >>  8) & 0xff );
	gcry_md_putc( digest,  a	& 0xff );
	for(i=0; i < nsig; i++ ) {
	    size_t n = gcry_mpi_get_nbits( sig->data[i]);

	    gcry_md_putc( md, n>>8);
	    gcry_md_putc( md, n );
	    if( gcry_mpi_aprint( GCRYMPI_FMT_USG, &p, &n, sig->data[i] ) )
		BUG();
	    gcry_md_write( md, p, n );
	    gcry_free(p);
	}
	gcry_md_final( md );
	p = make_radix64_string( gcry_md_read( md, 0 ), 20 );
	buffer = gcry_xmalloc( strlen(p) + 60 );
	sprintf( buffer, "%s %s %lu",
		 p, strtimestamp( sig->timestamp ), (ulong)sig->timestamp );
	write_status_text( STATUS_SIG_ID, buffer );
	gcry_free(buffer);
	gcry_free(p);
	gcry_md_close(md);
    }

    return rc;
}


/****************
 * This function gets called by pubkey_verify() if the algorithm needs it.
 */
static int
cmp_help( void *opaque, MPI result )
{
  #if 0 /* we do not use this anymore */
    int rc=0, i, j, c, old_enc;
    byte *dp;
    const byte *asn;
    size_t mdlen, asnlen;
    struct cmp_help_context_s *ctx = opaque;
    PKT_signature *sig = ctx->sig;
    GCRY_MD_HD digest = ctx->md;

    old_enc = 0;
    for(i=j=0; (c=mpi_getbyte(result, i)) != -1; i++ ) {
	if( !j ) {
	    if( !i && c != 1 )
		break;
	    else if( i && c == 0xff )
		; /* skip the padding */
	    else if( i && !c )
		j++;
	    else
		break;
	}
	else if( ++j == 18 && c != 1 )
	    break;
	else if( j == 19 && c == 0 ) {
	    old_enc++;
	    break;
	}
    }
    if( old_enc ) {
	log_error("old encoding scheme is not supported\n");
	return GPGERR_GENERAL;
    }

    if( (rc=check_digest_algo(sig->digest_algo)) )
	return rc; /* unsupported algo */
    asn = md_asn_oid( sig->digest_algo, &asnlen, &mdlen );

    for(i=mdlen,j=asnlen-1; (c=mpi_getbyte(result, i)) != -1 && j >= 0;
							   i++, j-- )
	if( asn[j] != c )
	    break;
    if( j != -1 || mpi_getbyte(result, i) )
	return GPGERR_BAD_PUBKEY;  /* ASN is wrong */
    for(i++; (c=mpi_getbyte(result, i)) != -1; i++ )
	if( c != 0xff  )
	    break;
    i++;
    if( c != sig->digest_algo || mpi_getbyte(result, i) ) {
	/* Padding or leading bytes in signature is wrong */
	return GPGERR_BAD_PUBKEY;
    }
    if( mpi_getbyte(result, mdlen-1) != sig->digest_start[0]
	|| mpi_getbyte(result, mdlen-2) != sig->digest_start[1] ) {
	/* Wrong key used to check the signature */
	return GPGERR_BAD_PUBKEY;
    }

    dp = md_read( digest, sig->digest_algo );
    for(i=mdlen-1; i >= 0; i--, dp++ ) {
	if( mpi_getbyte( result, i ) != *dp )
	    return GPGERR_BAD_SIGN;
    }
    return 0;
  #else
    return -1;
  #endif
}


static int
do_check( PKT_public_key *pk, PKT_signature *sig, GCRY_MD_HD digest,
						    int *r_expired )
{
    MPI result = NULL;
    int rc=0;
    struct cmp_help_context_s ctx;
    u32 cur_time;

    *r_expired = 0;
    if( pk->version == 4 && pk->pubkey_algo == GCRY_PK_ELG_E ) {
	log_info(_("this is a PGP generated "
		   "ElGamal key which is NOT secure for signatures!\n"));
	return GPGERR_PUBKEY_ALGO;
    }

    if( pk->timestamp > sig->timestamp ) {
	ulong d = pk->timestamp - sig->timestamp;
	log_info( d==1
		  ? _("public key is %lu second newer than the signature\n")
		  : _("public key is %lu seconds newer than the signature\n"),
		       d );
	if( !opt.ignore_time_conflict )
	    return GPGERR_TIME_CONFLICT; /* pubkey newer than signature */
    }

    cur_time = make_timestamp();
    if( pk->timestamp > cur_time ) {
	ulong d = pk->timestamp - cur_time;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	if( !opt.ignore_time_conflict )
	    return GPGERR_TIME_CONFLICT;
    }

    if( pk->expiredate && pk->expiredate < cur_time ) {
	log_info(_("NOTE: signature key expired %s\n"),
					asctimestamp( pk->expiredate ) );
	write_status(STATUS_SIGEXPIRED);
	*r_expired = 1;
    }


    if( (rc=openpgp_md_test_algo(sig->digest_algo)) )
	return rc;
    if( (rc=openpgp_pk_test_algo(sig->pubkey_algo, 0)) )
	return rc;

    /* make sure the digest algo is enabled (in case of a detached signature)*/
    gcry_md_enable( digest, sig->digest_algo );

    /* complete the digest */
    if( sig->version >= 4 )
	gcry_md_putc( digest, sig->version );
    gcry_md_putc( digest, sig->sig_class );
    if( sig->version < 4 ) {
	u32 a = sig->timestamp;
	gcry_md_putc( digest, (a >> 24) & 0xff );
	gcry_md_putc( digest, (a >> 16) & 0xff );
	gcry_md_putc( digest, (a >>  8) & 0xff );
	gcry_md_putc( digest,  a	& 0xff );
    }
    else {
	byte buf[6];
	size_t n;
	gcry_md_putc( digest, sig->pubkey_algo );
	gcry_md_putc( digest, sig->digest_algo );
	if( sig->hashed_data ) {
	    n = (sig->hashed_data[0] << 8) | sig->hashed_data[1];
	    gcry_md_write( digest, sig->hashed_data, n+2 );
	    n += 6;
	}
	else
	    n = 6;
	/* add some magic */
	buf[0] = sig->version;
	buf[1] = 0xff;
	buf[2] = n >> 24;
	buf[3] = n >> 16;
	buf[4] = n >>  8;
	buf[5] = n;
	gcry_md_write( digest, buf, 6 );
    }
    gcry_md_final( digest );

    result = encode_md_value( pk->pubkey_algo, digest, sig->digest_algo,
			      gcry_mpi_get_nbits(pk->pkey[0]), 0);
    ctx.sig = sig;
    ctx.md = digest;
    rc = pk_verify( pk->pubkey_algo, result, sig->data, pk->pkey,
			cmp_help, &ctx );
    mpi_release( result );
    if( (opt.emulate_bugs & EMUBUG_MDENCODE)
	&& rc == GPGERR_BAD_SIGN && is_ELGAMAL(pk->pubkey_algo) ) {
	/* In this case we try again because old GnuPG versions didn't encode
	 * the hash right. There is no problem with DSA however  */
	result = encode_md_value( pk->pubkey_algo, digest, sig->digest_algo,
				  gcry_mpi_get_nbits(pk->pkey[0]), (sig->version < 5) );
	ctx.sig = sig;
	ctx.md = digest;
	rc = pk_verify( pk->pubkey_algo, result, sig->data, pk->pkey,
			cmp_help, &ctx );
    }

    if( !rc && sig->flags.unknown_critical ) {
	log_info(_("assuming bad signature due to an unknown critical bit\n"));
	rc = GPGERR_BAD_SIGN;
    }
    sig->flags.checked = 1;
    sig->flags.valid = !rc;

    return rc;
}


static void
hash_uid_node( KBNODE unode, GCRY_MD_HD md, PKT_signature *sig )
{
    PKT_user_id *uid = unode->pkt->pkt.user_id;

    assert( unode->pkt->pkttype == PKT_USER_ID );
    if( uid->photo ) {
	if( sig->version >=4 ) {
	    byte buf[5];
	    buf[0] = 0xd1;		   /* packet of type 17 */
	    buf[1] = uid->photolen >> 24;  /* always use 4 length bytes */
	    buf[2] = uid->photolen >> 16;
	    buf[3] = uid->photolen >>  8;
	    buf[4] = uid->photolen;
	    gcry_md_write( md, buf, 5 );
	}
	gcry_md_write( md, uid->photo, uid->photolen );
    }
    else {
	if( sig->version >=4 ) {
	    byte buf[5];
	    buf[0] = 0xb4;	      /* indicates a userid packet */
	    buf[1] = uid->len >> 24;  /* always use 4 length bytes */
	    buf[2] = uid->len >> 16;
	    buf[3] = uid->len >>  8;
	    buf[4] = uid->len;
	    gcry_md_write( md, buf, 5 );
	}
	gcry_md_write( md, uid->name, uid->len );
    }
}

/****************
 * check the signature pointed to by NODE. This is a key signature.
 * If the function detects a self-signature, it uses the PK from
 * ROOT and does not read any public key.
 */
int
check_key_signature( KBNODE root, KBNODE node, int *is_selfsig )
{
    u32 dummy;
    int dum2;
    return check_key_signature2(root, node, is_selfsig, &dummy, &dum2 );
}

int
check_key_signature2( KBNODE root, KBNODE node, int *is_selfsig,
				       u32 *r_expiredate, int *r_expired )
{
    GCRY_MD_HD md;
    PKT_public_key *pk;
    PKT_signature *sig;
    int algo;
    int rc;

    if( is_selfsig )
	*is_selfsig = 0;
    *r_expiredate = 0;
    *r_expired = 0;
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( root->pkt->pkttype == PKT_PUBLIC_KEY );

    pk = root->pkt->pkt.public_key;
    sig = node->pkt->pkt.signature;
    algo = sig->digest_algo;

  #if 0
    if( sig->flags.checked ) {
	log_debug("check_key_signature: already checked: %s\n",
		      sig->flags.valid? "good":"bad" );
        if ( sig->flags.valid )
            return 0; /* shortcut already checked signatures */
        /* FIXME: We should also do this with bad signatures but here we
         * have to distinguish between several reasons; e.g. for a missing
         * public key. the key may now be available.
         * For now we simply don't shortcut bad signatures
         */
    }
  #endif

    if( (rc=openpgp_md_test_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x20 ) {
	if( !(md = gcry_md_open( algo, 0 )) )
	    BUG();
	hash_public_key( md, pk );
	rc = do_check( pk, sig, md, r_expired );
	gcry_md_close(md);
    }
    else if( sig->sig_class == 0x28 ) { /* subkey revocation */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    if( !(md = gcry_md_open( algo, 0 )) )
		BUG();
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired );
	    gcry_md_close(md);
	}
	else {
	    log_error("no subkey for subkey revocation packet\n");
	    rc = GPGERR_SIG_CLASS;
	}
    }
    else if( sig->sig_class == 0x18 ) {
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    if( is_selfsig ) {	/* does this make sense????? */
		u32 keyid[2];	/* it should always be a selfsig */

		keyid_from_pk( pk, keyid );
		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    *is_selfsig = 1;
	    }
	    if( !(md = gcry_md_open( algo, 0 )) )
		BUG();
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired );
	    gcry_md_close(md);
	}
	else {
	    log_error("no subkey for key signature packet\n");
	    rc = GPGERR_SIG_CLASS;
	}
    }
    else {
	KBNODE unode = find_prev_kbnode( root, node, PKT_USER_ID );

	if( unode ) {
	    u32 keyid[2];

	    keyid_from_pk( pk, keyid );
	    if( !(md = gcry_md_open( algo, 0 )) )
		BUG();
	    hash_public_key( md, pk );
	    hash_uid_node( unode, md, sig );
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] ) {
		if( is_selfsig )
		    *is_selfsig = 1;
		rc = do_check( pk, sig, md, r_expired );
	    }
	    else {
		rc = do_signature_check( sig, md, r_expiredate, r_expired );
	    }
	    gcry_md_close(md);
	}
	else {
	    log_error("no user ID for key signature packet\n");
	    rc = GPGERR_SIG_CLASS;
	}
    }

    return rc;
}


