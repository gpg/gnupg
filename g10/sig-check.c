/* sig-check.c -  Check a signature
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2003  Free Software Foundation, Inc.
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

#include "gpg.h"
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "mpi.h"
#include "keydb.h"
#include "cipher.h"
#include "main.h"
#include "status.h"
#include "i18n.h"
#include "options.h"
#include "pkglue.h"

struct cmp_help_context_s {
    PKT_signature *sig;
    MD_HANDLE md;
};


static int do_check( PKT_public_key *pk, PKT_signature *sig, MD_HANDLE digest,
		     int *r_expired, int *r_revoked, PKT_public_key *ret_pk);

/****************
 * Check the signature which is contained in SIG.
 * The MD_HANDLE should be currently open, so that this function
 * is able to append some data, before finalizing the digest.
 */
int
signature_check( PKT_signature *sig, MD_HANDLE digest )
{
    return signature_check2( sig, digest, NULL, NULL, NULL, NULL );
}

int
signature_check2( PKT_signature *sig, MD_HANDLE digest, u32 *r_expiredate, 
		  int *r_expired, int *r_revoked, PKT_public_key *ret_pk )
{
    PKT_public_key *pk = xcalloc (1, sizeof *pk );
    int rc=0;

    /* Sanity check that the md has a context for the hash that the
       sig is expecting.  This can happen if a onepass sig header does
       not match the actual sig, and also if the clearsign "Hash:"
       header is missing or does not match the actual sig. */

    if(!gcry_md_is_enabled (digest,sig->digest_algo)) {
        log_info(_("WARNING: signature digest conflict in message\n"));
	rc=GPG_ERR_GENERAL;
    }
    else if( get_pubkey( pk, sig->keyid ) )
	rc = GPG_ERR_NO_PUBKEY;
    else if(!pk->is_valid && !pk->is_primary)
        rc=GPG_ERR_BAD_PUBKEY; /* you cannot have a good sig from an
				 invalid subkey */
    else {
        if (r_expiredate)
	    *r_expiredate = pk->expiredate;
	rc = do_check( pk, sig, digest, r_expired, r_revoked, ret_pk );
    }

    free_public_key( pk );

    if( !rc && sig->sig_class < 2 && is_status_enabled() ) {
	/* This signature id works best with DLP algorithms because
	 * they use a random parameter for every signature.  Instead of
	 * this sig-id we could have also used the hash of the document
	 * and the timestamp, but the drawback of this is, that it is
	 * not possible to sign more than one identical document within
	 * one second.	Some remote batch processing applications might
	 * like this feature here */
	gcry_md_hd_t md;
	u32 a = sig->timestamp;
	int i, nsig = pubkey_get_nsig( sig->pubkey_algo );
	byte *p, *buffer;

	gcry_md_open (&md, GCRY_MD_RMD160, 0);
	gcry_md_putc( digest, sig->pubkey_algo );
	gcry_md_putc( digest, sig->digest_algo );
	gcry_md_putc( digest, (a >> 24) & 0xff );
	gcry_md_putc( digest, (a >> 16) & 0xff );
	gcry_md_putc( digest, (a >>  8) & 0xff );
	gcry_md_putc( digest,  a        & 0xff );
	for(i=0; i < nsig; i++ ) {
	    size_t n;
            unsigned char *tmp;

	    if (gcry_mpi_aprint (GCRYMPI_FMT_USG, &tmp, &n, sig->data[i]))
		BUG();
            
	    gcry_md_write (md, tmp, n);
	    xfree (tmp);
	}
	gcry_md_final( md );
	p = make_radix64_string( gcry_md_read( md, 0 ), 20 );
	buffer = xmalloc ( strlen(p) + 60 );
	sprintf( buffer, "%s %s %lu",
		 p, strtimestamp( sig->timestamp ), (ulong)sig->timestamp );
	write_status_text( STATUS_SIG_ID, buffer );
	xfree (buffer);
	xfree (p);
	gcry_md_close(md);
    }

    return rc;
}


static int
do_check_messages( PKT_public_key *pk, PKT_signature *sig,
                   int *r_expired, int *r_revoked )
{
    u32 cur_time;

    if (r_expired)
      *r_expired = 0;
    if (r_revoked)
      *r_revoked = 0;
    if( pk->version == 4 && pk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E ) {
	log_info(_("key %08lX: this is a PGP generated "
		   "ElGamal key which is NOT secure for signatures!\n"),
 		  (ulong)keyid_from_pk(pk,NULL));
	return GPG_ERR_PUBKEY_ALGO;
    }

    if( pk->timestamp > sig->timestamp ) {
	ulong d = pk->timestamp - sig->timestamp;
	log_info( d==1
	     ? _("public key %08lX is %lu second newer than the signature\n")
	     : _("public key %08lX is %lu seconds newer than the signature\n"),
	        (ulong)keyid_from_pk(pk,NULL),d );
	if( !opt.ignore_time_conflict )
	    return GPG_ERR_TIME_CONFLICT; /* pubkey newer than signature */
    }

    cur_time = make_timestamp();
    if( pk->timestamp > cur_time ) {
	ulong d = pk->timestamp - cur_time;
	log_info( d==1 ? _("key %08lX has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key %08lX has been created %lu seconds "
			   "in future (time warp or clock problem)\n"),
		       (ulong)keyid_from_pk(pk,NULL),d );
	if( !opt.ignore_time_conflict )
	    return GPG_ERR_TIME_CONFLICT;
    }

    if( pk->expiredate && pk->expiredate < cur_time ) {
        char buf[11];
        if (opt.verbose) {
	    u32 tmp_kid[2];

	    keyid_from_pk( pk, tmp_kid );
            log_info(_("NOTE: signature key %08lX expired %s\n"),
                     (ulong)tmp_kid[1], asctimestamp( pk->expiredate ) );
        }
	/* SIGEXPIRED is deprecated.  Use KEYEXPIRED. */
	sprintf(buf,"%lu",(ulong)pk->expiredate);
	write_status_text(STATUS_KEYEXPIRED,buf);
	write_status(STATUS_SIGEXPIRED);
        if (r_expired)
          *r_expired = 1;
    }

    if(pk->is_revoked && r_revoked)
      *r_revoked=1;

    return 0;
}


static int
do_check( PKT_public_key *pk, PKT_signature *sig, MD_HANDLE digest,
	  int *r_expired, int *r_revoked, PKT_public_key *ret_pk )
{
    gcry_mpi_t result = NULL;
    int rc=0;
    struct cmp_help_context_s ctx;

    if( (rc=do_check_messages(pk,sig,r_expired,r_revoked)) )
        return rc;
    if( (rc=gcry_md_test_algo(sig->digest_algo)) )
	return rc;
    if( (rc=gcry_pk_test_algo(sig->pubkey_algo)) )
	return rc;

    /* make sure the digest algo is enabled (in case of a detached
       signature)*/
    gcry_md_enable( digest, sig->digest_algo );

    /* complete the digest */
    if( sig->version >= 4 )
	gcry_md_putc( digest, sig->version );
    gcry_md_putc( digest, sig->sig_class );
    if( sig->version < 4 ) {
	u32 a = sig->timestamp;
	gcry_md_putc( digest, (a >> 24) & 0xff );
	gcry_md_putc( digest, (a >> 16) & 0xff );
	gcry_md_putc( digest, (a >>	8) & 0xff );
	gcry_md_putc( digest,  a	   & 0xff );
    }
    else {
	byte buf[6];
	size_t n;
	gcry_md_putc( digest, sig->pubkey_algo );
	gcry_md_putc( digest, sig->digest_algo );
	if( sig->hashed ) {
	    n = sig->hashed->len;
            gcry_md_putc (digest, (n >> 8) );
            gcry_md_putc (digest,  n       );
	    gcry_md_write (digest, sig->hashed->data, n);
	    n += 6;
	}
	else {
	  /* Two octets for the (empty) length of the hashed
             section. */
          gcry_md_putc (digest, 0);
	  gcry_md_putc (digest, 0);
	  n = 6;
	}
	/* add some magic */
	buf[0] = sig->version;
	buf[1] = 0xff;
	buf[2] = n >> 24;
	buf[3] = n >> 16;
	buf[4] = n >>  8;
	buf[5] = n;
	gcry_md_write( digest, buf, 6 );
    }
    gcry_md_final (digest);

    result = encode_md_value( pk->pubkey_algo, digest, sig->digest_algo,
			      mpi_get_nbits(pk->pkey[0]), 0 );
    if (!result)
        return GPG_ERR_GENERAL;
    ctx.sig = sig;
    ctx.md = digest;
    rc = pk_verify ( pk->pubkey_algo, result, sig->data, pk->pkey);
    gcry_mpi_release ( result );
    if( (opt.emulate_bugs & EMUBUG_MDENCODE)
	&& gpg_err_code (rc) == GPG_ERR_BAD_SIGNATURE
        && is_ELGAMAL(pk->pubkey_algo) ) {
	/* In this case we try again because old GnuPG versions didn't encode
	 * the hash right. There is no problem with DSA however  */
	result = encode_md_value( pk->pubkey_algo, digest, sig->digest_algo,
			      mpi_get_nbits(pk->pkey[0]), (sig->version < 5) );
        if (!result)
            rc = GPG_ERR_GENERAL;
        else {
            ctx.sig = sig;
            ctx.md = digest;
            rc = pk_verify (pk->pubkey_algo, result, sig->data, pk->pkey);
        }
    }

    if( !rc && sig->flags.unknown_critical ) {
      log_info(_("assuming bad signature from key %08lX "
                 "due to an unknown critical bit\n"),
               (ulong)keyid_from_pk(pk,NULL));
	rc = gpg_error (GPG_ERR_BAD_SIGNATURE);
    }

    if(!rc && ret_pk)
      copy_public_key(ret_pk,pk);

    return rc;
}


static void
hash_uid_node( KBNODE unode, MD_HANDLE md, PKT_signature *sig )
{
    PKT_user_id *uid = unode->pkt->pkt.user_id;

    assert( unode->pkt->pkttype == PKT_USER_ID );
    if( uid->attrib_data ) {
	if( sig->version >=4 ) {
	    byte buf[5];
	    buf[0] = 0xd1;		     /* packet of type 17 */
	    buf[1] = uid->attrib_len >> 24;  /* always use 4 length bytes */
	    buf[2] = uid->attrib_len >> 16;
	    buf[3] = uid->attrib_len >>  8;
	    buf[4] = uid->attrib_len;
	    gcry_md_write( md, buf, 5 );
	}
	gcry_md_write( md, uid->attrib_data, uid->attrib_len );
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

static void
cache_sig_result ( PKT_signature *sig, int result )
{
    if ( !result ) {
        sig->flags.checked = 1;
        sig->flags.valid = 1;
    }
    else if ( gpg_err_code (result) == GPG_ERR_BAD_SIGNATURE ) {
        sig->flags.checked = 1;
        sig->flags.valid = 0;
    }
    else {
        sig->flags.checked = 0;
        sig->flags.valid = 0;
    }
}


/* Check the revocation keys to see if any of them have revoked our
   pk.  sig is the revocation sig.  pk is the key it is on.  This code
   will need to be modified if gpg ever becomes multi-threaded.  Note
   that this guarantees that a designated revocation sig will never be
   considered valid unless it is actually valid, as well as being
   issued by a revocation key in a valid direct signature.  Note that
   this is written so that a revoked revoker can still issue
   revocations: i.e. If A revokes B, but A is revoked, B is still
   revoked.  I'm not completely convinced this is the proper behavior,
   but it matches how PGP does it. -dms */

/* Returns 0 if sig is valid (i.e. pk is revoked), non-0 if not
   revoked */
int
check_revocation_keys(PKT_public_key *pk,PKT_signature *sig)
{
  static int busy=0;
  int i,rc=GPG_ERR_GENERAL;

  assert(IS_KEY_REV(sig));
  assert((sig->keyid[0]!=pk->keyid[0]) || (sig->keyid[0]!=pk->keyid[1]));

  if(busy)
    {
      /* return -1 (i.e. not revoked), but mark the pk as uncacheable
         as we don't really know its revocation status until it is
         checked directly. */

      pk->dont_cache=1;
      return rc;
    }

  busy=1;

  /*  printf("looking at %08lX with a sig from %08lX\n",(ulong)pk->keyid[1],
      (ulong)sig->keyid[1]); */

  /* is the issuer of the sig one of our revokers? */
  if( !pk->revkey && pk->numrevkeys )
     BUG();
  else
      for(i=0;i<pk->numrevkeys;i++)
	{
          u32 keyid[2];
    
          keyid_from_fingerprint(pk->revkey[i].fpr,MAX_FINGERPRINT_LEN,keyid);
    
          if(keyid[0]==sig->keyid[0] && keyid[1]==sig->keyid[1])
	    {
              gcry_md_hd_t md;
    
              gcry_md_open (&md, sig->digest_algo,0);
              hash_public_key(md,pk);
              rc=signature_check(sig,md);
	      cache_sig_result(sig,rc);
	      break;
	    }
	}

  busy=0;

  return rc;
} 

/****************
 * check the signature pointed to by NODE. This is a key signature.
 * If the function detects a self-signature, it uses the PK from
 * ROOT and does not read any public key.
 */
int
check_key_signature( KBNODE root, KBNODE node, int *is_selfsig )
{
    return check_key_signature2(root, node, NULL, NULL, is_selfsig, NULL, NULL);
}

/* If check_pk is set, then use it to check the signature in node
   rather than getting it from root or the keydb.  If ret_pk is set,
   fill in the public key that was used to verify the signature.
   ret_pk is only meaningful when the verification was successful. */
/* TODO: add r_revoked here as well.  It has the same problems as
   r_expiredate and r_expired and the cache. */
int
check_key_signature2( KBNODE root, KBNODE node, PKT_public_key *check_pk,
		      PKT_public_key *ret_pk, int *is_selfsig,
                      u32 *r_expiredate, int *r_expired )
{
    MD_HANDLE md;
    PKT_public_key *pk;
    PKT_signature *sig;
    int algo;
    int rc;

    if( is_selfsig )
	*is_selfsig = 0;
    if( r_expiredate )
        *r_expiredate = 0;
    if( r_expired )
        *r_expired = 0;
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( root->pkt->pkttype == PKT_PUBLIC_KEY );

    pk = root->pkt->pkt.public_key;
    sig = node->pkt->pkt.signature;
    algo = sig->digest_algo;

    /* check whether we have cached the result of a previous signature check.*/
    if ( !opt.no_sig_cache ) {
        if (sig->flags.checked) { /*cached status available*/
	    if( is_selfsig ) {	
		u32 keyid[2];	

		keyid_from_pk( pk, keyid );
		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    *is_selfsig = 1;
	    }
	    /* BUG: This is wrong for non-self-sigs. Needs to be the
	       actual pk */
	    if((rc=do_check_messages(pk,sig,r_expired,NULL)))
	      return rc;
            return sig->flags.valid? 0 : gpg_error (GPG_ERR_BAD_SIGNATURE);
        }
    }

    if( (rc=gcry_md_test_algo(algo)) )
      return rc;

    if( sig->sig_class == 0x20 ) { /* key revocation */
        u32 keyid[2];	
	keyid_from_pk( pk, keyid );

	/* is it a designated revoker? */
        if(keyid[0]!=sig->keyid[0] || keyid[1]!=sig->keyid[1])
	  rc=check_revocation_keys(pk,sig);
	else
	  {
	    gcry_md_open (&md, algo, 0 );
	    hash_public_key( md, pk );
	    rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
	    cache_sig_result ( sig, rc );
	    gcry_md_close(md);
	  }
    }
    else if( sig->sig_class == 0x28 ) { /* subkey revocation */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    gcry_md_open (&md, algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
            cache_sig_result ( sig, rc );
	    gcry_md_close(md);
	}
	else {
            if (opt.verbose)
                log_info (_("key %08lX: no subkey for subkey "
			    "revocation signature\n"),
                          (ulong)keyid_from_pk (pk, NULL));
	    rc = GPG_ERR_SIG_CLASS;
	}
    }
    else if( sig->sig_class == 0x18 ) { /* key binding */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    if( is_selfsig ) {	/* does this make sense????? */
		u32 keyid[2];	/* it should always be a selfsig */

		keyid_from_pk( pk, keyid );
		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    *is_selfsig = 1;
	    }
	    gcry_md_open (&md, algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
            cache_sig_result ( sig, rc );
	    gcry_md_close(md);
	}
	else {
            if (opt.verbose)
                log_info(_("key %08lX: no subkey for subkey "
			   "binding signature\n"),
			 (ulong)keyid_from_pk (pk, NULL));
	    rc = GPG_ERR_SIG_CLASS;
	}
    }
    else if( sig->sig_class == 0x1f ) { /* direct key signature */
	gcry_md_open (&md, algo, 0 );
	hash_public_key( md, pk );
	rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
        cache_sig_result ( sig, rc );
	gcry_md_close(md);
    }
    else { /* all other classes */
	KBNODE unode = find_prev_kbnode( root, node, PKT_USER_ID );

	if( unode ) {
	    u32 keyid[2];

	    keyid_from_pk( pk, keyid );
	    gcry_md_open (&md, algo, 0 );
	    hash_public_key( md, pk );
	    hash_uid_node( unode, md, sig );
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
	      {
		if( is_selfsig )
		  *is_selfsig = 1;
		rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
	      }
	    else if (check_pk)
	      rc=do_check(check_pk,sig,md,r_expired, NULL, ret_pk);
	    else
	      rc = signature_check2( sig, md, r_expiredate, r_expired,
                                     NULL, ret_pk);

            cache_sig_result ( sig, rc );
	    gcry_md_close(md);
	}
	else {
            if (!opt.quiet)
                log_info ("key %08lX: no user ID for key signature packet "
                          "of class %02x\n",
                          (ulong)keyid_from_pk (pk, NULL), sig->sig_class );
	    rc = GPG_ERR_SIG_CLASS;
	}
    }

    return rc;
}
