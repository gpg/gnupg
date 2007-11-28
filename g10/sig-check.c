/* sig-check.c -  Check a signature
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
    PKT_public_key *pk = xmalloc_clear( sizeof *pk );
    int rc=0;

    if( (rc=check_digest_algo(sig->digest_algo)) )
      ; /* we don't have this digest */
    else if((rc=check_pubkey_algo(sig->pubkey_algo)))
      ; /* we don't have this pubkey algo */
    else if(!md_algo_present(digest,sig->digest_algo))
      {
	/* Sanity check that the md has a context for the hash that the
	   sig is expecting.  This can happen if a onepass sig header does
	   not match the actual sig, and also if the clearsign "Hash:"
	   header is missing or does not match the actual sig. */

        log_info(_("WARNING: signature digest conflict in message\n"));
	rc=G10ERR_GENERAL;
      }
    else if( get_pubkey( pk, sig->keyid ) )
	rc = G10ERR_NO_PUBKEY;
    else if(!pk->is_valid && !pk->is_primary)
        rc=G10ERR_BAD_PUBKEY; /* you cannot have a good sig from an
				 invalid subkey */
    else
      {
        if(r_expiredate)
	  *r_expiredate = pk->expiredate;

	rc = do_check( pk, sig, digest, r_expired, r_revoked, ret_pk );

	/* Check the backsig.  This is a 0x19 signature from the
	   subkey on the primary key.  The idea here is that it should
	   not be possible for someone to "steal" subkeys and claim
	   them as their own.  The attacker couldn't actually use the
	   subkey, but they could try and claim ownership of any
	   signaures issued by it. */
	if(rc==0 && !pk->is_primary && pk->backsig<2)
	  {
	    if(pk->backsig==0)
	      {
		log_info(_("WARNING: signing subkey %s is not"
			   " cross-certified\n"),keystr_from_pk(pk));
		log_info(_("please see %s for more information\n"),
			 "http://www.gnupg.org/faq/subkey-cross-certify.html");
		/* --require-cross-certification makes this warning an
                     error.  TODO: change the default to require this
                     after more keys have backsigs. */
		if(opt.flags.require_cross_cert)
		  rc=G10ERR_GENERAL;
	      }
	    else if(pk->backsig==1)
	      {
		log_info(_("WARNING: signing subkey %s has an invalid"
			   " cross-certification\n"),keystr_from_pk(pk));
		rc=G10ERR_GENERAL;
	      }
	  }
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
	MD_HANDLE md;
	u32 a = sig->timestamp;
	int i, nsig = pubkey_get_nsig( sig->pubkey_algo );
	byte *p, *buffer;

	md = md_open( DIGEST_ALGO_RMD160, 0);
	md_putc( digest, sig->pubkey_algo );
	md_putc( digest, sig->digest_algo );
	md_putc( digest, (a >> 24) & 0xff );
	md_putc( digest, (a >> 16) & 0xff );
	md_putc( digest, (a >>	8) & 0xff );
	md_putc( digest,  a	   & 0xff );
	for(i=0; i < nsig; i++ ) {
	    unsigned n = mpi_get_nbits( sig->data[i]);

	    md_putc( md, n>>8);
	    md_putc( md, n );
	    p = mpi_get_buffer( sig->data[i], &n, NULL );
	    md_write( md, p, n );
	    xfree(p);
	}
	md_final( md );
	p = make_radix64_string( md_read( md, 0 ), 20 );
	buffer = xmalloc( strlen(p) + 60 );
	sprintf( buffer, "%s %s %lu",
		 p, strtimestamp( sig->timestamp ), (ulong)sig->timestamp );
	write_status_text( STATUS_SIG_ID, buffer );
	xfree(buffer);
	xfree(p);
	md_close(md);
    }

    return rc;
}


static int
do_check_messages( PKT_public_key *pk, PKT_signature *sig,
		   int *r_expired, int *r_revoked )
{
    u32 cur_time;

    if(r_expired)
      *r_expired = 0;
    if(r_revoked)
      *r_revoked = 0;

    if( pk->timestamp > sig->timestamp )
      {
	ulong d = pk->timestamp - sig->timestamp;
	log_info(d==1
		 ?_("public key %s is %lu second newer than the signature\n")
		 :_("public key %s is %lu seconds newer than the signature\n"),
		 keystr_from_pk(pk),d );
	if( !opt.ignore_time_conflict )
	  return G10ERR_TIME_CONFLICT; /* pubkey newer than signature */
      }

    cur_time = make_timestamp();
    if( pk->timestamp > cur_time )
      {
	ulong d = pk->timestamp - cur_time;
	log_info( d==1
		  ? _("key %s was created %lu second"
		      " in the future (time warp or clock problem)\n")
		  : _("key %s was created %lu seconds"
		      " in the future (time warp or clock problem)\n"),
		  keystr_from_pk(pk),d );
	if( !opt.ignore_time_conflict )
	  return G10ERR_TIME_CONFLICT;
      }

    if( pk->expiredate && pk->expiredate < cur_time ) {
        char buf[11];
        if (opt.verbose)
	  log_info(_("NOTE: signature key %s expired %s\n"),
		   keystr_from_pk(pk), asctimestamp( pk->expiredate ) );
	/* SIGEXPIRED is deprecated.  Use KEYEXPIRED. */
	sprintf(buf,"%lu",(ulong)pk->expiredate);
	write_status_text(STATUS_KEYEXPIRED,buf);
	write_status(STATUS_SIGEXPIRED);
	if(r_expired)
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
    MPI result = NULL;
    int rc=0;
    struct cmp_help_context_s ctx;

    if( (rc=do_check_messages(pk,sig,r_expired,r_revoked)) )
        return rc;

    /* make sure the digest algo is enabled (in case of a detached signature)*/
    md_enable( digest, sig->digest_algo );

    /* complete the digest */
    if( sig->version >= 4 )
	md_putc( digest, sig->version );
    md_putc( digest, sig->sig_class );
    if( sig->version < 4 ) {
	u32 a = sig->timestamp;
	md_putc( digest, (a >> 24) & 0xff );
	md_putc( digest, (a >> 16) & 0xff );
	md_putc( digest, (a >>	8) & 0xff );
	md_putc( digest,  a	   & 0xff );
    }
    else {
	byte buf[6];
	size_t n;
	md_putc( digest, sig->pubkey_algo );
	md_putc( digest, sig->digest_algo );
	if( sig->hashed ) {
	    n = sig->hashed->len;
            md_putc (digest, (n >> 8) );
            md_putc (digest,  n       );
	    md_write (digest, sig->hashed->data, n);
	    n += 6;
	}
	else {
	  /* Two octets for the (empty) length of the hashed
             section. */
          md_putc (digest, 0);
	  md_putc (digest, 0);
	  n = 6;
	}
	/* add some magic */
	buf[0] = sig->version;
	buf[1] = 0xff;
	buf[2] = n >> 24;
	buf[3] = n >> 16;
	buf[4] = n >>  8;
	buf[5] = n;
	md_write( digest, buf, 6 );
    }
    md_final( digest );

    result = encode_md_value( pk, NULL, digest, sig->digest_algo );
    if (!result)
        return G10ERR_GENERAL;
    ctx.sig = sig;
    ctx.md = digest;
    rc = pubkey_verify( pk->pubkey_algo, result, sig->data, pk->pkey );
    mpi_free( result );

    if(rc==G10ERR_BAD_SIGN && is_RSA(pk->pubkey_algo)
       && sig->digest_algo==DIGEST_ALGO_SHA224)
      {
	/* This code is to work around a SHA-224 problem.  RFC-4880
	   and the drafts leading up to it were published with the
	   wrong DER prefix for SHA-224.  Unfortunately, GPG pre-1.4.8
	   used this wrong prefix.  What this code does is take all
	   bad RSA signatures that use SHA-224, and re-checks them
	   using the old, incorrect, DER prefix.  Someday we should
	   remove this code, and when we do remove it, pkcs1_encode_md
	   can be made into a static function again.  Note that GPG2
	   does not have this issue as it uses libgcrypt, which is
	   being fixed while it is still a development version. */

	/* The incorrect SHA-224 DER prefix used in pre-1.4.8 */
	static byte asn[]={0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
			   0x00, 0x04, 0x20};

	result=pkcs1_encode_md(digest,DIGEST_ALGO_SHA224,28,
			       mpi_get_nbits(pk->pkey[0]),asn,DIM(asn));

	rc=pubkey_verify(pk->pubkey_algo,result,sig->data,pk->pkey);
	mpi_free(result);
      }

    if( !rc && sig->flags.unknown_critical )
      {
	log_info(_("assuming bad signature from key %s"
		   " due to an unknown critical bit\n"),keystr_from_pk(pk));
	rc = G10ERR_BAD_SIGN;
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
	    md_write( md, buf, 5 );
	}
	md_write( md, uid->attrib_data, uid->attrib_len );
    }
    else {
	if( sig->version >=4 ) {
	    byte buf[5];
	    buf[0] = 0xb4;	      /* indicates a userid packet */
	    buf[1] = uid->len >> 24;  /* always use 4 length bytes */
	    buf[2] = uid->len >> 16;
	    buf[3] = uid->len >>  8;
	    buf[4] = uid->len;
	    md_write( md, buf, 5 );
	}
	md_write( md, uid->name, uid->len );
    }
}

static void
cache_sig_result ( PKT_signature *sig, int result )
{
    if ( !result ) {
        sig->flags.checked = 1;
        sig->flags.valid = 1;
    }
    else if ( result == G10ERR_BAD_SIGN ) {
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
   issued by a revocation key in a valid direct signature.  Note also
   that this is written so that a revoked revoker can still issue
   revocations: i.e. If A revokes B, but A is revoked, B is still
   revoked.  I'm not completely convinced this is the proper behavior,
   but it matches how PGP does it. -dms */

/* Returns 0 if sig is valid (i.e. pk is revoked), non-0 if not
   revoked.  It is important that G10ERR_NO_PUBKEY is only returned
   when a revocation signature is from a valid revocation key
   designated in a revkey subpacket, but the revocation key itself
   isn't present. */
int
check_revocation_keys(PKT_public_key *pk,PKT_signature *sig)
{
  static int busy=0;
  int i,rc=G10ERR_GENERAL;

  assert(IS_KEY_REV(sig));
  assert((sig->keyid[0]!=pk->keyid[0]) || (sig->keyid[0]!=pk->keyid[1]));

  if(busy)
    {
      /* return an error (i.e. not revoked), but mark the pk as
         uncacheable as we don't really know its revocation status
         until it is checked directly. */

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
              MD_HANDLE md;
    
              md=md_open(sig->digest_algo,0);
              hash_public_key(md,pk);
              rc=signature_check(sig,md);
	      cache_sig_result(sig,rc);
	      break;
	    }
	}

  busy=0;

  return rc;
} 

/* Backsigs (0x19) have the same format as binding sigs (0x18), but
   this function is simpler than check_key_signature in a few ways.
   For example, there is no support for expiring backsigs since it is
   questionable what such a thing actually means.  Note also that the
   sig cache check here, unlike other sig caches in GnuPG, is not
   persistent. */
int
check_backsig(PKT_public_key *main_pk,PKT_public_key *sub_pk,
	      PKT_signature *backsig)
{
  MD_HANDLE md;
  int rc;

  if(!opt.no_sig_cache && backsig->flags.checked)
    {
      if((rc=check_digest_algo(backsig->digest_algo)))
	return rc;

      return backsig->flags.valid? 0 : G10ERR_BAD_SIGN;
    }

  md=md_open(backsig->digest_algo,0);
  hash_public_key(md,main_pk);
  hash_public_key(md,sub_pk);
  rc=do_check(sub_pk,backsig,md,NULL,NULL,NULL);
  cache_sig_result(backsig,rc);
  md_close(md);

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
  return check_key_signature2(root, node, NULL, NULL, is_selfsig, NULL, NULL );
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

    /* Check whether we have cached the result of a previous signature
       check.  Note that we may no longer have the pubkey or hash
       needed to verify a sig, but can still use the cached value.  A
       cache refresh detects and clears these cases. */
    if ( !opt.no_sig_cache ) {
        if (sig->flags.checked) { /*cached status available*/
	    if( is_selfsig ) {	
		u32 keyid[2];	

		keyid_from_pk( pk, keyid );
		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    *is_selfsig = 1;
	    }
	    /* BUG: This is wrong for non-self-sigs.. needs to be the
	       actual pk */
	    if((rc=do_check_messages(pk,sig,r_expired,NULL)))
	      return rc;
            return sig->flags.valid? 0 : G10ERR_BAD_SIGN;
        }
    }

    if( (rc=check_pubkey_algo(sig->pubkey_algo)) )
	return rc;
    if( (rc=check_digest_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x20 ) { /* key revocation */
        u32 keyid[2];	
	keyid_from_pk( pk, keyid );

	/* is it a designated revoker? */
        if(keyid[0]!=sig->keyid[0] || keyid[1]!=sig->keyid[1])
	  rc=check_revocation_keys(pk,sig);
	else
	  {
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
	    cache_sig_result ( sig, rc );
	    md_close(md);
	  }
    }
    else if( sig->sig_class == 0x28 ) { /* subkey revocation */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
            cache_sig_result ( sig, rc );
	    md_close(md);
	}
	else
	  {
            if (opt.verbose)
	      log_info (_("key %s: no subkey for subkey"
			  " revocation signature\n"),keystr_from_pk(pk));
	    rc = G10ERR_SIG_CLASS;
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
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
            cache_sig_result ( sig, rc );
	    md_close(md);
	}
	else
	  {
            if (opt.verbose)
	      log_info(_("key %s: no subkey for subkey"
			 " binding signature\n"),keystr_from_pk(pk));
	    rc = G10ERR_SIG_CLASS;
	  }
    }
    else if( sig->sig_class == 0x1f ) { /* direct key signature */
	md = md_open( algo, 0 );
	hash_public_key( md, pk );
	rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
        cache_sig_result ( sig, rc );
	md_close(md);
    }
    else { /* all other classes */
	KBNODE unode = find_prev_kbnode( root, node, PKT_USER_ID );

	if( unode ) {
	    u32 keyid[2];

	    keyid_from_pk( pk, keyid );
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_uid_node( unode, md, sig );
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
	      {
		if( is_selfsig )
		  *is_selfsig = 1;
		rc = do_check( pk, sig, md, r_expired, NULL, ret_pk );
	      }
	    else if (check_pk)
	      rc=do_check(check_pk,sig,md,r_expired,NULL,ret_pk);
	    else
	      rc=signature_check2(sig,md,r_expiredate,r_expired,NULL,ret_pk);

            cache_sig_result ( sig, rc );
	    md_close(md);
	}
	else
	  {
            if (!opt.quiet)
	      log_info ("key %s: no user ID for key signature packet"
			" of class %02x\n",keystr_from_pk(pk),sig->sig_class);
	    rc = G10ERR_SIG_CLASS;
	  }
    }

    return rc;
}
