/* sig-check.c -  Check a signature
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2004, 2006 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH
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

#include "gpg.h"
#include "util.h"
#include "packet.h"
#include "keydb.h"
#include "main.h"
#include "status.h"
#include "i18n.h"
#include "options.h"
#include "pkglue.h"
#include "host2net.h"

/* Check a signature.  This is shorthand for check_signature2 with
   the unnamed arguments passed as NULL.  */
int
check_signature (PKT_signature *sig, gcry_md_hd_t digest)
{
    return check_signature2 (sig, digest, NULL, NULL, NULL, NULL);
}


/* Check a signature.
 *
 * Looks up the public key that created the signature (SIG->KEYID)
 * from the key db.  Makes sure that the signature is valid (it was
 * not created prior to the key, the public key was created in the
 * past, and the signature does not include any unsupported critical
 * features), finishes computing the hash of the signature data, and
 * checks that the signature verifies the digest.  If the key that
 * generated the signature is a subkey, this function also verifies
 * that there is a valid backsig from the subkey to the primary key.
 * Finally, if status fd is enabled and the signature class is 0x00 or
 * 0x01, then a STATUS_SIG_ID is emitted on the status fd.
 *
 * SIG is the signature to check.
 *
 * DIGEST contains a valid hash context that already includes the
 * signed data.  This function adds the relevant meta-data from the
 * signature packet to compute the final hash.  (See Section 5.2 of
 * RFC 4880: "The concatenation of the data being signed and the
 * signature data from the version number through the hashed subpacket
 * data (inclusive) is hashed.")
 *
 * If R_EXPIREDATE is not NULL, R_EXPIREDATE is set to the key's
 * expiry.
 *
 * If R_EXPIRED is not NULL, *R_EXPIRED is set to 1 if PK has expired
 * (0 otherwise).  Note: PK being expired does not cause this function
 * to fail.
 *
 * If R_REVOKED is not NULL, *R_REVOKED is set to 1 if PK has been
 * revoked (0 otherwise).  Note: PK being revoked does not cause this
 * function to fail.
 *
 * If PK is not NULL, the public key is saved in *PK on success.
 *
 * Returns 0 on success.  An error code otherwise.  */
int
check_signature2 (PKT_signature *sig, gcry_md_hd_t digest, u32 *r_expiredate,
		  int *r_expired, int *r_revoked, PKT_public_key *pk )
{
    int rc=0;
    int pk_internal;

    if (pk)
      pk_internal = 0;
    else
      {
	pk_internal = 1;
	pk = xmalloc_clear( sizeof *pk );
      }

    if ( (rc=openpgp_md_test_algo(sig->digest_algo)) )
      ; /* We don't have this digest. */
    else if ((rc=openpgp_pk_test_algo(sig->pubkey_algo)))
      ; /* We don't have this pubkey algo. */
    else if (!gcry_md_is_enabled (digest,sig->digest_algo))
      {
	/* Sanity check that the md has a context for the hash that the
	   sig is expecting.  This can happen if a onepass sig header does
	   not match the actual sig, and also if the clearsign "Hash:"
	   header is missing or does not match the actual sig. */

        log_info(_("WARNING: signature digest conflict in message\n"));
	rc = GPG_ERR_GENERAL;
      }
    else if( get_pubkey( pk, sig->keyid ) )
	rc = GPG_ERR_NO_PUBKEY;
    else if(!pk->flags.valid && !pk->flags.primary)
      {
        /* You cannot have a good sig from an invalid subkey.  */
        rc = GPG_ERR_BAD_PUBKEY;
      }
    else
      {
        if(r_expiredate)
	  *r_expiredate = pk->expiredate;

	rc = check_signature_end (pk, sig, digest, r_expired, r_revoked, NULL);

	/* Check the backsig.  This is a 0x19 signature from the
	   subkey on the primary key.  The idea here is that it should
	   not be possible for someone to "steal" subkeys and claim
	   them as their own.  The attacker couldn't actually use the
	   subkey, but they could try and claim ownership of any
	   signatures issued by it. */
	if(rc==0 && !pk->flags.primary && pk->flags.backsig < 2)
	  {
	    if (!pk->flags.backsig)
	      {
		log_info(_("WARNING: signing subkey %s is not"
			   " cross-certified\n"),keystr_from_pk(pk));
		log_info(_("please see %s for more information\n"),
			 "https://gnupg.org/faq/subkey-cross-certify.html");
		/* --require-cross-certification makes this warning an
                     error.  TODO: change the default to require this
                     after more keys have backsigs. */
		if(opt.flags.require_cross_cert)
		  rc = GPG_ERR_GENERAL;
	      }
	    else if(pk->flags.backsig == 1)
	      {
		log_info(_("WARNING: signing subkey %s has an invalid"
			   " cross-certification\n"),keystr_from_pk(pk));
		rc = GPG_ERR_GENERAL;
	      }
	  }
      }

    if (pk_internal || rc)
      {
	release_public_key_parts (pk);
	if (pk_internal)
	  xfree (pk);
	else
	  /* Be very sure that the caller doesn't try to use *PK.  */
	  memset (pk, 0, sizeof (*pk));
      }

    if( !rc && sig->sig_class < 2 && is_status_enabled() ) {
	/* This signature id works best with DLP algorithms because
	 * they use a random parameter for every signature.  Instead of
	 * this sig-id we could have also used the hash of the document
	 * and the timestamp, but the drawback of this is, that it is
	 * not possible to sign more than one identical document within
	 * one second.	Some remote batch processing applications might
	 * like this feature here.
         *
         * Note that before 2.0.10, we used RIPE-MD160 for the hash
         * and accidentally didn't include the timestamp and algorithm
         * information in the hash.  Given that this feature is not
         * commonly used and that a replay attacks detection should
         * not solely be based on this feature (because it does not
         * work with RSA), we take the freedom and switch to SHA-1
         * with 2.0.10 to take advantage of hardware supported SHA-1
         * implementations.  We also include the missing information
         * in the hash.  Note also the SIG_ID as computed by gpg 1.x
         * and gpg 2.x didn't matched either because 2.x used to print
         * MPIs not in PGP format.  */
	u32 a = sig->timestamp;
	int nsig = pubkey_get_nsig( sig->pubkey_algo );
	unsigned char *p, *buffer;
        size_t n, nbytes;
        int i;
        char hashbuf[20];

        nbytes = 6;
	for (i=0; i < nsig; i++ )
          {
	    if (gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &n, sig->data[i]))
              BUG();
            nbytes += n;
          }

        /* Make buffer large enough to be later used as output buffer.  */
        if (nbytes < 100)
          nbytes = 100;
        nbytes += 10;  /* Safety margin.  */

        /* Fill and hash buffer.  */
        buffer = p = xmalloc (nbytes);
	*p++ = sig->pubkey_algo;
	*p++ = sig->digest_algo;
	*p++ = (a >> 24) & 0xff;
	*p++ = (a >> 16) & 0xff;
	*p++ = (a >>  8) & 0xff;
	*p++ =  a & 0xff;
        nbytes -= 6;
	for (i=0; i < nsig; i++ )
          {
	    if (gcry_mpi_print (GCRYMPI_FMT_PGP, p, nbytes, &n, sig->data[i]))
              BUG();
            p += n;
            nbytes -= n;
          }
        gcry_md_hash_buffer (GCRY_MD_SHA1, hashbuf, buffer, p-buffer);

	p = make_radix64_string (hashbuf, 20);
	sprintf (buffer, "%s %s %lu",
		 p, strtimestamp (sig->timestamp), (ulong)sig->timestamp);
	xfree (p);
	write_status_text (STATUS_SIG_ID, buffer);
	xfree (buffer);
    }

    return rc;
}


/* The signature SIG was generated with the public key PK.  Check
 * whether the signature is valid in the following sense:
 *
 *   - Make sure the public key was created before the signature was
 *     generated.
 *
 *   - Make sure the public key was created in the past
 *
 *   - Check whether PK has expired (set *R_EXPIRED to 1 if so and 0
 *     otherwise)
 *
 *   - Check whether PK has been revoked (set *R_REVOKED to 1 if so
 *     and 0 otherwise).
 *
 * If either of the first two tests fail, returns an error code.
 * Otherwise returns 0.  (Thus, this function doesn't fail if the
 * public key is expired or revoked.)  */
static int
check_signature_metadata_validity (PKT_public_key *pk, PKT_signature *sig,
				   int *r_expired, int *r_revoked)
{
    u32 cur_time;

    if(r_expired)
      *r_expired = 0;
    if(r_revoked)
      *r_revoked = 0;

    if( pk->timestamp > sig->timestamp )
      {
	ulong d = pk->timestamp - sig->timestamp;
        if ( d < 86400 )
          {
            log_info
              (ngettext
               ("public key %s is %lu second newer than the signature\n",
                "public key %s is %lu seconds newer than the signature\n",
                d), keystr_from_pk (pk), d);
          }
        else
          {
            d /= 86400;
            log_info
              (ngettext
               ("public key %s is %lu day newer than the signature\n",
                "public key %s is %lu days newer than the signature\n",
                d), keystr_from_pk (pk), d);
          }
	if (!opt.ignore_time_conflict)
	  return GPG_ERR_TIME_CONFLICT; /* pubkey newer than signature.  */
      }

    cur_time = make_timestamp();
    if( pk->timestamp > cur_time )
      {
	ulong d = pk->timestamp - cur_time;
        if (d < 86400)
          {
            log_info (ngettext("key %s was created %lu second"
                               " in the future (time warp or clock problem)\n",
                               "key %s was created %lu seconds"
                               " in the future (time warp or clock problem)\n",
                               d), keystr_from_pk (pk), d);
          }
        else
          {
            d /= 86400;
            log_info (ngettext("key %s was created %lu day"
                               " in the future (time warp or clock problem)\n",
                               "key %s was created %lu days"
                               " in the future (time warp or clock problem)\n",
                               d), keystr_from_pk (pk), d);
          }
	if (!opt.ignore_time_conflict)
	  return GPG_ERR_TIME_CONFLICT;
      }

    /* Check whether the key has expired.  We check the has_expired
       flag which is set after a full evaluation of the key (getkey.c)
       as well as a simple compare to the current time in case the
       merge has for whatever reasons not been done.  */
    if( pk->has_expired || (pk->expiredate && pk->expiredate < cur_time)) {
        char buf[11];
        if (opt.verbose)
	  log_info(_("Note: signature key %s expired %s\n"),
		   keystr_from_pk(pk), asctimestamp( pk->expiredate ) );
	sprintf(buf,"%lu",(ulong)pk->expiredate);
	write_status_text(STATUS_KEYEXPIRED,buf);
	if(r_expired)
	  *r_expired = 1;
    }

    if (pk->flags.revoked)
      {
        if (opt.verbose)
	  log_info (_("Note: signature key %s has been revoked\n"),
                    keystr_from_pk(pk));
        if (r_revoked)
          *r_revoked=1;
      }

    return 0;
}


/* Finish generating a signature and check it.  Concretely: make sure
 * that the signature is valid (it was not created prior to the key,
 * the public key was created in the past, and the signature does not
 * include any unsupported critical features), finish computing the
 * digest by adding the relevant data from the signature packet, and
 * check that the signature verifies the digest.
 *
 * DIGEST contains a hash context, which has already hashed the signed
 * data.  This function adds the relevant meta-data from the signature
 * packet to compute the final hash.  (See Section 5.2 of RFC 4880:
 * "The concatenation of the data being signed and the signature data
 * from the version number through the hashed subpacket data
 * (inclusive) is hashed.")
 *
 * SIG is the signature to check.
 *
 * PK is the public key used to generate the signature.
 *
 * If R_EXPIRED is not NULL, *R_EXPIRED is set to 1 if PK has expired
 * (0 otherwise).  Note: PK being expired does not cause this function
 * to fail.
 *
 * If R_REVOKED is not NULL, *R_REVOKED is set to 1 if PK has been
 * revoked (0 otherwise).  Note: PK being revoked does not cause this
 * function to fail.
 *
 * If RET_PK is not NULL, PK is copied into RET_PK on success.
 *
 * Returns 0 on success.  An error code other.  */
int
check_signature_end (PKT_public_key *pk, PKT_signature *sig,
		     gcry_md_hd_t digest,
		     int *r_expired, int *r_revoked, PKT_public_key *ret_pk)
{
    int rc = 0;

    if ((rc = check_signature_metadata_validity (pk, sig,
						 r_expired, r_revoked)))
        return rc;

    if ((rc = check_signature_only_end (pk, sig, digest)))
      return rc;

    if(!rc && ret_pk)
      copy_public_key(ret_pk,pk);

    return rc;
}

int
check_signature_only_end (PKT_public_key *pk, PKT_signature *sig,
                          gcry_md_hd_t digest)
{
    gcry_mpi_t result = NULL;
    int rc = 0;
    const struct weakhash *weak;

    if (!opt.flags.allow_weak_digest_algos)
      for (weak = opt.weak_digests; weak; weak = weak->next)
        if (sig->digest_algo == weak->algo)
          {
            print_digest_rejected_note(sig->digest_algo);
            return GPG_ERR_DIGEST_ALGO;
          }

    /* Make sure the digest algo is enabled (in case of a detached
       signature).  */
    gcry_md_enable (digest, sig->digest_algo);

    /* Complete the digest. */
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
	/* add some magic per Section 5.2.4 of RFC 4880.  */
	buf[0] = sig->version;
	buf[1] = 0xff;
	buf[2] = n >> 24;
	buf[3] = n >> 16;
	buf[4] = n >>  8;
	buf[5] = n;
	gcry_md_write( digest, buf, 6 );
    }
    gcry_md_final( digest );

    /* Convert the digest to an MPI.  */
    result = encode_md_value (pk, digest, sig->digest_algo );
    if (!result)
        return GPG_ERR_GENERAL;

    /* Verify the signature.  */
    rc = pk_verify( pk->pubkey_algo, result, sig->data, pk->pkey );
    gcry_mpi_release (result);

    if( !rc && sig->flags.unknown_critical )
      {
	log_info(_("assuming bad signature from key %s"
		   " due to an unknown critical bit\n"),keystr_from_pk(pk));
	rc = GPG_ERR_BAD_SIGNATURE;
      }

    return rc;
}


/* Add a uid node to a hash context.  See section 5.2.4, paragraph 4
   of RFC 4880.  */
void
hash_uid_node( KBNODE unode, gcry_md_hd_t md, PKT_signature *sig )
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


/* SIG is a key revocation signature.  Check if this signature was
 * generated by any of the public key PK's designated revokers.
 *
 *   PK is the public key that SIG allegedly revokes.
 *
 *   SIG is the revocation signature to check.
 *
 * This function avoids infinite recursion, which can happen if two
 * keys are designed revokers for each other and they revoke each
 * other.  This is done by observing that if a key A is revoked by key
 * B we still consider the revocation to be valid even if B is
 * revoked.  Thus, we don't need to determine whether B is revoked to
 * determine whether A has been revoked by B, we just need to check
 * the signature.
 *
 * Returns 0 if sig is valid (i.e. pk is revoked), non-0 if not
 * revoked.  We are careful to make sure that GPG_ERR_NO_PUBKEY is
 * only returned when a revocation signature is from a valid
 * revocation key designated in a revkey subpacket, but the revocation
 * key itself isn't present.
 *
 * XXX: This code will need to be modified if gpg ever becomes
 * multi-threaded.  Note that this guarantees that a designated
 * revocation sig will never be considered valid unless it is actually
 * valid, as well as being issued by a revocation key in a valid
 * direct signature.  Note also that this is written so that a revoked
 * revoker can still issue revocations: i.e. If A revokes B, but A is
 * revoked, B is still revoked.  I'm not completely convinced this is
 * the proper behavior, but it matches how PGP does it. -dms */
int
check_revocation_keys (PKT_public_key *pk, PKT_signature *sig)
{
  static int busy=0;
  int i;
  int rc = GPG_ERR_GENERAL;

  assert(IS_KEY_REV(sig));
  assert((sig->keyid[0]!=pk->keyid[0]) || (sig->keyid[0]!=pk->keyid[1]));

  /* Avoid infinite recursion.  Consider the following:
   *
   *   - We want to check if A is revoked.
   *
   *   - C is a designated revoker for B and has revoked B.
   *
   *   - B is a designated revoker for A and has revoked A.
   *
   * When checking if A is revoked (in merge_selfsigs_main), we
   * observe that A has a designed revoker.  As such, we call this
   * function.  This function sees that there is a valid revocation
   * signature, which is signed by B.  It then calls check_signature()
   * to verify that the signature is good.  To check the sig, we need
   * to lookup B.  Looking up B means calling merge_selfsigs_main,
   * which checks whether B is revoked, which calls this function to
   * see if B was revoked by some key.
   *
   * In this case, the added level of indirection doesn't hurt.  It
   * just means a bit more work.  However, if C == A, then we'd end up
   * in a loop.  But, it doesn't make sense to look up C anyways: even
   * if B is revoked, we conservatively consider a valid revocation
   * signed by B to revoke A.  Since this is the only place where this
   * type of recursion can occur, we simply cause this function to
   * fail if it is entered recursively.  */
  if (busy)
    {
      /* Return an error (i.e. not revoked), but mark the pk as
         uncacheable as we don't really know its revocation status
         until it is checked directly.  */
      pk->flags.dont_cache = 1;
      return rc;
    }

  busy=1;

  /*  es_printf("looking at %08lX with a sig from %08lX\n",(ulong)pk->keyid[1],
      (ulong)sig->keyid[1]); */

  /* is the issuer of the sig one of our revokers? */
  if( !pk->revkey && pk->numrevkeys )
     BUG();
  else
      for(i=0;i<pk->numrevkeys;i++)
	{
	  /* The revoker's keyid.  */
          u32 keyid[2];

          keyid_from_fingerprint(pk->revkey[i].fpr,MAX_FINGERPRINT_LEN,keyid);

          if(keyid[0]==sig->keyid[0] && keyid[1]==sig->keyid[1])
	    /* The signature was generated by a designated revoker.
	       Verify the signature.  */
	    {
              gcry_md_hd_t md;

              if (gcry_md_open (&md, sig->digest_algo, 0))
                BUG ();
              hash_public_key(md,pk);
	      /* Note: check_signature only checks that the signature
		 is good.  It does not fail if the key is revoked.  */
              rc=check_signature(sig,md);
	      cache_sig_result(sig,rc);
              gcry_md_close (md);
	      break;
	    }
	}

  busy=0;

  return rc;
}

/* Check that the backsig BACKSIG from the subkey SUB_PK to its
   primary key MAIN_PK is valid.

   Backsigs (0x19) have the same format as binding sigs (0x18), but
   this function is simpler than check_key_signature in a few ways.
   For example, there is no support for expiring backsigs since it is
   questionable what such a thing actually means.  Note also that the
   sig cache check here, unlike other sig caches in GnuPG, is not
   persistent. */
int
check_backsig (PKT_public_key *main_pk,PKT_public_key *sub_pk,
	       PKT_signature *backsig)
{
  gcry_md_hd_t md;
  int rc;

  /* Always check whether the algorithm is available.  Although
     gcry_md_open would throw an error, some libgcrypt versions will
     print a debug message in that case too. */
  if ((rc=openpgp_md_test_algo (backsig->digest_algo)))
    return rc;

  if(!opt.no_sig_cache && backsig->flags.checked)
    return backsig->flags.valid? 0 : gpg_error (GPG_ERR_BAD_SIGNATURE);

  rc = gcry_md_open (&md, backsig->digest_algo,0);
  if (!rc)
    {
      hash_public_key(md,main_pk);
      hash_public_key(md,sub_pk);
      rc = check_signature_end (sub_pk, backsig, md, NULL, NULL, NULL);
      cache_sig_result(backsig,rc);
      gcry_md_close(md);
    }

  return rc;
}


/* Check that a signature over a key is valid.  This is a
 * specialization of check_key_signature2 with the unnamed parameters
 * passed as NULL.  See the documentation for that function for more
 * details.  */
int
check_key_signature (KBNODE root, KBNODE node, int *is_selfsig)
{
  return check_key_signature2 (root, node, NULL, NULL, is_selfsig, NULL, NULL);
}


/* Check that a signature over a key (e.g., a key revocation, key
 * binding, user id certification, etc.) is valid.  If the function
 * detects a self-signature, it uses the public key from the specified
 * key block and does not bother looking up the key specified in the
 * signature packet.
 *
 * ROOT is a keyblock.
 *
 * NODE references a signature packet that appears in the keyblock
 * that should be verified.
 *
 * If CHECK_PK is set, the specified key is sometimes preferred for
 * verifying signatures.  See the implementation for details.
 *
 * If RET_PK is not NULL, the public key that successfully verified
 * the signature is copied into *RET_PK.
 *
 * If IS_SELFSIG is not NULL, *IS_SELFSIG is set to 1 if NODE is a
 * self-signature.
 *
 * If R_EXPIREDATE is not NULL, *R_EXPIREDATE is set to the expiry
 * date.
 *
 * If R_EXPIRED is not NULL, *R_EXPIRED is set to 1 if PK has been
 * expired (0 otherwise).  Note: PK being revoked does not cause this
 * function to fail.
 *
 *
 * If OPT.NO_SIG_CACHE is not set, this function will first check if
 * the result of a previous verification is already cached in the
 * signature packet's data structure.
 *
 * TODO: add r_revoked here as well.  It has the same problems as
 * r_expiredate and r_expired and the cache.  */
int
check_key_signature2 (kbnode_t root, kbnode_t node, PKT_public_key *check_pk,
                      PKT_public_key *ret_pk, int *is_selfsig,
                      u32 *r_expiredate, int *r_expired )
{
  gcry_md_hd_t md;
  PKT_public_key *pk;
  PKT_signature *sig;
  int algo;
  int rc;

  if (is_selfsig)
    *is_selfsig = 0;
  if (r_expiredate)
    *r_expiredate = 0;
  if (r_expired)
    *r_expired = 0;
  assert (node->pkt->pkttype == PKT_SIGNATURE);
  assert (root->pkt->pkttype == PKT_PUBLIC_KEY);

  pk = root->pkt->pkt.public_key;
  sig = node->pkt->pkt.signature;
  algo = sig->digest_algo;

  /* Check whether we have cached the result of a previous signature
     check.  Note that we may no longer have the pubkey or hash
     needed to verify a sig, but can still use the cached value.  A
     cache refresh detects and clears these cases. */
  if ( !opt.no_sig_cache )
    {
      if (sig->flags.checked) /* Cached status available.  */
        {
          if (is_selfsig)
            {
              u32 keyid[2];

              keyid_from_pk (pk, keyid);
              if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1])
                *is_selfsig = 1;
	    }
          /* BUG: This is wrong for non-self-sigs... needs to be the
             actual pk.  */
          rc = check_signature_metadata_validity (pk, sig, r_expired, NULL);
          if (rc)
            return rc;
          return sig->flags.valid? 0 : gpg_error (GPG_ERR_BAD_SIGNATURE);
        }
    }

  rc = openpgp_pk_test_algo(sig->pubkey_algo);
  if (rc)
    return rc;
  rc = openpgp_md_test_algo(algo);
  if (rc)
    return rc;

  if (sig->sig_class == 0x20) /* key revocation */
    {
      u32 keyid[2];
      keyid_from_pk( pk, keyid );

      /* Is it a designated revoker? */
      if (keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1])
        rc = check_revocation_keys (pk, sig);
      else
        {
          if (gcry_md_open (&md, algo, 0))
            BUG ();
          hash_public_key (md, pk);
          rc = check_signature_end (pk, sig, md, r_expired, NULL, ret_pk);
          cache_sig_result (sig, rc);
          gcry_md_close (md);
        }
    }
  else if (sig->sig_class == 0x28) /* subkey revocation */
    {
      kbnode_t snode = find_prev_kbnode (root, node, PKT_PUBLIC_SUBKEY);

      if (snode)
        {
          if (gcry_md_open (&md, algo, 0))
            BUG ();
          hash_public_key (md, pk);
          hash_public_key (md, snode->pkt->pkt.public_key);
          rc = check_signature_end (pk, sig, md, r_expired, NULL, ret_pk);
          cache_sig_result (sig, rc);
          gcry_md_close (md);
	}
      else
        {
          if (opt.verbose)
            log_info (_("key %s: no subkey for subkey"
                        " revocation signature\n"), keystr_from_pk(pk));
          rc = GPG_ERR_SIG_CLASS;
        }
    }
    else if (sig->sig_class == 0x18) /* key binding */
      {
	kbnode_t snode = find_prev_kbnode (root, node, PKT_PUBLIC_SUBKEY);

	if (snode)
          {
	    if (is_selfsig)
              {
                /* Does this make sense?  It should always be a
                   selfsig.  Yes: We can't be sure about this and we
                   need to be able to indicate that it is a selfsig.
                   FIXME: The question is whether we should reject
                   such a signature if it is not a selfsig.  */
		u32 keyid[2];

		keyid_from_pk (pk, keyid);
		if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1])
                  *is_selfsig = 1;
              }
	    if (gcry_md_open (&md, algo, 0))
              BUG ();
	    hash_public_key (md, pk);
	    hash_public_key (md, snode->pkt->pkt.public_key);
	    rc = check_signature_end (pk, sig, md, r_expired, NULL, ret_pk);
            cache_sig_result ( sig, rc );
	    gcry_md_close (md);
          }
	else
	  {
            if (opt.verbose)
	      log_info(_("key %s: no subkey for subkey"
			 " binding signature\n"), keystr_from_pk(pk));
	    rc = GPG_ERR_SIG_CLASS;
	  }
      }
    else if (sig->sig_class == 0x1f) /* direct key signature */
      {
        if (gcry_md_open (&md, algo, 0 ))
          BUG ();
	hash_public_key( md, pk );
	rc = check_signature_end (pk, sig, md, r_expired, NULL, ret_pk);
        cache_sig_result (sig, rc);
	gcry_md_close (md);
      }
    else /* all other classes */
      {
	kbnode_t unode = find_prev_kbnode (root, node, PKT_USER_ID);

	if (unode)
          {
	    u32 keyid[2];

	    keyid_from_pk (pk, keyid);
	    if (gcry_md_open (&md, algo, 0))
              BUG ();
	    hash_public_key (md, pk);
	    hash_uid_node (unode, md, sig);
	    if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1])
	      { /* The primary key is the signing key.  */

		if (is_selfsig)
		  *is_selfsig = 1;
		rc = check_signature_end (pk, sig, md, r_expired, NULL, ret_pk);
	      }
	    else if (check_pk)
              { /* The caller specified a key.  Try that.  */

                rc = check_signature_end (check_pk, sig, md,
                                          r_expired, NULL, ret_pk);
              }
	    else
              { /* Look up the key.  */
                rc = check_signature2 (sig, md, r_expiredate, r_expired,
                                       NULL, ret_pk);
              }

            cache_sig_result  (sig, rc);
	    gcry_md_close (md);
          }
	else
	  {
            if (!opt.quiet)
	      log_info ("key %s: no user ID for key signature packet"
			" of class %02x\n",keystr_from_pk(pk),sig->sig_class);
	    rc = GPG_ERR_SIG_CLASS;
	  }
      }

  return rc;
}


void
sig_print (estream_t fp,
           PKT_public_key *pk, PKT_signature *sig, gpg_error_t sig_status,
           int print_without_key, int extended)
{
  int sigrc;
  int is_rev = sig->sig_class == 0x30;

  switch (gpg_err_code (sig_status))
    {
    case GPG_ERR_NO_VALUE: /* Unknown.  */
      sigrc = ' ';
      break;
    case 0:
      sigrc = '!';
      break;
    case GPG_ERR_BAD_SIGNATURE:
      sigrc = '-';
      break;
    case GPG_ERR_NO_PUBKEY:
    case GPG_ERR_UNUSABLE_PUBKEY:
      sigrc = '?';
      break;
    default:
      sigrc = '%';
      break;
    }
  if (sigrc != '?' || print_without_key)
    {
      es_fprintf (fp, "%s%c%c %c%c%c%c%c%c %s %s",
                  is_rev ? "rev" : "sig", sigrc,
                  (sig->sig_class - 0x10 > 0 &&
                   sig->sig_class - 0x10 <
                   4) ? '0' + sig->sig_class - 0x10 : ' ',
                  sig->flags.exportable ? ' ' : 'L',
                  sig->flags.revocable ? ' ' : 'R',
                  sig->flags.policy_url ? 'P' : ' ',
                  sig->flags.notation ? 'N' : ' ',
                  sig->flags.expired ? 'X' : ' ',
                  (sig->trust_depth > 9) ? 'T' : (sig->trust_depth >
                                                  0) ? '0' +
                  sig->trust_depth : ' ',
                  keystr (sig->keyid),
                  datestr_from_sig (sig));
      if ((opt.list_options & LIST_SHOW_SIG_EXPIRE) || extended )
	es_fprintf (fp, " %s", expirestr_from_sig (sig));
      es_fprintf (fp, "  ");
      if (sigrc == '%')
	es_fprintf (fp, "[%s] ", gpg_strerror (sig_status));
      else if (sigrc == '?')
	;
      else
	{
	  size_t n;
	  char *p = get_user_id (sig->keyid, &n);
	  tty_print_utf8_string2 (fp, p, n,
				  opt.screen_columns - keystrlen () - 26 -
				  ((opt.
				    list_options & LIST_SHOW_SIG_EXPIRE) ? 11
				   : 0));
	  xfree (p);
	}
      es_fprintf (fp, "\n");

      if (sig->flags.policy_url
          && ((opt.list_options & LIST_SHOW_POLICY_URLS) || extended))
        /* XXX: Change to print to FP.  */
	show_policy_url (sig, 3, 0);

      if (sig->flags.notation
          && ((opt.list_options & LIST_SHOW_NOTATIONS) || extended))
        /* XXX: Change to print to FP.  */
	show_notation (sig, 3, 0,
		       ((opt.
			 list_options & LIST_SHOW_STD_NOTATIONS) ? 1 : 0) +
		       ((opt.
			 list_options & LIST_SHOW_USER_NOTATIONS) ? 2 : 0));

      if (sig->flags.pref_ks
          && ((opt.list_options & LIST_SHOW_KEYSERVER_URLS) || extended))
        /* XXX: Change to print to FP.  */
	show_keyserver_url (sig, 3, 0);

      if (extended)
        {
          const unsigned char *s;

          s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PRIMARY_UID, NULL);
          if (s && *s)
            es_fprintf (fp, "             [primary]\n");

          s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
          if (s && buf32_to_u32 (s))
            es_fprintf (fp, "             [expires: %s]\n",
                        isotimestamp (pk->timestamp + buf32_to_u32 (s)));
        }
    }
}


char *
sig_format (PKT_public_key *pk, PKT_signature *sig, gpg_error_t sig_status,
            int print_without_key, int extended)
{
  estream_t fp;
  char *s;

  fp = es_fopenmem (0, "rw,samethread");
  if (! fp)
    log_fatal ("Error creating memory stream\n");

  sig_print (fp, pk, sig, sig_status, print_without_key, extended);

  es_fputc (0, fp);
  if (es_fclose_snatch (fp, (void **) &s, NULL))
    log_fatal ("error snatching memory stream\n");

  if (s[strlen (s) - 1] == '\n')
    s[strlen (s) - 1] = '\0';

  return s;
}

/* Order two signatures.  The actual ordering isn't important.  Our
   goal is to ensure that identical signatures occur together.  */
static int
sig_comparison (const void *av, const void *bv)
{
  const KBNODE an = *(const KBNODE *) av;
  const KBNODE bn = *(const KBNODE *) bv;
  const PKT_signature *a;
  const PKT_signature *b;
  int ndataa;
  int ndatab;
  int i;

  assert (an->pkt->pkttype == PKT_SIGNATURE);
  assert (bn->pkt->pkttype == PKT_SIGNATURE);

  a = an->pkt->pkt.signature;
  b = bn->pkt->pkt.signature;

  if (a->digest_algo < b->digest_algo)
    return -1;
  if (a->digest_algo > b->digest_algo)
    return 1;

  ndataa = pubkey_get_nsig (a->pubkey_algo);
  ndatab = pubkey_get_nsig (a->pubkey_algo);
  assert (ndataa == ndatab);

  for (i = 0; i < ndataa; i ++)
    {
      int c = gcry_mpi_cmp (a->data[i], b->data[i]);
      if (c != 0)
        return c;
    }

  /* Okay, they are equal.  */
  return 0;
}

/* Check that a keyblock is okay and possibly repair some damage.
   Concretely:

     - Detect duplicate signatures and remove them.

     - Detect out of order signatures and relocate them (e.g., a sig
       over a user id located under a subkey)

   Note: this function does not remove signatures that don't belong or
   components that are not signed!  (Although it would be trivial to
   do.)

   If ONLY_SELFSIGS is true, then this function only reorders self
   signatures (it still checks all signatures for duplicates,
   however).

   Returns 1 if the keyblock was modified, 0 otherwise.
 */
int
keyblock_check_sigs (KBNODE kb, int only_selfsigs)
{
  gpg_error_t err;
  PKT_public_key *pk;
  u32 pk_keyid[2];
  KBNODE n, n_next, *n_prevp, n2;
  char *pending_desc = NULL;
  PKT_public_key *issuer;
  KBNODE current_component = NULL;
  int dups = 0;
  int missing_issuer = 0;
  int reordered = 0;
  int bad_signature = 0;
  int modified = 0;

  assert (kb->pkt->pkttype == PKT_PUBLIC_KEY);
  pk = kb->pkt->pkt.public_key;
  keyid_from_pk (pk, pk_keyid);

  /* First we look for duplicates.  */
  {
    int nsigs = 0;
    KBNODE *sigs;
    int i;
    int last_i;

    /* Count the sigs.  */
    for (n = kb; n; n = n->next)
      if (is_deleted_kbnode (n))
        continue;
      else if (n->pkt->pkttype == PKT_SIGNATURE)
        nsigs ++;

    /* Add them all to the SIGS array.  */
    sigs = xmalloc_clear (sizeof (*sigs) * nsigs);

    i = 0;
    for (n = kb; n; n = n->next)
      {
        if (is_deleted_kbnode (n))
          continue;

        if (n->pkt->pkttype != PKT_SIGNATURE)
          continue;

        sigs[i] = n;
        i ++;
      }
    assert (i == nsigs);

    qsort (sigs, nsigs, sizeof (sigs[0]), sig_comparison);

    last_i = 0;
    for (i = 1; i < nsigs; i ++)
      {
        assert (sigs[last_i]);
        assert (sigs[last_i]->pkt->pkttype == PKT_SIGNATURE);
        assert (sigs[i]);
        assert (sigs[i]->pkt->pkttype == PKT_SIGNATURE);

        if (sig_comparison (&sigs[last_i], &sigs[i]) == 0)
          /* They are the same.  Kill the latter.  */
          {
            if (opt.verbose)
              {
                PKT_signature *sig = sigs[i]->pkt->pkt.signature;

                log_info (_("Signature appears multiple times, deleting duplicate:\n"));
                log_info ("  sig: class 0x%x, issuer: %s, timestamp: %s (%lld), digest: %02x %02x\n",
                          sig->sig_class, keystr (sig->keyid),
                          isotimestamp (sig->timestamp),
                          (long long) sig->timestamp,
                          sig->digest_start[0], sig->digest_start[1]);
              }

            /* Remove sigs[i] from the keyblock.  */
            {
              KBNODE z, *prevp;
              int to_kill = i;

              for (prevp = &kb, z = kb; z; prevp = &z->next, z = z->next)
                if (z == sigs[to_kill])
                  break;

              *prevp = sigs[to_kill]->next;

              sigs[to_kill]->next = NULL;
              release_kbnode (sigs[to_kill]);
              sigs[to_kill] = NULL;

              dups ++;
              modified = 1;
            }
          }
        else
          last_i = i;
      }

    if (dups)
      log_info (_("Ignored %d duplicate signatures (total: %d).\n"),
                 dups, nsigs);

    xfree (sigs);
  }

  /* Make sure the sigs occur after the component (public key, subkey,
     user id) that they sign.  */
  issuer = NULL;
  for (n_prevp = &kb, n = kb; n; n_prevp = &n->next, n = n_next)
    {
      PACKET *p;
      int processed_current_component;
      KBNODE sig_over = NULL;
      PKT_signature *sig;
      int algo;
      int pkttype;
      gcry_md_hd_t md;
      int dump_sig_params = 0;

      n_next = n->next;

      if (is_deleted_kbnode (n))
        continue;

      p = n->pkt;

      if (issuer != pk)
        free_public_key (issuer);
      issuer = NULL;

      xfree (pending_desc);
      pending_desc = NULL;

      switch (p->pkttype)
        {
        case PKT_PUBLIC_KEY:
          assert (p->pkt.public_key == pk);
          keyid_from_pk (pk, NULL);
          log_info ("public key %s: timestamp: %s (%lld)\n",
                    keystr (pk->keyid),
                    isotimestamp (pk->timestamp),
                    (long long) pk->timestamp);
          current_component = n;
          break;
        case PKT_PUBLIC_SUBKEY:
          keyid_from_pk (p->pkt.public_key, NULL);
          log_info ("subkey %s: timestamp: %s (%lld)\n",
                    keystr (p->pkt.public_key->keyid),
                    isotimestamp (p->pkt.public_key->timestamp),
                    (long long) p->pkt.public_key->timestamp);
          current_component = n;
          break;
        case PKT_USER_ID:
          log_info ("user id: %s\n",
                    p->pkt.user_id->attrib_data
                    ? "[ photo id ]"
                    : p->pkt.user_id->name);
          current_component = n;
          break;
        case PKT_SIGNATURE:
          sig = n->pkt->pkt.signature;
          algo = sig->digest_algo;

#if 1
          pending_desc = xasprintf ("  sig: class: 0x%x, issuer: %s, timestamp: %s (%lld), digest: %02x %02x",
                                    sig->sig_class,
                                    keystr (sig->keyid),
                                    isotimestamp (sig->timestamp),
                                    (long long) sig->timestamp,
                                    sig->digest_start[0], sig->digest_start[1]);
#else
          pending_desc = sig_format (pk, sig, GPG_ERR_NO_VALUE, 1, 0);
#endif


          if (pk_keyid[0] == sig->keyid[0] && pk_keyid[1] == sig->keyid[1])
            issuer = pk;
          else
            /* Issuer is a different key.  */
            {
              if (only_selfsigs)
                continue;

              issuer = xmalloc (sizeof (*issuer));
              err = get_pubkey (issuer, sig->keyid);
              if (err)
                {
                  xfree (issuer);
                  issuer = NULL;
                  if (opt.verbose)
                    {
                      if (pending_desc)
                        log_info ("%s", pending_desc);
                      log_info (_("    Can't check signature allegedly issued by %s: %s\n"),
                                keystr (sig->keyid), gpg_strerror (err));
                    }
                  missing_issuer ++;
                  break;
                }
            }

          if ((err = openpgp_pk_test_algo (sig->pubkey_algo)))
            {
              if (pending_desc)
                log_info ("%s", pending_desc);
              log_info (_("    Unsupported algorithm: %s.\n"),
                        gpg_strerror (err));
              break;
            }
          if ((err = openpgp_md_test_algo(algo)))
            {
              if (pending_desc)
                log_info ("%s", pending_desc);
              log_info (_("    Unimplemented algorithm: %s.\n"),
                        gpg_strerror (err));
              break;
            }

          /* We iterate over the keyblock.  Most likely, the matching
             component is the current component so always try that
             first.  */
          processed_current_component = 0;
          for (n2 = current_component;
               n2;
               n2 = (processed_current_component ? n2->next : kb),
                 processed_current_component = 1)
            if (is_deleted_kbnode (n2))
              continue;
            else if (processed_current_component && n2 == current_component)
              /* Don't process it twice.  */
              continue;
            else if (! ((pkttype = n2->pkt->pkttype)
                   && (pkttype == PKT_PUBLIC_KEY
                       || pkttype == PKT_PUBLIC_SUBKEY
                       || pkttype == PKT_USER_ID)))
              continue;
            else if (sig->sig_class == 0x20)
              {
                PKT_public_key *k;

                if (pkttype != PKT_PUBLIC_KEY)
                  continue;

                k = n2->pkt->pkt.public_key;

                /* If issuer != pk, then we (may) have a designated
                   revoker.  */

                if (gcry_md_open (&md, algo, 0))
                  BUG ();
                hash_public_key (md, k);
                err = check_signature_only_end (issuer, sig, md);
                gcry_md_close (md);
                if (! err)
                  {
                    assert (! sig_over);
                    sig_over = n2;
                    break;
                  }
              }
            else if (sig->sig_class == 0x28)
              /* subkey revocation */
              {
                PKT_public_key *k;

                if (pkttype != PKT_PUBLIC_SUBKEY)
                  continue;

                if (issuer != pk)
                  /* Definately invalid: class 0x28 keys must be made
                     by the primary key.  */
                  {
                    n2 = NULL;
                    break;
                  }

                k = n2->pkt->pkt.public_key;

                if (gcry_md_open (&md, algo, 0))
                  BUG ();
                hash_public_key (md, pk);
                hash_public_key (md, k);
                err = check_signature_only_end (pk, sig, md);
                gcry_md_close (md);
                if (! err)
                  {
                    assert (! sig_over);
                    sig_over = n2;
                    break;
                  }
              }
            else if (sig->sig_class == 0x18)
              /* key binding */
              {
                PKT_public_key *k;

                if (pkttype != PKT_PUBLIC_SUBKEY)
                  continue;

                if (issuer != pk)
                  /* Definately invalid: class 0x18 keys must be made
                     by the primary key.  */
                  {
                    n2 = NULL;
                    break;
                  }

                k = n2->pkt->pkt.public_key;

                if (gcry_md_open (&md, algo, 0))
                  BUG ();
                hash_public_key (md, pk);
                hash_public_key (md, k);
                err = check_signature_only_end (pk, sig, md);
                gcry_md_close (md);
                if (! err)
                  {
                    assert (! sig_over);
                    sig_over = n2;
                    break;
                  }
              }
            else if (sig->sig_class == 0x1f)
              /* direct key signature */
              {
                if (pkttype != PKT_PUBLIC_KEY)
                  continue;

                if (issuer != pk)
                  /* Definately invalid: class 0x1f keys must be made
                     by the primary key.  */
                  {
                    n2 = NULL;
                    break;
                  }

                if (gcry_md_open (&md, algo, 0 ))
                  BUG ();
                hash_public_key (md, pk);
                err = check_signature_only_end (pk, sig, md);
                gcry_md_close (md);
                if (! err)
                  {
                    assert (! sig_over);
                    sig_over = n2;
                    break;
                  }
              }
            else
              /* all other classes */
              {
                if (pkttype != PKT_USER_ID)
                  continue;

                if (gcry_md_open (&md, algo, 0))
                  BUG ();
                hash_public_key (md, pk);
                hash_uid_node (n2, md, sig);
                err = check_signature_only_end (issuer, sig, md);
                gcry_md_close (md);
                if (! err)
                  {
                    assert (! sig_over);
                    sig_over = n2;
                    break;
                  }
              }

          /* n/sig is a signature and n2 is the component (public key,
             subkey or user id) that it signs, if any.
             current_component is that component that it appears to
             apply to (according to the ordering).  */

          if (current_component == n2)
            {
              log_info ("%s", pending_desc);
              log_info (_("    Good signature over last major component!\n"));
              cache_sig_result (sig, 0);
            }
          else if (n2)
            {
              assert (n2->pkt->pkttype == PKT_USER_ID
                      || n2->pkt->pkttype == PKT_PUBLIC_KEY
                      || n2->pkt->pkttype == PKT_PUBLIC_SUBKEY);

              log_info ("%s", pending_desc);
              log_info (_("    Good signature out of order!  (Over %s (%d) '%s')\n"),
                        n2->pkt->pkttype == PKT_USER_ID
                        ? "user id"
                        : n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
                        ? "subkey"
                        : "primary key",
                        n2->pkt->pkttype,
                        n2->pkt->pkttype == PKT_USER_ID
                        ? n2->pkt->pkt.user_id->name
                        : keystr (n2->pkt->pkt.public_key->keyid));

              /* Reorder the packets: move the signature n to be just
                 after n2.  */
              assert (n_prevp);
              *n_prevp = n->next;
              n->next = n2->next;
              n2->next = n;

              cache_sig_result (sig, 0);

              reordered ++;
              modified = 1;
            }
          else
            {
              log_info ("%s", pending_desc);
#if 0
              log_info (_("    Bad signature, removing from key block.\n"));

              /* Remove the signature n.  */
              *n_prevp = n->next;
              n->next = NULL;
              release_kbnode (n);

              modified = 1;
#else
              log_info (_("    Bad signature.\n"));
#endif

              cache_sig_result (sig, GPG_ERR_BAD_SIGNATURE);

              if (opt.verbose)
                dump_sig_params = 1;

              bad_signature ++;
            }

          if (dump_sig_params)
            {
              int i;

              for (i = 0; i < pubkey_get_nsig (sig->pubkey_algo); i ++)
                {
                  char buffer[1024];
                  size_t len;
                  char *printable;
                  gcry_mpi_print (GCRYMPI_FMT_USG,
                                  buffer, sizeof (buffer), &len,
                                  sig->data[i]);
                  printable = bin2hex (buffer, len, NULL);
                  log_info ("        %d: %s\n", i, printable);
                  xfree (printable);
                }
            }
          break;
        default:
          if (DBG_PACKET)
            log_debug ("unhandled packet: %d\n", p->pkttype);
          break;
        }
    }

  xfree (pending_desc);
  pending_desc = NULL;

  if (issuer != pk)
    free_public_key (issuer);
  issuer = NULL;

  if (missing_issuer)
    log_info (_("Couldn't check %d signatures due to missing issuer keys.\n"),
              missing_issuer);
  if (bad_signature)
    log_info (_("%d bad signatures.\n"), bad_signature);
  if (reordered)
    log_info (_("Reordered %d packets.\n"), reordered);

  return modified;
}
