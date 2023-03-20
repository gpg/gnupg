/* sig-check.c -  Check a signature
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2004, 2006 Free Software Foundation, Inc.
 * Copyright (C) 2015, 2016 g10 Code GmbH
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "keydb.h"
#include "main.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "options.h"
#include "pkglue.h"
#include "../common/compliance.h"

static int check_signature_end (PKT_public_key *pk, PKT_signature *sig,
				gcry_md_hd_t digest,
                                const void *extrahash, size_t extrahashlen,
				int *r_expired, int *r_revoked,
				PKT_public_key *ret_pk);

static int check_signature_end_simple (PKT_public_key *pk, PKT_signature *sig,
                                       gcry_md_hd_t digest,
                                       const void *extrahash,
                                       size_t extrahashlen);


/* Statistics for signature verification.  */
struct
{
  unsigned int total;  /* Total number of verifications.  */
  unsigned int cached; /* Number of seen cache entries.  */
  unsigned int goodsig;/* Number of good verifications from the cache.  */
  unsigned int badsig; /* Number of bad verifications from the cache.  */
} cache_stats;


/* Dump verification stats.  */
void
sig_check_dump_stats (void)
{
  log_info ("sig_cache: total=%u cached=%u good=%u bad=%u\n",
            cache_stats.total, cache_stats.cached,
            cache_stats.goodsig, cache_stats.badsig);
}


static gpg_error_t
check_key_verify_compliance (PKT_public_key *pk)
{
  gpg_error_t err = 0;

  if (!gnupg_pk_is_allowed (opt.compliance, PK_USE_VERIFICATION,
                            pk->pubkey_algo, 0, pk->pkey,
                            nbits_from_pk (pk),
                            NULL))
    {
      /* Compliance failure.  */
      log_error (_("key %s may not be used for signing in %s mode\n"),
                 keystr_from_pk (pk),
                 gnupg_compliance_option_string (opt.compliance));
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
    }

  return err;
}



/* Check a signature.  This is shorthand for check_signature2 with
   the unnamed arguments passed as NULL.  */
int
check_signature (ctrl_t ctrl, PKT_signature *sig, gcry_md_hd_t digest)
{
  return check_signature2 (ctrl, sig, digest, NULL, 0, NULL,
                           NULL, NULL, NULL, NULL);
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
 * EXTRAHASH and EXTRAHASHLEN is additional data which is hashed with
 * v5 signatures.  They may be NULL to use the default.
 *
 * If FORCED_PK is not NULL this public key is used to verify the
 * signature and no other public key is looked up.  This is used to
 * verify against a key included in the signature.
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
 * If R_PK is not NULL, the public key is stored at that address if it
 * was found; other wise NULL is stored.
 *
 * Returns 0 on success.  An error code otherwise.  */
gpg_error_t
check_signature2 (ctrl_t ctrl,
                  PKT_signature *sig, gcry_md_hd_t digest,
                  const void *extrahash, size_t extrahashlen,
                  PKT_public_key *forced_pk,
                  u32 *r_expiredate,
		  int *r_expired, int *r_revoked, PKT_public_key **r_pk)
{
  int rc=0;
  PKT_public_key *pk;

  if (r_expiredate)
    *r_expiredate = 0;
  if (r_expired)
    *r_expired = 0;
  if (r_revoked)
    *r_revoked = 0;
  if (r_pk)
    *r_pk = NULL;

  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    return gpg_error_from_syserror ();

  if  ((rc=openpgp_md_test_algo(sig->digest_algo)))
    {
      /* We don't have this digest. */
    }
  else if (!gnupg_digest_is_allowed (opt.compliance, 0, sig->digest_algo))
    {
      /* Compliance failure.  */
      log_info (_("digest algorithm '%s' may not be used in %s mode\n"),
                gcry_md_algo_name (sig->digest_algo),
                gnupg_compliance_option_string (opt.compliance));
      rc = gpg_error (GPG_ERR_DIGEST_ALGO);
    }
  else if ((rc=openpgp_pk_test_algo(sig->pubkey_algo)))
    {
      /* We don't have this pubkey algo. */
    }
  else if (!gcry_md_is_enabled (digest,sig->digest_algo))
    {
      /* Sanity check that the md has a context for the hash that the
       * sig is expecting.  This can happen if a onepass sig header
       * does not match the actual sig, and also if the clearsign
       * "Hash:" header is missing or does not match the actual sig. */
      log_info(_("WARNING: signature digest conflict in message\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
    }
  else if (get_pubkey_for_sig (ctrl, pk, sig, forced_pk))
    rc = gpg_error (GPG_ERR_NO_PUBKEY);
  else if ((rc = check_key_verify_compliance (pk)))
    ;/* Compliance failure.  */
  else if (!pk->flags.valid)
    {
      /* You cannot have a good sig from an invalid key.  */
      rc = gpg_error (GPG_ERR_BAD_PUBKEY);
    }
  else
    {
      if (r_expiredate)
        *r_expiredate = pk->expiredate;

      rc = check_signature_end (pk, sig, digest, extrahash, extrahashlen,
                                r_expired, r_revoked, NULL);

      /* Check the backsig.  This is a back signature (0x19) from
       * the subkey on the primary key.  The idea here is that it
       * should not be possible for someone to "steal" subkeys and
       * claim them as their own.  The attacker couldn't actually
       * use the subkey, but they could try and claim ownership of
       * any signatures issued by it.  */
      if (!rc && !pk->flags.primary && pk->flags.backsig < 2)
        {
          if (!pk->flags.backsig)
            {
              log_info (_("WARNING: signing subkey %s is not"
                          " cross-certified\n"),keystr_from_pk(pk));
              log_info (_("please see %s for more information\n"),
                        "https://gnupg.org/faq/subkey-cross-certify.html");
              /* The default option --require-cross-certification
               * makes this warning an error.  */
              if (opt.flags.require_cross_cert)
                rc = gpg_error (GPG_ERR_GENERAL);
            }
          else if(pk->flags.backsig == 1)
            {
              log_info (_("WARNING: signing subkey %s has an invalid"
                          " cross-certification\n"), keystr_from_pk(pk));
              rc = gpg_error (GPG_ERR_GENERAL);
            }
        }

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
        char hashbuf[20];  /* We use SHA-1 here.  */

      nbytes = 6;
      for (i=0; i < nsig; i++ )
        {
          if (gcry_mpi_get_flag (sig->data[i], GCRYMPI_FLAG_OPAQUE))
            {
              unsigned int nbits;

              gcry_mpi_get_opaque (sig->data[i], &nbits);
              n = (nbits+7)/8 + 2;
            }
          else if (gcry_mpi_print (GCRYMPI_FMT_PGP, NULL, 0, &n, sig->data[i]))
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
          if (gcry_mpi_get_flag (sig->data[i], GCRYMPI_FLAG_OPAQUE))
            {
              const byte *sigdata;
              unsigned int nbits;

              sigdata = gcry_mpi_get_opaque (sig->data[i], &nbits);
              n = (nbits+7)/8;
              p[0] = nbits >> 8;
              p[1] = (nbits & 0xff);
              memcpy (p+2, sigdata, n);
              n += 2;
            }
          else if (gcry_mpi_print (GCRYMPI_FMT_PGP, p, nbytes, &n, sig->data[i]))
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

  if (r_pk)
    *r_pk = pk;
  else
    {
      release_public_key_parts (pk);
      xfree (pk);
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

  if (r_expired)
    *r_expired = 0;
  if (r_revoked)
    *r_revoked = 0;

  if (pk->timestamp > sig->timestamp
      && !(parse_key_usage (sig) & PUBKEY_USAGE_RENC))
    {
      ulong d = pk->timestamp - sig->timestamp;
      if ( d < 86400 )
        {
          log_info (ngettext
                    ("public key %s is %lu second newer than the signature\n",
                     "public key %s is %lu seconds newer than the signature\n",
                     d), keystr_from_pk (pk), d);
        }
      else
        {
          d /= 86400;
          log_info (ngettext
                    ("public key %s is %lu day newer than the signature\n",
                     "public key %s is %lu days newer than the signature\n",
                     d), keystr_from_pk (pk), d);
        }
      if (!opt.ignore_time_conflict)
        return GPG_ERR_TIME_CONFLICT; /* pubkey newer than signature.  */
    }

  cur_time = make_timestamp ();
  if (pk->timestamp > cur_time)
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
   * flag which is set after a full evaluation of the key (getkey.c)
   * as well as a simple compare to the current time in case the
   * merge has for whatever reasons not been done.  */
  if (pk->has_expired || (pk->expiredate && pk->expiredate < cur_time))
    {
      char buf[11];
      if (opt.verbose)
        log_info (_("Note: signature key %s expired %s\n"),
                  keystr_from_pk(pk), isotimestamp( pk->expiredate ) );
      snprintf (buf, sizeof buf, "%lu",(ulong)pk->expiredate);
      write_status_text (STATUS_KEYEXPIRED, buf);
      if (r_expired)
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
static int
check_signature_end (PKT_public_key *pk, PKT_signature *sig,
		     gcry_md_hd_t digest,
                     const void *extrahash, size_t extrahashlen,
		     int *r_expired, int *r_revoked, PKT_public_key *ret_pk)
{
  int rc = 0;

  if ((rc = check_signature_metadata_validity (pk, sig,
                                               r_expired, r_revoked)))
    return rc;

  if ((rc = check_signature_end_simple (pk, sig, digest,
                                        extrahash, extrahashlen)))
    return rc;

  if (!rc && ret_pk)
    copy_public_key(ret_pk,pk);

  return rc;
}


/* This function is similar to check_signature_end, but it only checks
 * whether the signature was generated by PK.  It does not check
 * expiration, revocation, etc.  */
static int
check_signature_end_simple (PKT_public_key *pk, PKT_signature *sig,
                            gcry_md_hd_t digest,
                            const void *extrahash, size_t extrahashlen)
{
  gcry_mpi_t result = NULL;
  int rc = 0;

  if (!opt.flags.allow_weak_digest_algos)
    {
      if (is_weak_digest (sig->digest_algo))
        {
          print_digest_rejected_note (sig->digest_algo);
          return GPG_ERR_DIGEST_ALGO;
        }
    }

  /* For key signatures check that the key has a cert usage.  We may
   * do this only for subkeys because the primary may always issue key
   * signature.  The latter may not be reflected in the pubkey_usage
   * field because we need to check the key signatures to extract the
   * key usage.  */
  if (!pk->flags.primary
      && IS_CERT (sig) && !(pk->pubkey_usage & PUBKEY_USAGE_CERT))
    {
      rc = gpg_error (GPG_ERR_WRONG_KEY_USAGE);
      if (!opt.quiet)
        log_info (_("bad key signature from key %s: %s (0x%02x, 0x%x)\n"),
                  keystr_from_pk (pk), gpg_strerror (rc),
                  sig->sig_class, pk->pubkey_usage);
      return rc;
    }

  /* For data signatures check that the key has sign usage.  */
  if (!IS_BACK_SIG (sig) && IS_SIG (sig)
      && !(pk->pubkey_usage & PUBKEY_USAGE_SIG))
    {
      rc = gpg_error (GPG_ERR_WRONG_KEY_USAGE);
      if (!opt.quiet)
        log_info (_("bad data signature from key %s: %s (0x%02x, 0x%x)\n"),
                  keystr_from_pk (pk), gpg_strerror (rc),
                  sig->sig_class, pk->pubkey_usage);
      return rc;
    }

  /* Make sure the digest algo is enabled (in case of a detached
   * signature).  */
  gcry_md_enable (digest, sig->digest_algo);

  /* Complete the digest. */
  if (sig->version >= 4)
    gcry_md_putc (digest, sig->version);

  gcry_md_putc( digest, sig->sig_class );
  if (sig->version < 4)
    {
      u32 a = sig->timestamp;
      gcry_md_putc (digest, ((a >> 24) & 0xff));
      gcry_md_putc (digest, ((a >> 16) & 0xff));
      gcry_md_putc (digest, ((a >>  8) & 0xff));
      gcry_md_putc (digest, ( a        & 0xff));
    }
  else
    {
      byte buf[10];
      int i;
      size_t n;

      gcry_md_putc (digest, sig->pubkey_algo);
      gcry_md_putc (digest, sig->digest_algo);
      if (sig->hashed)
        {
          n = sig->hashed->len;
          gcry_md_putc (digest, (n >> 8) );
          gcry_md_putc (digest,  n       );
          gcry_md_write (digest, sig->hashed->data, n);
          n += 6;
	}
      else
        {
	  /* Two octets for the (empty) length of the hashed
           * section. */
          gcry_md_putc (digest, 0);
	  gcry_md_putc (digest, 0);
	  n = 6;
	}
      /* Hash data from the literal data packet.  */
      if (sig->version >= 5
          && (sig->sig_class == 0x00 || sig->sig_class == 0x01))
        {
          /* - One octet content format
           * - File name (one octet length followed by the name)
           * - Four octet timestamp */
          if (extrahash && extrahashlen)
            gcry_md_write (digest, extrahash, extrahashlen);
          else /* Detached signature. */
            {
              memset (buf, 0, 6);
              gcry_md_write (digest, buf, 6);
            }
        }
      /* Add some magic per Section 5.2.4 of RFC 4880.  */
      i = 0;
      buf[i++] = sig->version;
      buf[i++] = 0xff;
      if (sig->version >= 5)
        {
#if SIZEOF_SIZE_T > 4
          buf[i++] = n >> 56;
          buf[i++] = n >> 48;
          buf[i++] = n >> 40;
          buf[i++] = n >> 32;
#else
          buf[i++] = 0;
          buf[i++] = 0;
          buf[i++] = 0;
          buf[i++] = 0;
#endif
        }
      buf[i++] = n >> 24;
      buf[i++] = n >> 16;
      buf[i++] = n >>  8;
      buf[i++] = n;
      gcry_md_write (digest, buf, i);
    }
    gcry_md_final( digest );

    /* Convert the digest to an MPI.  */
    result = encode_md_value (pk, digest, sig->digest_algo );
    if (!result)
        return GPG_ERR_GENERAL;

    /* Verify the signature.  */
    if (DBG_CLOCK && sig->sig_class <= 0x01)
      log_clock ("enter pk_verify");
    rc = pk_verify( pk->pubkey_algo, result, sig->data, pk->pkey );
    if (DBG_CLOCK && sig->sig_class <= 0x01)
      log_clock ("leave pk_verify");
    gcry_mpi_release (result);

  if (!rc && sig->flags.unknown_critical)
    {
      log_info(_("assuming bad signature from key %s"
                 " due to an unknown critical bit\n"),keystr_from_pk(pk));
      rc = GPG_ERR_BAD_SIGNATURE;
    }

  return rc;
}


/* Add a uid node to a hash context.  See section 5.2.4, paragraph 4
 * of RFC 4880.  */
static void
hash_uid_packet (PKT_user_id *uid, gcry_md_hd_t md, PKT_signature *sig )
{
  if (uid->attrib_data)
    {
      if (sig->version >= 4)
        {
          byte buf[5];
          buf[0] = 0xd1;		   /* packet of type 17 */
          buf[1] = uid->attrib_len >> 24;  /* always use 4 length bytes */
          buf[2] = uid->attrib_len >> 16;
          buf[3] = uid->attrib_len >>  8;
          buf[4] = uid->attrib_len;
          gcry_md_write( md, buf, 5 );
	}
      gcry_md_write( md, uid->attrib_data, uid->attrib_len );
    }
  else
    {
      if (sig->version >= 4)
        {
          byte buf[5];
          buf[0] = 0xb4;	      /* indicates a userid packet */
          buf[1] = uid->len >> 24;    /* always use 4 length bytes */
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
  if (!result)
    {
      sig->flags.checked = 1;
      sig->flags.valid = 1;
    }
  else if  (gpg_err_code (result) == GPG_ERR_BAD_SIGNATURE)
    {
      sig->flags.checked = 1;
      sig->flags.valid = 0;
    }
  else
    {
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
check_revocation_keys (ctrl_t ctrl, PKT_public_key *pk, PKT_signature *sig)
{
  static int busy=0;
  int i;
  int rc = GPG_ERR_GENERAL;

  log_assert (IS_KEY_REV(sig));
  log_assert ((sig->keyid[0]!=pk->keyid[0]) || (sig->keyid[0]!=pk->keyid[1]));

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

          keyid_from_fingerprint (ctrl, pk->revkey[i].fpr, pk->revkey[i].fprlen,
                                  keyid);

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
              rc = check_signature (ctrl, sig, md);
	      cache_sig_result(sig,rc);
              gcry_md_close (md);
	      break;
	    }
	}

  busy=0;

  return rc;
}

/* Check that the backsig BACKSIG from the subkey SUB_PK to its
 * primary key MAIN_PK is valid.
 *
 * Backsigs (0x19) have the same format as binding sigs (0x18), but
 * this function is simpler than check_key_signature in a few ways.
 * For example, there is no support for expiring backsigs since it is
 * questionable what such a thing actually means.  Note also that the
 * sig cache check here, unlike other sig caches in GnuPG, is not
 * persistent.  */
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
      rc = check_signature_end (sub_pk, backsig, md, NULL, 0, NULL, NULL, NULL);
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
check_key_signature (ctrl_t ctrl, kbnode_t root, kbnode_t node,
                     int *is_selfsig)
{
  return check_key_signature2 (ctrl, root, node, NULL, NULL,
                               is_selfsig, NULL, NULL);
}


/* Returns whether SIGNER generated the signature SIG over the packet
 * PACKET, which is a key, subkey or uid, and comes from the key block
 * KB.  (KB is PACKET's corresponding keyblock; we don't assume that
 * SIG has been added to the keyblock.)
 *
 * If SIGNER is set, then checks whether SIGNER generated the
 * signature.  Otherwise, uses SIG->KEYID to find the alleged signer.
 * This parameter can be used to effectively override the alleged
 * signer that is stored in SIG.
 *
 * KB may be NULL if SIGNER is set.
 *
 * Unlike check_key_signature, this function ignores any cached
 * results!  That is, it does not consider SIG->FLAGS.CHECKED and
 * SIG->FLAGS.VALID nor does it set them.
 *
 * This doesn't check the signature's semantic mean.  Concretely, it
 * doesn't check whether a non-self signed revocation signature was
 * created by a designated revoker.  In fact, it doesn't return an
 * error for a binding generated by a completely different key!
 *
 * Returns 0 if the signature is valid.  Returns GPG_ERR_SIG_CLASS if
 * this signature can't be over PACKET.  Returns GPG_ERR_NOT_FOUND if
 * the key that generated the signature (according to SIG) could not
 * be found.  Returns GPG_ERR_BAD_SIGNATURE if the signature is bad.
 * Other errors codes may be returned if something else goes wrong.
 *
 * IF IS_SELFSIG is not NULL, sets *IS_SELFSIG to 1 if this is a
 * self-signature (by the key's primary key) or 0 if not.
 *
 * If RET_PK is not NULL, returns a copy of the public key that
 * generated the signature (i.e., the signer) on success.  This must
 * be released by the caller using release_public_key_parts ().  */
gpg_error_t
check_signature_over_key_or_uid (ctrl_t ctrl, PKT_public_key *signer,
                                 PKT_signature *sig, KBNODE kb, PACKET *packet,
                                 int *is_selfsig, PKT_public_key *ret_pk)
{
  int rc;
  PKT_public_key *pripk = kb->pkt->pkt.public_key;
  gcry_md_hd_t md;
  int signer_alloced = 0;
  int stub_is_selfsig;

  if (!is_selfsig)
    is_selfsig = &stub_is_selfsig;

  rc = openpgp_pk_test_algo (sig->pubkey_algo);
  if (rc)
    return rc;
  rc = openpgp_md_test_algo (sig->digest_algo);
  if (rc)
    return rc;

  /* A signature's class indicates the type of packet that it
     signs.  */
  if (IS_BACK_SIG (sig) || IS_KEY_SIG (sig) || IS_KEY_REV (sig))
    {
      /* Key revocations can only be over primary keys.  */
      if (packet->pkttype != PKT_PUBLIC_KEY)
        return gpg_error (GPG_ERR_SIG_CLASS);
    }
  else if (IS_SUBKEY_SIG (sig) || IS_SUBKEY_REV (sig))
    {
      if (packet->pkttype != PKT_PUBLIC_SUBKEY)
        return gpg_error (GPG_ERR_SIG_CLASS);
    }
  else if (IS_UID_SIG (sig) || IS_UID_REV (sig))
    {
      if (packet->pkttype != PKT_USER_ID)
        return gpg_error (GPG_ERR_SIG_CLASS);
    }
  else
    return gpg_error (GPG_ERR_SIG_CLASS);

  /* PACKET is the right type for SIG.  */

  if (signer)
    {
      if (signer->keyid[0] == pripk->keyid[0]
          && signer->keyid[1] == pripk->keyid[1])
        *is_selfsig = 1;
      else
        *is_selfsig = 0;
    }
  else
    {
      /* Get the signer.  If possible, avoid a look up.  */
      if (sig->keyid[0] == pripk->keyid[0]
          && sig->keyid[1] == pripk->keyid[1])
        {
          /* Issued by the primary key.  */
          signer = pripk;
          *is_selfsig = 1;
        }
      else
        {
          /* See if one of the subkeys was the signer (although this
           * is extremely unlikely).  */
          kbnode_t ctx = NULL;
          kbnode_t n;

          while ((n = walk_kbnode (kb, &ctx, 0)))
            {
              PKT_public_key *subk;

              if (n->pkt->pkttype != PKT_PUBLIC_SUBKEY)
                continue;

              subk = n->pkt->pkt.public_key;
              if (sig->keyid[0] == subk->keyid[0]
                  && sig->keyid[1] == subk->keyid[1])
                {
                  /* Issued by a subkey.  */
                  signer = subk;
                  break;
                }
            }

          if (! signer)
            {
              /* Signer by some other key.  */
              *is_selfsig = 0;
              if (ret_pk)
                {
                  signer = ret_pk;
                  /* FIXME: Using memset here is probematic because it
                   * assumes that there are no allocated fields in
                   * SIGNER.  */
                  memset (signer, 0, sizeof (*signer));
                  signer_alloced = 1;
                }
              else
                {
                  signer = xmalloc_clear (sizeof (*signer));
                  signer_alloced = 2;
                }

              if (IS_CERT (sig))
                signer->req_usage = PUBKEY_USAGE_CERT;

              rc = get_pubkey_for_sig (ctrl, signer, sig, NULL);
              if (rc)
                {
                  xfree (signer);
                  signer = NULL;
                  signer_alloced = 0;
                  goto leave;
                }
            }
        }
    }

  /* We checked above that we supported this algo, so an error here is
   * a bug.  */
  if (gcry_md_open (&md, sig->digest_algo, 0))
    BUG ();

  /* Hash the relevant data.  */

  if (IS_KEY_SIG (sig) || IS_KEY_REV (sig))
    {
      log_assert (packet->pkttype == PKT_PUBLIC_KEY);
      hash_public_key (md, packet->pkt.public_key);
      rc = check_signature_end_simple (signer, sig, md, NULL, 0);
    }
  else if (IS_BACK_SIG (sig))
    {
      log_assert (packet->pkttype == PKT_PUBLIC_KEY);
      hash_public_key (md, packet->pkt.public_key);
      hash_public_key (md, signer);
      rc = check_signature_end_simple (signer, sig, md, NULL, 0);
    }
  else if (IS_SUBKEY_SIG (sig) || IS_SUBKEY_REV (sig))
    {
      log_assert (packet->pkttype == PKT_PUBLIC_SUBKEY);
      hash_public_key (md, pripk);
      hash_public_key (md, packet->pkt.public_key);
      rc = check_signature_end_simple (signer, sig, md, NULL, 0);
    }
  else if (IS_UID_SIG (sig) || IS_UID_REV (sig))
    {
      log_assert (packet->pkttype == PKT_USER_ID);
      if (sig->digest_algo == DIGEST_ALGO_SHA1 && !*is_selfsig
          && !opt.flags.allow_weak_key_signatures)
        {
          /* If the signature was created using SHA-1 we consider this
           * signature invalid because it makes it possible to mount a
           * chosen-prefix collision.  We don't do this for
           * self-signatures, though.  */
          print_sha1_keysig_rejected_note ();
          rc = gpg_error (GPG_ERR_DIGEST_ALGO);
        }
      else
        {
          hash_public_key (md, pripk);
          hash_uid_packet (packet->pkt.user_id, md, sig);
          rc = check_signature_end_simple (signer, sig, md, NULL, 0);
        }
    }
  else
    {
      /* We should never get here.  (The first if above should have
       * already caught this error.)  */
      BUG ();
    }

  gcry_md_close (md);

 leave:
  if (! rc && ret_pk && ret_pk != signer)
    copy_public_key (ret_pk, signer);

  if (signer_alloced)
    {
      /* We looked up SIGNER; it is not a pointer into KB.  */
      release_public_key_parts (signer);
      /* Free if we also allocated the memory.  */
      if (signer_alloced == 2)
        xfree (signer);
    }

  return rc;
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
 * r_expiredate and r_expired and the cache [nw].  Which problems [wk]? */
int
check_key_signature2 (ctrl_t ctrl,
                      kbnode_t root, kbnode_t node, PKT_public_key *check_pk,
                      PKT_public_key *ret_pk, int *is_selfsig,
                      u32 *r_expiredate, int *r_expired )
{
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
  log_assert (node->pkt->pkttype == PKT_SIGNATURE);
  log_assert (root->pkt->pkttype == PKT_PUBLIC_KEY);

  pk = root->pkt->pkt.public_key;
  sig = node->pkt->pkt.signature;
  algo = sig->digest_algo;

  /* Check whether we have cached the result of a previous signature
   * check.  Note that we may no longer have the pubkey or hash
   * needed to verify a sig, but can still use the cached value.  A
   * cache refresh detects and clears these cases. */
  if ( !opt.no_sig_cache )
    {
      cache_stats.total++;
      if (sig->flags.checked) /* Cached status available.  */
        {
          cache_stats.cached++;
          if (is_selfsig)
            {
              u32 keyid[2];

              keyid_from_pk (pk, keyid);
              if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1])
                *is_selfsig = 1;
	    }
          /* BUG: This is wrong for non-self-sigs... needs to be the
           * actual pk.  */
          rc = check_signature_metadata_validity (pk, sig, r_expired, NULL);
          if (rc)
            return rc;
          if (sig->flags.valid)
            {
              cache_stats.goodsig++;
              return 0;
            }
          cache_stats.badsig++;
          return gpg_error (GPG_ERR_BAD_SIGNATURE);
        }
    }

  rc = openpgp_pk_test_algo(sig->pubkey_algo);
  if (rc)
    return rc;
  rc = openpgp_md_test_algo(algo);
  if (rc)
    return rc;

  if (IS_KEY_REV (sig))
    {
      u32 keyid[2];
      keyid_from_pk( pk, keyid );

      /* Is it a designated revoker? */
      if (keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1])
        rc = check_revocation_keys (ctrl, pk, sig);
      else
        {
          rc = check_signature_metadata_validity (pk, sig,
                                                  r_expired, NULL);
          if (! rc)
            rc = check_signature_over_key_or_uid (ctrl, pk, sig,
                                                  root, root->pkt,
                                                  is_selfsig, ret_pk);
        }
    }
  else if (IS_SUBKEY_REV (sig) || IS_SUBKEY_SIG (sig))
    {
      kbnode_t snode = find_prev_kbnode (root, node, PKT_PUBLIC_SUBKEY);

      if (snode)
        {
          rc = check_signature_metadata_validity (pk, sig,
                                                  r_expired, NULL);
          if (! rc)
            {
              /* A subkey revocation (0x28) must be a self-sig, but a
               * subkey signature (0x18) needn't be.  */
              rc = check_signature_over_key_or_uid (ctrl,
                                                    IS_SUBKEY_SIG (sig)
                                                    ? NULL : pk,
                                                    sig, root, snode->pkt,
                                                    is_selfsig, ret_pk);
            }
        }
      else
        {
          if (opt.verbose)
            {
              if (IS_SUBKEY_REV (sig))
                log_info (_("key %s: no subkey for subkey"
                            " revocation signature\n"), keystr_from_pk(pk));
              else if (sig->sig_class == 0x18)
                log_info(_("key %s: no subkey for subkey"
                           " binding signature\n"), keystr_from_pk(pk));
            }
          rc = GPG_ERR_SIG_CLASS;
        }
    }
  else if (IS_KEY_SIG (sig)) /* direct key signature */
      {
        rc = check_signature_metadata_validity (pk, sig,
                                                r_expired, NULL);
        if (! rc)
          rc = check_signature_over_key_or_uid (ctrl, pk, sig, root, root->pkt,
                                                is_selfsig, ret_pk);
      }
    else if (IS_UID_SIG (sig) || IS_UID_REV (sig))
      {
	kbnode_t unode = find_prev_kbnode (root, node, PKT_USER_ID);

	if (unode)
          {
            rc = check_signature_metadata_validity (pk, sig, r_expired, NULL);
            if (! rc)
              {
                /* If this is a self-sig, ignore check_pk.  */
                rc = check_signature_over_key_or_uid
                  (ctrl,
                   keyid_cmp (pk_keyid (pk), sig->keyid) == 0 ? pk : check_pk,
                   sig, root, unode->pkt, NULL, ret_pk);
              }
          }
	else
	  {
            if (!opt.quiet)
	      log_info ("key %s: no user ID for key signature packet"
			" of class %02x\n",keystr_from_pk(pk),sig->sig_class);
	    rc = GPG_ERR_SIG_CLASS;
	  }
      }
  else
    {
      log_info ("sig issued by %s with class %d (digest: %02x %02x)"
                " is not valid over a user id or a key id, ignoring.\n",
                keystr (sig->keyid), sig->sig_class,
                sig->digest_start[0], sig->digest_start[1]);
      rc = gpg_error (GPG_ERR_BAD_SIGNATURE);
    }

  cache_sig_result  (sig, rc);

  return rc;
}
