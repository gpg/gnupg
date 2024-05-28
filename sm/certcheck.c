/* certcheck.c - check one certificate
 * Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
 * Copyright (C) 2001-2019 Werner Koch
 * Copyright (C) 2015-2020 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/i18n.h"


/* Return the number of bits of the Q parameter from the DSA key
   KEY.  */
static unsigned int
get_dsa_qbits (gcry_sexp_t key)
{
  gcry_sexp_t l1, l2;
  gcry_mpi_t q;
  unsigned int nbits;

  l1 = gcry_sexp_find_token (key, "public-key", 0);
  if (!l1)
    return 0; /* Does not contain a key object.  */
  l2 = gcry_sexp_cadr (l1);
  gcry_sexp_release  (l1);
  l1 = gcry_sexp_find_token (l2, "q", 1);
  gcry_sexp_release (l2);
  if (!l1)
    return 0; /* Invalid object.  */
  q = gcry_sexp_nth_mpi (l1, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l1);
  if (!q)
    return 0; /* Missing value.  */
  nbits = gcry_mpi_get_nbits (q);
  gcry_mpi_release (q);

  return nbits;
}


static int
do_encode_md (gcry_md_hd_t md, int algo, int pkalgo, unsigned int nbits,
              gcry_sexp_t pkey, gcry_mpi_t *r_val)
{
  int n;
  size_t nframe;
  unsigned char *frame;

  if (pkalgo == GCRY_PK_DSA || pkalgo == GCRY_PK_ECC)
    {
      unsigned int qbits0, qbits;

      if ( pkalgo == GCRY_PK_ECC )
        {
          qbits0 = gcry_pk_get_nbits (pkey);
          qbits = qbits0 == 521? 512 : qbits0;
        }
      else
        qbits0 = qbits = get_dsa_qbits (pkey);

      if ( (qbits%8) )
	{
	  log_error(_("DSA requires the hash length to be a"
		      " multiple of 8 bits\n"));
	  return gpg_error (GPG_ERR_INTERNAL);
	}

      /* Don't allow any Q smaller than 160 bits.  We don't want
	 someone to issue signatures from a key with a 16-bit Q or
	 something like that, which would look correct but allow
	 trivial forgeries.  Yes, I know this rules out using MD5 with
	 DSA. ;) */
      if (qbits < 160)
	{
	  log_error (_("%s key uses an unsafe (%u bit) hash\n"),
                     gcry_pk_algo_name (pkalgo), qbits0);
	  return gpg_error (GPG_ERR_INTERNAL);
	}

      /* Check if we're too short.  Too long is safe as we'll
	 automatically left-truncate. */
      nframe = gcry_md_get_algo_dlen (algo);
      if (nframe < qbits/8)
        {
	  log_error (_("a %u bit hash is not valid for a %u bit %s key\n"),
                     (unsigned int)nframe*8,
                     qbits0,
                     gcry_pk_algo_name (pkalgo));
          /* FIXME: we need to check the requirements for ECDSA.  */
          if (nframe < 20 || pkalgo == GCRY_PK_DSA  )
            return gpg_error (GPG_ERR_INTERNAL);
        }

      frame = xtrymalloc (nframe);
      if (!frame)
        return out_of_core ();
      memcpy (frame, gcry_md_read (md, algo), nframe);
      n = nframe;
      /* Truncate.  */
      if (n > qbits/8)
        n = qbits/8;
    }
  else
    {
      int i;
      unsigned char asn[100];
      size_t asnlen;
      size_t len;

      nframe = (nbits+7) / 8;

      asnlen = DIM(asn);
      if (!algo || gcry_md_test_algo (algo))
        return gpg_error (GPG_ERR_DIGEST_ALGO);
      if (gcry_md_algo_info (algo, GCRYCTL_GET_ASNOID, asn, &asnlen))
        {
          log_error ("no object identifier for algo %d\n", algo);
          return gpg_error (GPG_ERR_INTERNAL);
        }

      len = gcry_md_get_algo_dlen (algo);

      if ( len + asnlen + 4  > nframe )
        {
          log_error ("can't encode a %d bit MD into a %d bits frame\n",
                     (int)(len*8), (int)nbits);
          return gpg_error (GPG_ERR_INTERNAL);
        }

      /* We encode the MD in this way:
       *
       *	   0  A PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
       *
       * PAD consists of FF bytes.
       */
      frame = xtrymalloc (nframe);
      if (!frame)
        return out_of_core ();
      n = 0;
      frame[n++] = 0;
      frame[n++] = 1; /* block type */
      i = nframe - len - asnlen -3 ;
      assert ( i > 1 );
      memset ( frame+n, 0xff, i ); n += i;
      frame[n++] = 0;
      memcpy ( frame+n, asn, asnlen ); n += asnlen;
      memcpy ( frame+n, gcry_md_read(md, algo), len ); n += len;
      assert ( n == nframe );
    }
  if (DBG_CRYPTO)
    {
      int j;
      log_debug ("encoded hash:");
      for (j=0; j < nframe; j++)
        log_printf (" %02X", frame[j]);
      log_printf ("\n");
    }

  gcry_mpi_scan (r_val, GCRYMPI_FMT_USG, frame, n, &nframe);
  xfree (frame);
  return 0;
}

/* Return the public key algorithm id from the S-expression PKEY.
   FIXME: libgcrypt should provide such a function.  Note that this
   implementation uses the names as used by libksba.  */
static int
pk_algo_from_sexp (gcry_sexp_t pkey)
{
  gcry_sexp_t l1, l2;
  const char *name;
  size_t n;
  int algo;

  l1 = gcry_sexp_find_token (pkey, "public-key", 0);
  if (!l1)
    return 0; /* Not found.  */
  l2 = gcry_sexp_cadr (l1);
  gcry_sexp_release (l1);

  name = gcry_sexp_nth_data (l2, 0, &n);
  if (!name)
    algo = 0; /* Not found. */
  else if (n==3 && !memcmp (name, "rsa", 3))
    algo = GCRY_PK_RSA;
  else if (n==3 && !memcmp (name, "dsa", 3))
    algo = GCRY_PK_DSA;
  else if (n==3 && !memcmp (name, "ecc", 3))
    algo = GCRY_PK_ECC;
  else if (n==13 && !memcmp (name, "ambiguous-rsa", 13))
    algo = GCRY_PK_RSA;
  else
    algo = 0;
  gcry_sexp_release (l2);
  return algo;
}


/* Return the hash algorithm's algo id from its name given in the
 * non-null termnated string in (buffer,buflen).  Returns 0 on failure
 * or if the algo is not known.  */
static int
hash_algo_from_buffer (const void *buffer, size_t buflen)
{
  char *string;
  int algo;

  string = xtrymalloc (buflen + 1);
  if (!string)
    {
      log_error (_("out of core\n"));
      return 0;
    }
  memcpy (string, buffer, buflen);
  string[buflen] = 0;
  algo = gcry_md_map_name (string);
  if (!algo)
    log_error ("unknown digest algorithm '%s' used in certificate\n", string);
  xfree (string);
  return algo;
}


/* Return an unsigned integer from the non-null termnated string
 * (buffer,buflen).  Returns 0 on failure.  */
static unsigned int
uint_from_buffer (const void *buffer, size_t buflen)
{
  char *string;
  unsigned int val;

  string = xtrymalloc (buflen + 1);
  if (!string)
    {
      log_error (_("out of core\n"));
      return 0;
    }
  memcpy (string, buffer, buflen);
  string[buflen] = 0;
  val = strtoul (string, NULL, 10);
  xfree (string);
  return val;
}


/* Extract the hash algorithm and the salt length from the sigval.  */
static gpg_error_t
extract_pss_params (gcry_sexp_t s_sig, int *r_algo, unsigned int *r_saltlen)
{
  gpg_error_t err;
  gcry_buffer_t ioarray[2] = { {0}, {0} };

  err = gcry_sexp_extract_param (s_sig, "sig-val",
                                 "&'hash-algo''salt-length'",
                                 ioarray+0, ioarray+1, NULL);
  if (err)
    {
      log_error ("extracting params from PSS failed: %s\n", gpg_strerror (err));
      return err;
    }

  *r_algo = hash_algo_from_buffer (ioarray[0].data, ioarray[0].len);
  *r_saltlen = uint_from_buffer (ioarray[1].data, ioarray[1].len);
  xfree (ioarray[0].data);
  xfree (ioarray[1].data);
  if (*r_saltlen < 20)
    {
      log_error ("length of PSS salt too short\n");
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }
  if (!*r_algo)
    {
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  /* PSS has no hash function firewall like PKCS#1 and thus offers
   * a path for hash algorithm replacement.  To avoid this it makes
   * sense to restrict the allowed hash algorithms and also allow only
   * matching salt lengths.  According to Peter Gutmann:
   *  "Beware of bugs in the above signature scheme;
   *   I have only proved it secure, not implemented it"
   *   - Apologies to Donald Knuth.
   * https://www.metzdowd.com/pipermail/cryptography/2019-November/035449.html
   *
   * Given the set of supported algorithms currently available in
   * Libgcrypt and the extra hash checks we have in some compliance
   * modes, it would be hard to trick gpgsm to verify a forged
   * signature.  However, if eventually someone adds the xor256 hash
   * algorithm (1.3.6.1.4.1.3029.3.2) to Libgcrypt we would be doomed.
   */
  switch (*r_algo)
    {
    case GCRY_MD_SHA1:
    case GCRY_MD_SHA256:
    case GCRY_MD_SHA384:
    case GCRY_MD_SHA512:
    case GCRY_MD_SHA3_256:
    case GCRY_MD_SHA3_384:
    case GCRY_MD_SHA3_512:
      break;
    default:
      log_error ("PSS hash algorithm '%s' rejected\n",
                 gcry_md_algo_name (*r_algo));
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  if (gcry_md_get_algo_dlen (*r_algo) != *r_saltlen)
    {
      log_error ("PSS hash algorithm '%s' rejected due to salt length %u\n",
                 gcry_md_algo_name (*r_algo), *r_saltlen);
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  return 0;
}


/* Check the signature on CERT using the ISSUER-CERT.  This function
   does only test the cryptographic signature and nothing else.  It is
   assumed that the ISSUER_CERT is valid. */
int
gpgsm_check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert)
{
  const char *algoid;
  gcry_md_hd_t md;
  int rc, algo;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig, s_data, s_pkey;
  int use_pss = 0;
  unsigned int saltlen;

  /* Note that we map the 4 algos which current Libgcrypt versions are
   * not aware of the OID.  */
  algo = gcry_md_map_name ( (algoid=ksba_cert_get_digest_algo (cert)));
  if (!algo && algoid && !strcmp (algoid, "1.2.840.113549.1.1.10"))
    use_pss = 1;
  else if (!algo && algoid && !strcmp (algoid, "1.2.840.10045.4.3.1"))
    algo = GCRY_MD_SHA224; /* ecdsa-with-sha224 */
  else if (!algo && algoid && !strcmp (algoid, "1.2.840.10045.4.3.2"))
    algo = GCRY_MD_SHA256; /* ecdsa-with-sha256 */
  else if (!algo && algoid && !strcmp (algoid, "1.2.840.10045.4.3.3"))
    algo = GCRY_MD_SHA384; /* ecdsa-with-sha384 */
  else if (!algo && algoid && !strcmp (algoid, "1.2.840.10045.4.3.4"))
    algo = GCRY_MD_SHA512; /* ecdsa-with-sha512 */
  else if (!algo)
    {
      log_error ("unknown digest algorithm '%s' used certificate\n",
                 algoid? algoid:"?");
      if (algoid
          && (  !strcmp (algoid, "1.2.840.113549.1.1.2")
                ||!strcmp (algoid, "1.2.840.113549.2.2")))
        log_info (_("(this is the MD2 algorithm)\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  /* The the signature from the certificate.  */
  p = ksba_cert_get_sig_val (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      ksba_free (p);
      return gpg_error (GPG_ERR_BUG);
    }
  rc = gcry_sexp_sscan ( &s_sig, NULL, (char*)p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return rc;
    }
  if (DBG_CRYPTO)
    gcry_log_debugsxp ("sigval", s_sig);

  if (use_pss)
    {
      rc = extract_pss_params (s_sig, &algo, &saltlen);
      if (rc)
        {
          gcry_sexp_release (s_sig);
          return rc;
        }
    }


  /* Hash the to-be-signed parts of the certificate.  */
  rc = gcry_md_open (&md, algo, 0);
  if (rc)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (rc));
      return rc;
    }
  if (DBG_HASHING)
    gcry_md_debug (md, "hash.cert");

  rc = ksba_cert_hash (cert, 1, HASH_FNC, md);
  if (rc)
    {
      log_error ("ksba_cert_hash failed: %s\n", gpg_strerror (rc));
      gcry_md_close (md);
      return rc;
    }
  gcry_md_final (md);

  /* Get the public key from the certificate.  */
  p = ksba_cert_get_public_key (issuer_cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      gcry_md_close (md);
      ksba_free (p);
      gcry_sexp_release (s_sig);
      return gpg_error (GPG_ERR_BUG);
    }
  rc = gcry_sexp_sscan ( &s_pkey, NULL, (char*)p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      return rc;
    }
  if (DBG_CRYPTO)
    gcry_log_debugsxp ("pubkey:", s_pkey);

  if (use_pss)
    {
      rc = gcry_sexp_build (&s_data, NULL,
                            "(data (flags pss)"
                            "(hash %s %b)"
                            "(salt-length %u))",
                            hash_algo_to_string (algo),
                            (int)gcry_md_get_algo_dlen (algo),
                            gcry_md_read (md, algo),
                            saltlen);
      if (rc)
        BUG ();
    }
  else
    {
      /* RSA or DSA: Prepare the hash for verification.  */
      gcry_mpi_t frame;

      rc = do_encode_md (md, algo, pk_algo_from_sexp (s_pkey),
                         gcry_pk_get_nbits (s_pkey), s_pkey, &frame);
      if (rc)
        {
          gcry_md_close (md);
          gcry_sexp_release (s_sig);
          gcry_sexp_release (s_pkey);
          return rc;
        }
      if ( gcry_sexp_build (&s_data, NULL, "%m", frame) )
        BUG ();
      gcry_mpi_release (frame);
    }
  if (DBG_CRYPTO)
    gcry_log_debugsxp ("data:", s_data);

  /* Verify.  */
  rc = gcry_pk_verify (s_sig, s_data, s_pkey);
  if (DBG_X509)
      log_debug ("gcry_pk_verify: %s\n", gpg_strerror (rc));
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);
  return rc;
}



int
gpgsm_check_cms_signature (ksba_cert_t cert, gcry_sexp_t s_sig,
                           gcry_md_hd_t md, int mdalgo,
                           unsigned int pkalgoflags, int *r_pkalgo)
{
  int rc;
  ksba_sexp_t p;
  gcry_sexp_t s_hash, s_pkey;
  size_t n;
  int pkalgo;
  int use_pss;
  unsigned int saltlen = 0;

  if (r_pkalgo)
    *r_pkalgo = 0;

  /* Check whether rsaPSS is needed.  This information is indicated in
   * the SIG-VAL and already provided to us by the caller so that we
   * do not need to parse this out. */
  use_pss = !!(pkalgoflags & PK_ALGO_FLAG_RSAPSS);
  if (use_pss)
    {
      int algo;

      rc = extract_pss_params (s_sig, &algo, &saltlen);
      if (rc)
        {
          return rc;
        }
      if (algo != mdalgo)
        {
          log_error ("PSS hash algo mismatch (%d/%d)\n", mdalgo, algo);
          return gpg_error (GPG_ERR_DIGEST_ALGO);
        }
    }

  p = ksba_cert_get_public_key (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      ksba_free (p);
      return gpg_error (GPG_ERR_BUG);
    }
  if (DBG_CRYPTO)
    log_printhex (p, n, "public key: ");

  rc = gcry_sexp_sscan ( &s_pkey, NULL, (char*)p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  pkalgo = pk_algo_from_sexp (s_pkey);
  if (r_pkalgo)
    *r_pkalgo = pkalgo;

  if (use_pss)
    {
      rc = gcry_sexp_build (&s_hash, NULL,
                            "(data (flags pss)"
                            "(hash %s %b)"
                            "(salt-length %u))",
                            hash_algo_to_string (mdalgo),
                            (int)gcry_md_get_algo_dlen (mdalgo),
                            gcry_md_read (md, mdalgo),
                            saltlen);
      if (rc)
        BUG ();
    }
  else
    {
      /* RSA or DSA: Prepare the hash for verification.  */
      gcry_mpi_t frame;

      rc = do_encode_md (md, mdalgo, pkalgo,
                         gcry_pk_get_nbits (s_pkey), s_pkey, &frame);
      if (rc)
        {
          gcry_sexp_release (s_pkey);
          return rc;
        }
      /* put hash into the S-Exp s_hash */
      if ( gcry_sexp_build (&s_hash, NULL, "%m", frame) )
        BUG ();
      gcry_mpi_release (frame);
    }

  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (DBG_X509)
    log_debug ("gcry_pk_verify: %s\n", gpg_strerror (rc));
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}



int
gpgsm_create_cms_signature (ctrl_t ctrl, ksba_cert_t cert,
                            gcry_md_hd_t md, int mdalgo,
                            unsigned char **r_sigval)
{
  int rc;
  char *grip, *desc;
  size_t siglen;

  grip = gpgsm_get_keygrip_hexstring (cert);
  if (!grip)
    return gpg_error (GPG_ERR_BAD_CERT);

  desc = gpgsm_format_keydesc (cert);

  rc = gpgsm_agent_pksign (ctrl, grip, desc, gcry_md_read(md, mdalgo),
                           gcry_md_get_algo_dlen (mdalgo), mdalgo,
                           r_sigval, &siglen);
  xfree (desc);
  xfree (grip);
  return rc;
}
