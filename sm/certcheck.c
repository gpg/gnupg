/* certcheck.c - check one certificate
 *	Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "i18n.h"


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

  if (pkalgo == GCRY_PK_DSA || pkalgo == GCRY_PK_ECDSA)
    {
      unsigned int qbits;

      if ( pkalgo == GCRY_PK_ECDSA )
        qbits = gcry_pk_get_nbits (pkey);
      else
        qbits = get_dsa_qbits (pkey);

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
                     gcry_pk_algo_name (pkalgo), qbits);
	  return gpg_error (GPG_ERR_INTERNAL);
	}

      /* Check if we're too short.  Too long is safe as we'll
	 automatically left-truncate. */
      nframe = gcry_md_get_algo_dlen (algo);
      if (nframe < qbits/8)
        {
	  log_error (_("a %u bit hash is not valid for a %u bit %s key\n"),
                     (unsigned int)nframe*8,
                     gcry_pk_get_nbits (pkey),
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
  /* Because this function is called only for verification we can
     assume that ECC actually means ECDSA.  */
  else if (n==3 && !memcmp (name, "ecc", 3))
    algo = GCRY_PK_ECDSA;
  else if (n==13 && !memcmp (name, "ambiguous-rsa", 13))
    algo = GCRY_PK_RSA;
  else
    algo = 0;
  gcry_sexp_release (l2);
  return algo;
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
  gcry_mpi_t frame;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig, s_hash, s_pkey;

  algo = gcry_md_map_name ( (algoid=ksba_cert_get_digest_algo (cert)));
  if (!algo)
    {
      log_error ("unknown hash algorithm `%s'\n", algoid? algoid:"?");
      if (algoid
          && (  !strcmp (algoid, "1.2.840.113549.1.1.2")
                ||!strcmp (algoid, "1.2.840.113549.2.2")))
        log_info (_("(this is the MD2 algorithm)\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }
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

  p = ksba_cert_get_sig_val (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      gcry_md_close (md);
      ksba_free (p);
      return gpg_error (GPG_ERR_BUG);
    }
  if (DBG_CRYPTO)
    {
      int j;
      log_debug ("signature value:");
      for (j=0; j < n; j++)
        log_printf (" %02X", p[j]);
      log_printf ("\n");
    }

  rc = gcry_sexp_sscan ( &s_sig, NULL, (char*)p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      gcry_md_close (md);
      return rc;
    }

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

  rc = do_encode_md (md, algo, pk_algo_from_sexp (s_pkey),
                     gcry_pk_get_nbits (s_pkey), s_pkey, &frame);
  if (rc)
    {
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      gcry_sexp_release (s_pkey);
      return rc;
    }

  /* put hash into the S-Exp s_hash */
  if ( gcry_sexp_build (&s_hash, NULL, "%m", frame) )
    BUG ();
  gcry_mpi_release (frame);


  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (DBG_X509)
      log_debug ("gcry_pk_verify: %s\n", gpg_strerror (rc));
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}



int
gpgsm_check_cms_signature (ksba_cert_t cert, ksba_const_sexp_t sigval,
                           gcry_md_hd_t md, int mdalgo, int *r_pkalgo)
{
  int rc;
  ksba_sexp_t p;
  gcry_mpi_t frame;
  gcry_sexp_t s_sig, s_hash, s_pkey;
  size_t n;
  int pkalgo;

  if (r_pkalgo)
    *r_pkalgo = 0;

  n = gcry_sexp_canon_len (sigval, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      return gpg_error (GPG_ERR_BUG);
    }
  rc = gcry_sexp_sscan (&s_sig, NULL, (char*)sigval, n);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  p = ksba_cert_get_public_key (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      ksba_free (p);
      gcry_sexp_release (s_sig);
      return gpg_error (GPG_ERR_BUG);
    }
  if (DBG_CRYPTO)
    log_printhex ("public key: ", p, n);

  rc = gcry_sexp_sscan ( &s_pkey, NULL, (char*)p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      gcry_sexp_release (s_sig);
      return rc;
    }

  pkalgo = pk_algo_from_sexp (s_pkey);
  if (r_pkalgo)
    *r_pkalgo = pkalgo;
  rc = do_encode_md (md, mdalgo, pkalgo,
                     gcry_pk_get_nbits (s_pkey), s_pkey, &frame);
  if (rc)
    {
      gcry_sexp_release (s_sig);
      gcry_sexp_release (s_pkey);
      return rc;
    }
  /* put hash into the S-Exp s_hash */
  if ( gcry_sexp_build (&s_hash, NULL, "%m", frame) )
    BUG ();
  gcry_mpi_release (frame);

  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (DBG_X509)
      log_debug ("gcry_pk_verify: %s\n", gpg_strerror (rc));
  gcry_sexp_release (s_sig);
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



