/* certcheck.c - check one certificate
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "i18n.h"


static int
do_encode_md (gcry_md_hd_t md, int algo,  unsigned int nbits,
              gcry_mpi_t *r_val)
{
  int nframe = (nbits+7) / 8;
  byte *frame;
  int i, n;
  byte asn[100];
  size_t asnlen;
  size_t len;

  asnlen = DIM(asn);
  if (gcry_md_algo_info (algo, GCRYCTL_GET_ASNOID, asn, &asnlen))
    {
      log_error ("No object identifier for algo %d\n", algo);
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
    return OUT_OF_CORE (errno);
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
  if (DBG_X509)
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


/*
  Check the signature on CERT using the ISSUER-CERT.  This function
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
      return gpg_error (GPG_ERR_GENERAL);
    }
  rc = gcry_md_open (&md, algo, 0);
  if (rc)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (rc));
      return rc;
    }
  if (DBG_HASHING)
    gcry_md_start_debug (md, "hash.cert");

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
  if (DBG_X509)
    {
      int j;
      log_debug ("signature value:");
      for (j=0; j < n; j++)
        log_printf (" %02X", p[j]);
      log_printf ("\n");
    }

  rc = gcry_sexp_sscan ( &s_sig, NULL, p, n);
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
  rc = gcry_sexp_sscan ( &s_pkey, NULL, p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      return rc;
    }

  rc = do_encode_md (md, algo, gcry_pk_get_nbits (s_pkey), &frame);
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
  if (DBG_CRYPTO)
      log_debug ("gcry_pk_verify: %s\n", gpg_strerror (rc));
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}



int
gpgsm_check_cms_signature (ksba_cert_t cert, ksba_const_sexp_t sigval,
                           gcry_md_hd_t md, int algo)
{
  int rc;
  ksba_sexp_t p;
  gcry_mpi_t frame;
  gcry_sexp_t s_sig, s_hash, s_pkey;
  size_t n;

  n = gcry_sexp_canon_len (sigval, 0, NULL, NULL);
  if (!n)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      return gpg_error (GPG_ERR_BUG);
    }
  rc = gcry_sexp_sscan (&s_sig, NULL, sigval, n);
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
  if (DBG_X509)
    log_printhex ("public key: ", p, n);

  rc = gcry_sexp_sscan ( &s_pkey, NULL, p, n);
  ksba_free (p);
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      gcry_sexp_release (s_sig);
      return rc;
    }


  rc = do_encode_md (md, algo, gcry_pk_get_nbits (s_pkey), &frame);
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
  if (DBG_CRYPTO)
      log_debug ("gcry_pk_verify: %s\n", gpg_strerror (rc));
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}



int
gpgsm_create_cms_signature (ksba_cert_t cert, gcry_md_hd_t md, int mdalgo,
                            char **r_sigval)
{
  int rc;
  char *grip;
  size_t siglen;

  grip = gpgsm_get_keygrip_hexstring (cert);
  if (!grip)
    return gpg_error (GPG_ERR_BAD_CERT);

  rc = gpgsm_agent_pksign (grip, gcry_md_read(md, mdalgo), 
                           gcry_md_get_algo_dlen (mdalgo), mdalgo,
                           r_sigval, &siglen);
  xfree (grip);
  return rc;
}



