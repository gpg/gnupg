/* pkglue.c - public key operations glue code
 * Copyright (C) 2000, 2003, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2024 g10 Code GmbH.
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

#include "gpg.h"
#include "../common/util.h"
#include "pkglue.h"
#include "main.h"
#include "options.h"


/* FIXME: Better change the function name because mpi_ is used by
   gcrypt macros.  */
gcry_mpi_t
get_mpi_from_sexp (gcry_sexp_t sexp, const char *item, int mpifmt)
{
  gcry_sexp_t list;
  gcry_mpi_t data;

  list = gcry_sexp_find_token (sexp, item, 0);
  log_assert (list);
  data = gcry_sexp_nth_mpi (list, 1, mpifmt);
  log_assert (data);
  gcry_sexp_release (list);
  return data;
}


/*
 * SOS (Simply, Octet String) is an attempt to handle opaque octet
 * string in OpenPGP, where well-formed MPI cannot represent octet
 * string with leading zero octets.
 *
 * To retain maximum compatibility to existing MPI handling, SOS
 * has same structure, but allows leading zero octets.  When there
 * is no leading zero octets, SOS representation is as same as MPI one.
 * With leading zero octets, NBITS is 8*(length of octets), regardless
 * of leading zero bits.
 */
/* Extract SOS representation from SEXP for PARAM, return the result
 * in R_SOS.  It is represented by opaque MPI with GCRYMPI_FLAG_USER2
 * flag.  */
gpg_error_t
sexp_extract_param_sos (gcry_sexp_t sexp, const char *param, gcry_mpi_t *r_sos)
{
  gpg_error_t err;
  gcry_sexp_t l2 = gcry_sexp_find_token (sexp, param, 0);

  *r_sos = NULL;
  if (!l2)
    err = gpg_error (GPG_ERR_NO_OBJ);
  else
    {
      size_t buflen;
      void *p0 = gcry_sexp_nth_buffer (l2, 1, &buflen);

      if (!p0)
        err = gpg_error_from_syserror ();
      else
        {
          gcry_mpi_t sos;
          unsigned int nbits = buflen*8;
          unsigned char *p = p0;

          if (*p && nbits >= 8 && !(*p & 0x80))
            if (--nbits >= 7 && !(*p & 0x40))
              if (--nbits >= 6 && !(*p & 0x20))
                if (--nbits >= 5 && !(*p & 0x10))
                  if (--nbits >= 4 && !(*p & 0x08))
                    if (--nbits >= 3 && !(*p & 0x04))
                      if (--nbits >= 2 && !(*p & 0x02))
                        if (--nbits >= 1 && !(*p & 0x01))
                          --nbits;

          sos = gcry_mpi_set_opaque (NULL, p0, nbits);
          if (sos)
            {
              gcry_mpi_set_flag (sos, GCRYMPI_FLAG_USER2);
              *r_sos = sos;
              err = 0;
            }
          else
            err = gpg_error_from_syserror ();
        }
      gcry_sexp_release (l2);
    }

  return err;
}


/* "No leading zero octets" (nlz) version of the function above.
 *
 * This routine is used for backward compatibility to existing
 * implementation with the weird handling of little endian integer
 * representation with leading zero octets.  For the sake of
 * "well-fomed" MPI, which is designed for big endian integer, leading
 * zero octets are removed when output, and they are recovered at
 * input.
 *
 * Extract SOS representation from SEXP for PARAM, removing leading
 * zeros, return the result in R_SOS.  */
gpg_error_t
sexp_extract_param_sos_nlz (gcry_sexp_t sexp, const char *param,
                            gcry_mpi_t *r_sos)
{
  gpg_error_t err;
  gcry_sexp_t l2 = gcry_sexp_find_token (sexp, param, 0);

  *r_sos = NULL;
  if (!l2)
    err = gpg_error (GPG_ERR_NO_OBJ);
  else
    {
      size_t buflen;
      const void *p0 = gcry_sexp_nth_data (l2, 1, &buflen);

      if (!p0)
        err = gpg_error_from_syserror ();
      else
        {
          gcry_mpi_t sos;
          unsigned int nbits = buflen*8;
          const unsigned char *p = p0;

          /* Strip leading zero bits.  */
          for (; nbits >= 8 && !*p; p++, nbits -= 8)
            ;

          if (nbits >= 8 && !(*p & 0x80))
            if (--nbits >= 7 && !(*p & 0x40))
              if (--nbits >= 6 && !(*p & 0x20))
                if (--nbits >= 5 && !(*p & 0x10))
                  if (--nbits >= 4 && !(*p & 0x08))
                    if (--nbits >= 3 && !(*p & 0x04))
                      if (--nbits >= 2 && !(*p & 0x02))
                        if (--nbits >= 1 && !(*p & 0x01))
                          --nbits;

          sos = gcry_mpi_set_opaque_copy (NULL, p, nbits);
          if (sos)
            {
              gcry_mpi_set_flag (sos, GCRYMPI_FLAG_USER2);
              *r_sos = sos;
              err = 0;
            }
          else
            err = gpg_error_from_syserror ();
        }
      gcry_sexp_release (l2);
    }

  return err;
}


/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_verify (pubkey_algo_t pkalgo, gcry_mpi_t hash,
           gcry_mpi_t *data, gcry_mpi_t *pkey)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc;

  /* Make a sexp from pkey.  */
  if (pkalgo == PUBKEY_ALGO_DSA)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2], pkey[3]);
    }
  else if (pkalgo == PUBKEY_ALGO_ELGAMAL_E || pkalgo == PUBKEY_ALGO_ELGAMAL)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
    }
  else if (pkalgo == PUBKEY_ALGO_RSA || pkalgo == PUBKEY_ALGO_RSA_S)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))", pkey[0], pkey[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_ECDSA)
    {
      char *curve = openpgp_oid_to_str (pkey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_pkey, NULL,
                                "(public-key(ecdsa(curve %s)(q%m)))",
                                curve, pkey[1]);
          xfree (curve);
        }
    }
  else if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      char *curve = openpgp_oid_to_str (pkey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          const char *fmt;

          if (openpgp_oid_is_ed25519 (pkey[0]))
            fmt = "(public-key(ecc(curve %s)(flags eddsa)(q%m)))";
          else
            fmt = "(public-key(ecc(curve %s)(q%m)))";

          rc = gcry_sexp_build (&s_pkey, NULL, fmt, curve, pkey[1]);
          xfree (curve);
        }
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();  /* gcry_sexp_build should never fail.  */

  /* Put hash into a S-Exp s_hash. */
  if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      const char *fmt;

      if (openpgp_oid_is_ed25519 (pkey[0]))
        fmt = "(data(flags eddsa)(hash-algo sha512)(value %m))";
      else
        fmt = "(data(value %m))";

      if (gcry_sexp_build (&s_hash, NULL, fmt, hash))
        BUG (); /* gcry_sexp_build should never fail.  */
    }
  else
    {
      if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
        BUG (); /* gcry_sexp_build should never fail.  */
    }

  /* Put data into a S-Exp s_sig. */
  s_sig = NULL;
  if (pkalgo == PUBKEY_ALGO_DSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_ECDSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(ecdsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      gcry_mpi_t r = data[0];
      gcry_mpi_t s = data[1];

      if (openpgp_oid_is_ed25519 (pkey[0]))
        {
          size_t rlen, slen, n;  /* (bytes) */
          char buf[64];
          unsigned int nbits;
          unsigned int neededfixedlen = 256 / 8;

          log_assert (neededfixedlen <= sizeof buf);

          if (!r || !s)
            rc = gpg_error (GPG_ERR_BAD_MPI);
          else if ((rlen = (gcry_mpi_get_nbits (r)+7)/8) > neededfixedlen || !rlen)
            rc = gpg_error (GPG_ERR_BAD_MPI);
          else if ((slen = (gcry_mpi_get_nbits (s)+7)/8) > neededfixedlen || !slen)
            rc = gpg_error (GPG_ERR_BAD_MPI);
          else
            {
              r = gcry_mpi_copy (r);
              s = gcry_mpi_copy (s);

              if (!r || !s)
                {
                  rc = gpg_error_from_syserror ();
                  goto leave;
                }

              /* We need to fixup the length in case of leading zeroes.
               * OpenPGP does not allow leading zeroes and the parser for
               * the signature packet has no information on the used curve,
               * thus we need to do it here.  We won't do it for opaque
               * MPIs under the assumption that they are known to be fine;
               * we won't see them here anyway but the check is anyway
               * required.  Fixme: A nifty feature for gcry_sexp_build
               * would be a format to left pad the value (e.g. "%*M"). */
              rc = 0;

              if (rlen < neededfixedlen
                  && !gcry_mpi_get_flag (r, GCRYMPI_FLAG_OPAQUE)
                  && !(rc=gcry_mpi_print (GCRYMPI_FMT_USG,
                                          buf, sizeof buf, &n, r)))
                {
                  log_assert (n < neededfixedlen);
                  memmove (buf + (neededfixedlen - n), buf, n);
                  memset (buf, 0, neededfixedlen - n);
                  gcry_mpi_set_opaque_copy (r, buf, neededfixedlen * 8);
                }
              else if (rlen < neededfixedlen
                       && gcry_mpi_get_flag (r, GCRYMPI_FLAG_OPAQUE))
                {
                  const unsigned char *p;

                  p = gcry_mpi_get_opaque (r, &nbits);
                  n = (nbits+7)/8;
                  memcpy (buf + (neededfixedlen - n), p, n);
                  memset (buf, 0, neededfixedlen - n);
                  gcry_mpi_set_opaque_copy (r, buf, neededfixedlen * 8);
                }

              if (rc)
                ;
              else if (slen < neededfixedlen
                  && !gcry_mpi_get_flag (s, GCRYMPI_FLAG_OPAQUE)
                  && !(rc=gcry_mpi_print (GCRYMPI_FMT_USG,
                                          buf, sizeof buf, &n, s)))
                {
                  log_assert (n < neededfixedlen);
                  memmove (buf + (neededfixedlen - n), buf, n);
                  memset (buf, 0, neededfixedlen - n);
                  gcry_mpi_set_opaque_copy (s, buf, neededfixedlen * 8);
                }
              else if (slen < neededfixedlen
                       && gcry_mpi_get_flag (s, GCRYMPI_FLAG_OPAQUE))
                {
                  const unsigned char *p;

                  p = gcry_mpi_get_opaque (s, &nbits);
                  n = (nbits+7)/8;
                  memcpy (buf + (neededfixedlen - n), p, n);
                  memset (buf, 0, neededfixedlen - n);
                  gcry_mpi_set_opaque_copy (s, buf, neededfixedlen * 8);
                }
            }
        }
      else
        rc = 0;

      if (!rc)
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(eddsa(r%M)(s%M)))", r, s);

      if (r != data[0])
        gcry_mpi_release (r);
      if (s != data[1])
        gcry_mpi_release (s);
    }
  else if (pkalgo == PUBKEY_ALGO_ELGAMAL || pkalgo == PUBKEY_ALGO_ELGAMAL_E)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(elg(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_RSA || pkalgo == PUBKEY_ALGO_RSA_S)
    {
      if (!data[0])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", data[0]);
    }
  else
    BUG ();

  if (!rc)
    rc = gcry_pk_verify (s_sig, s_hash, s_pkey);

 leave:
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}


#if GCRY_KEM_MLKEM1024_ENCAPS_LEN < GCRY_KEM_MLKEM768_ENCAPS_LEN    \
    || GCRY_KEM_MLKEM1024_SHARED_LEN < GCRY_KEM_MLKEM768_SHARED_LEN
# error Bad Kyber constants in Libgcrypt
#endif

/* Core of the encryption for KEM algorithms.  See pk_decrypt for a
 * description of the arguments.  */
static gpg_error_t
do_encrypt_kem (PKT_public_key *pk, gcry_mpi_t data, int seskey_algo,
                gcry_mpi_t *resarr)
{
  gpg_error_t err;
  int i;
  unsigned int nbits, n;
  gcry_sexp_t s_data = NULL;
  gcry_cipher_hd_t hd = NULL;
  char *ecc_oid = NULL;
  const char *curve;
  const struct gnupg_ecc_params *ecc;
  enum gcry_kem_algos kyber_algo;

  const unsigned char *ecc_pubkey;
  size_t ecc_pubkey_len;
  const unsigned char *kyber_pubkey;
  size_t kyber_pubkey_len;
  const unsigned char *seskey;
  size_t seskey_len;
  unsigned char *enc_seskey = NULL;
  size_t enc_seskey_len;
  int ecc_hash_algo;

  unsigned char ecc_ct[ECC_POINT_LEN_MAX];
  unsigned char ecc_ecdh[ECC_POINT_LEN_MAX];
  unsigned char ecc_ss[ECC_HASH_LEN_MAX];
  size_t ecc_ct_len, ecc_ecdh_len, ecc_ss_len;

  unsigned char kyber_ct[GCRY_KEM_MLKEM1024_ENCAPS_LEN];
  unsigned char kyber_ss[GCRY_KEM_MLKEM1024_SHARED_LEN];
  size_t kyber_ct_len, kyber_ss_len;

  char fixedinfo[1+MAX_FINGERPRINT_LEN];
  int fixedlen;

  unsigned char kek[32];  /* AES-256 is mandatory.  */
  size_t kek_len = 32;

  /* For later error checking we make sure the array is cleared.  */
  resarr[0] = resarr[1] = resarr[2] = NULL;

  /* As of now we use KEM only for the combined Kyber and thus a
   * second public key is expected.  Right now we take the keys
   * directly from the PK->data elements.  */

  ecc_oid = openpgp_oid_to_str (pk->pkey[0]);
  if (!ecc_oid)
    {
      err = gpg_error_from_syserror ();
      log_error ("%s: error getting OID for ECC key\n", __func__);
      goto leave;
    }
  curve = openpgp_oid_to_curve (ecc_oid, 1);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      log_error ("%s: error getting curve for ECC key\n", __func__);
      goto leave;
    }
  ecc = gnupg_get_ecc_params (curve);
  if (!ecc)
    {
      if (opt.verbose)
        log_info ("%s: ECC curve %s not supported\n", __func__, curve);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  ecc_ct_len = ecc_ecdh_len = ecc->point_len;
  ecc_hash_algo = ecc->hash_algo;
  ecc_ss_len = gcry_md_get_algo_dlen (ecc_hash_algo);

  ecc_pubkey = gcry_mpi_get_opaque (pk->pkey[1], &nbits);
  ecc_pubkey_len = (nbits+7)/8;
  if (ecc_pubkey_len != ecc->pubkey_len)
    {
      if (ecc->kem_algo == GCRY_KEM_RAW_X25519
          && ecc_pubkey_len == ecc->pubkey_len - 1)
        /* For Curve25519, we also accept no prefix in the point
         * representation.  */
        ;
      else
        {
          if (opt.verbose)
            log_info ("%s: ECC public key length invalid (%zu)\n",
                      __func__, ecc_pubkey_len);
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }
    }

  if (ecc->kem_algo == GCRY_KEM_RAW_X25519)
    {
      if (!strcmp (ecc_oid, "1.3.6.1.4.1.3029.1.5.1"))
        log_info ("Warning: "
                  "legacy OID for cv25519 accepted during development\n");
      /* Optional prefix handling */
      if (ecc_pubkey_len == 33 && *ecc_pubkey == 0x40)
        {
          ecc_pubkey++;     /* Remove the 0x40 prefix.  */
          ecc_pubkey_len--;
        }
    }

  if (DBG_CRYPTO)
    {
      log_debug ("ECC    curve: %s\n", ecc_oid);
      log_printhex (ecc_pubkey, ecc_pubkey_len, "ECC   pubkey:");
    }

  err = gcry_kem_encap (ecc->kem_algo,
                        ecc_pubkey, ecc_pubkey_len,
                        ecc_ct, ecc_ct_len,
                        ecc_ecdh, ecc_ecdh_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_encap for ECC (%s) failed\n",
                  __func__, ecc_oid);
      goto leave;
    }
  if (DBG_CRYPTO)
    {
      log_printhex (ecc_ct, ecc_ct_len, "ECC    ephem:");
      log_printhex (ecc_ecdh, ecc_ecdh_len, "ECC     ecdh:");
    }
  err = gnupg_ecc_kem_kdf (ecc_ss, ecc_ss_len,
                           ecc_hash_algo,
                           ecc_ecdh, ecc_ecdh_len,
                           ecc_ct, ecc_ct_len,
                           ecc_pubkey, ecc_pubkey_len, NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: kdf for ECC failed\n", __func__);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (ecc_ss, ecc_ss_len, "ECC   shared:");

  kyber_pubkey = gcry_mpi_get_opaque (pk->pkey[2], &nbits);
  kyber_pubkey_len = (nbits+7)/8;
  if (kyber_pubkey_len == GCRY_KEM_MLKEM768_PUBKEY_LEN)
    {
      kyber_algo = GCRY_KEM_MLKEM768;
      kyber_ct_len = GCRY_KEM_MLKEM768_ENCAPS_LEN;
      kyber_ss_len = GCRY_KEM_MLKEM768_SHARED_LEN;
    }
  else if (kyber_pubkey_len == GCRY_KEM_MLKEM1024_PUBKEY_LEN)
    {
      kyber_algo = GCRY_KEM_MLKEM1024;
      kyber_ct_len = GCRY_KEM_MLKEM1024_ENCAPS_LEN;
      kyber_ss_len = GCRY_KEM_MLKEM1024_SHARED_LEN;
    }
  else
    {
      if (opt.verbose)
        log_info ("%s: Kyber public key length invalid (%zu)\n",
                  __func__, kyber_pubkey_len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (kyber_pubkey, kyber_pubkey_len, "|!trunc|Kyber pubkey:");

  err = gcry_kem_encap (kyber_algo,
                        kyber_pubkey, kyber_pubkey_len,
                        kyber_ct, kyber_ct_len,
                        kyber_ss, kyber_ss_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_encap for ECC failed\n", __func__);
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      log_printhex (kyber_ct, kyber_ct_len, "|!trunc|Kyber  ephem:");
      log_printhex (kyber_ss, kyber_ss_len, "Kyber shared:");
    }


  fixedinfo[0] = seskey_algo;
  v5_fingerprint_from_pk (pk, fixedinfo+1, NULL);
  fixedlen = 33;

  err = gnupg_kem_combiner (kek, kek_len,
                            ecc_ss, ecc_ss_len, ecc_ct, ecc_ct_len,
                            kyber_ss, kyber_ss_len, kyber_ct, kyber_ct_len,
                            fixedinfo, fixedlen);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: KEM combiner failed\n", __func__);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (kek, kek_len, "KEK:");

  err = gcry_cipher_open (&hd, GCRY_CIPHER_AES256,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = gcry_cipher_setkey (hd, kek, kek_len);
  if (err)
    {
      if (opt.verbose)
        log_error ("%s: failed to initialize AESWRAP: %s\n", __func__,
                   gpg_strerror (err));
      goto leave;
    }

  err = gcry_sexp_build (&s_data, NULL, "%m", data);
  if (err)
    goto leave;

  n = gcry_cipher_get_algo_keylen (seskey_algo);
  seskey = gcry_mpi_get_opaque (data, &nbits);
  seskey_len = (nbits+7)/8;
  if (seskey_len != n)
    {
      if (opt.verbose)
        log_info ("%s: session key length %zu"
                  " does not match the length for algo %d\n",
                  __func__, seskey_len, seskey_algo);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (seskey, seskey_len, "seskey:");

  enc_seskey_len = 1 + seskey_len + 8;
  enc_seskey = xtrymalloc (enc_seskey_len);
  if (!enc_seskey || enc_seskey_len > 254)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  enc_seskey[0] = enc_seskey_len - 1;
  err = gcry_cipher_encrypt (hd, enc_seskey+1, enc_seskey_len-1,
                             seskey, seskey_len);
  if (err)
    {
      log_error ("%s: wrapping session key failed\n", __func__);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (enc_seskey, enc_seskey_len, "enc_seskey:");

  resarr[0] = gcry_mpi_set_opaque_copy (NULL, ecc_ct, 8 * ecc_ct_len);
  if (resarr[0])
    resarr[1] = gcry_mpi_set_opaque_copy (NULL, kyber_ct, 8 * kyber_ct_len);
  if (resarr[1])
    resarr[2] = gcry_mpi_set_opaque_copy (NULL, enc_seskey, 8 * enc_seskey_len);
  if (!resarr[0] || !resarr[1] || !resarr[2])
    {
      err = gpg_error_from_syserror ();
      for (i=0; i < 3; i++)
        gcry_mpi_release (resarr[i]), resarr[i] = NULL;
    }

 leave:
  wipememory (ecc_ct, sizeof ecc_ct);
  wipememory (ecc_ecdh, sizeof ecc_ecdh);
  wipememory (ecc_ss, sizeof ecc_ss);
  wipememory (kyber_ct, sizeof kyber_ct);
  wipememory (kyber_ss, sizeof kyber_ss);
  wipememory (kek, kek_len);
  xfree (enc_seskey);
  gcry_cipher_close (hd);
  xfree (ecc_oid);
  return err;
}


/* Core of the encryption for the ECDH algorithms.  See pk_decrypt for
 * a description of the arguments.  */
static gpg_error_t
do_encrypt_ecdh (PKT_public_key *pk, gcry_mpi_t data,  gcry_mpi_t *resarr)
{
  gpg_error_t err;
  unsigned int nbits;
  gcry_cipher_hd_t hd = NULL;
  char *ecc_oid = NULL;
  const char *curve;
  const struct gnupg_ecc_params *ecc;

  const unsigned char *ecc_pubkey;
  size_t ecc_pubkey_len;
  const unsigned char *seskey;
  size_t seskey_len;
  unsigned char *enc_seskey = NULL;
  size_t enc_seskey_len;

  unsigned char ecc_ct[ECC_POINT_LEN_MAX];
  unsigned char ecc_ecdh[ECC_POINT_LEN_MAX];
  size_t ecc_ct_len, ecc_ecdh_len;

  unsigned char *kek = NULL;
  size_t kek_len;

  const unsigned char *kdf_params_spec;
  byte fp[MAX_FINGERPRINT_LEN];
  int keywrap_cipher_algo;
  int kdf_hash_algo;
  unsigned char *kdf_params = NULL;
  size_t kdf_params_len = 0;

  fingerprint_from_pk (pk, fp, NULL);

  ecc_oid = openpgp_oid_to_str (pk->pkey[0]);
  if (!ecc_oid)
    {
      err = gpg_error_from_syserror ();
      log_error ("%s: error getting OID for ECC key\n", __func__);
      goto leave;
    }
  curve = openpgp_oid_to_curve (ecc_oid, 1);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      log_error ("%s: error getting curve for ECC key\n", __func__);
      goto leave;
    }
  ecc = gnupg_get_ecc_params (curve);
  if (!ecc)
    {
      if (opt.verbose)
        log_info ("%s: ECC curve %s not supported\n", __func__, curve);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  ecc_ct_len = ecc_ecdh_len = ecc->point_len;

  ecc_pubkey = gcry_mpi_get_opaque (pk->pkey[1], &nbits);
  ecc_pubkey_len = (nbits+7)/8;
  if (ecc_pubkey_len != ecc->pubkey_len)
    {
      if (ecc->kem_algo == GCRY_KEM_RAW_X25519
          && ecc_pubkey_len == ecc->pubkey_len - 1)
        /* For Curve25519, we also accept no prefix in the point
         * representation.  */
        ;
      else
        {
          if (opt.verbose)
            log_info ("%s: ECC public key length invalid (%zu)\n",
                      __func__, ecc_pubkey_len);
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }
    }

  if (ecc->kem_algo == GCRY_KEM_RAW_X25519)
    {
      /* Note: Legacy OID is OK here.  */
      /* Optional prefix handling */
      if (ecc_pubkey_len == 33 && *ecc_pubkey == 0x40)
        {
          ecc_pubkey++;     /* Remove the 0x40 prefix.  */
          ecc_pubkey_len--;
        }
    }

  if (DBG_CRYPTO)
    {
      log_debug ("ECC    curve: %s\n", ecc_oid);
      log_printhex (ecc_pubkey, ecc_pubkey_len, "ECC   pubkey:");
    }

  err = gcry_kem_encap (ecc->kem_algo,
                        ecc_pubkey, ecc_pubkey_len,
                        ecc_ct, ecc_ct_len,
                        ecc_ecdh, ecc_ecdh_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_encap for ECC (%s) failed\n",
                  __func__, ecc_oid);
      goto leave;
    }
  if (DBG_CRYPTO)
    {
      log_printhex (ecc_ct, ecc_ct_len, "ECC    ephem:");
      log_printhex (ecc_ecdh, ecc_ecdh_len, "ECC     ecdh:");
    }

  err = ecc_build_kdf_params (&kdf_params, &kdf_params_len,
                              &kdf_params_spec, pk->pkey, fp);
  if (err)
    return err;

  keywrap_cipher_algo = kdf_params_spec[3];
  kdf_hash_algo = kdf_params_spec[2];

  if (DBG_CRYPTO)
    log_debug ("ecdh KDF algorithms %s+%s with aeswrap\n",
               openpgp_md_algo_name (kdf_hash_algo),
               openpgp_cipher_algo_name (keywrap_cipher_algo));

  if (kdf_hash_algo != GCRY_MD_SHA256
      && kdf_hash_algo != GCRY_MD_SHA384
      && kdf_hash_algo != GCRY_MD_SHA512)
    {
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  if (keywrap_cipher_algo != CIPHER_ALGO_AES
      && keywrap_cipher_algo != CIPHER_ALGO_AES192
      && keywrap_cipher_algo != CIPHER_ALGO_AES256)
    {
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  kek_len = gcry_cipher_get_algo_keylen (keywrap_cipher_algo);
  if (kek_len > gcry_md_get_algo_dlen (kdf_hash_algo))
    {
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  kek = xtrymalloc (kek_len);
  if (!kek)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gnupg_ecc_kem_kdf (kek, kek_len, kdf_hash_algo,
                           ecc->is_weierstrauss ?
                           ecc_ecdh + 1 : ecc_ecdh,
                           ecc->is_weierstrauss ?
                           (ecc_ecdh_len - 1) / 2 : ecc_ecdh_len,
                           NULL, 0, NULL, 0,
                           kdf_params, kdf_params_len);
  xfree (kdf_params);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: kdf for ECC failed\n", __func__);
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex (kek, kek_len, "KEK:");

  err = gcry_cipher_open (&hd, keywrap_cipher_algo,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = gcry_cipher_setkey (hd, kek, kek_len);
  if (err)
    {
      if (opt.verbose)
        log_error ("%s: failed to initialize AESWRAP: %s\n", __func__,
                   gpg_strerror (err));
      goto leave;
    }

  seskey = gcry_mpi_get_opaque (data, &nbits);
  seskey_len = (nbits+7)/8;

  enc_seskey_len = 1 + seskey_len + 8;
  enc_seskey = xtrymalloc (enc_seskey_len);
  if (!enc_seskey || enc_seskey_len > 254)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  enc_seskey[0] = enc_seskey_len - 1;
  err = gcry_cipher_encrypt (hd, enc_seskey+1, enc_seskey_len-1,
                             seskey, seskey_len);
  if (err)
    {
      log_error ("%s: wrapping session key failed\n", __func__);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (enc_seskey, enc_seskey_len, "enc_seskey:");

  resarr[0] = gcry_mpi_set_opaque_copy (NULL, ecc_ct, 8 * ecc_ct_len);
  if (!resarr[0])
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  resarr[1] = gcry_mpi_set_opaque_copy (NULL, enc_seskey, 8 * enc_seskey_len);
  if (!resarr[1])
    {
      err = gpg_error_from_syserror ();
      gcry_mpi_release (resarr[0]);
    }

 leave:
  xfree (enc_seskey);
  gcry_cipher_close (hd);
  xfree (kek);
  wipememory (ecc_ct, sizeof ecc_ct);
  wipememory (ecc_ecdh, sizeof ecc_ecdh);
  xfree (ecc_oid);
  return err;
}


/* Core of the encryption for RSA and Elgamal algorithms.  See
 * pk_decrypt for a description of the arguments.  */
static gpg_error_t
do_encrypt_rsa_elg (PKT_public_key *pk, gcry_mpi_t data, gcry_mpi_t *resarr)
{
  pubkey_algo_t algo = pk->pubkey_algo;
  gcry_mpi_t *pkey   = pk->pkey;
  gcry_sexp_t s_ciph = NULL;
  gcry_sexp_t s_data = NULL;
  gcry_sexp_t s_pkey = NULL;
  gpg_error_t err;

  if (algo == PUBKEY_ALGO_ELGAMAL || algo == PUBKEY_ALGO_ELGAMAL_E)
    err = gcry_sexp_build (&s_pkey, NULL,
                           "(public-key(elg(p%m)(g%m)(y%m)))",
                           pkey[0], pkey[1], pkey[2]);
  else
    err = gcry_sexp_build (&s_pkey, NULL,
                           "(public-key(rsa(n%m)(e%m)))",
                           pkey[0], pkey[1]);
  if (err)
    goto leave;

  err = gcry_sexp_build (&s_data, NULL, "%m", data);
  if (err)
    goto leave;

  err = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  if (err)
    goto leave;

  gcry_sexp_release (s_data); s_data = NULL;
  gcry_sexp_release (s_pkey); s_pkey = NULL;

  resarr[0] = get_mpi_from_sexp (s_ciph, "a", GCRYMPI_FMT_USG);
  if (!is_RSA (algo))
    resarr[1] = get_mpi_from_sexp (s_ciph, "b", GCRYMPI_FMT_USG);

 leave:
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);
  gcry_sexp_release (s_ciph);
  return err;
}


/*
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.  PK is is
 * the OpenPGP public key packet, DATA is an MPI with the to be
 * encrypted data, and RESARR receives the encrypted data.  RESARRAY
 * is expected to be an two/three item array which will be filled with
 * newly allocated MPIs.  SESKEY_ALGO is required for public key
 * algorithms which do not encode it in DATA.
 */
gpg_error_t
pk_encrypt (PKT_public_key *pk, gcry_mpi_t data, int seskey_algo,
            gcry_mpi_t *resarr)
{
  pubkey_algo_t algo = pk->pubkey_algo;

  if (algo == PUBKEY_ALGO_KYBER)
    return do_encrypt_kem (pk, data, seskey_algo, resarr);
  else if (algo == PUBKEY_ALGO_ECDH)
    return do_encrypt_ecdh (pk, data, resarr);
  else if (algo == PUBKEY_ALGO_ELGAMAL || algo == PUBKEY_ALGO_ELGAMAL_E)
    return do_encrypt_rsa_elg (pk, data, resarr);
  else if (algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_E)
    return do_encrypt_rsa_elg (pk, data, resarr);
  else
    return gpg_error (GPG_ERR_PUBKEY_ALGO);
}


/* Check whether SKEY is a suitable secret key. */
int
pk_check_secret_key (pubkey_algo_t pkalgo, gcry_mpi_t *skey)
{
  gcry_sexp_t s_skey;
  int rc;

  if (pkalgo == PUBKEY_ALGO_DSA)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4]);
    }
  else if (pkalgo == PUBKEY_ALGO_ELGAMAL || pkalgo == PUBKEY_ALGO_ELGAMAL_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3]);
    }
  else if (is_RSA (pkalgo))
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4],
			    skey[5]);
    }
  else if (pkalgo == PUBKEY_ALGO_ECDSA || pkalgo == PUBKEY_ALGO_ECDH)
    {
      char *curve = openpgp_oid_to_str (skey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_skey, NULL,
                                "(private-key(ecc(curve%s)(q%m)(d%m)))",
                                curve, skey[1], skey[2]);
          xfree (curve);
        }
    }
  else if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      char *curve = openpgp_oid_to_str (skey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          const char *fmt;

          if (openpgp_oid_is_ed25519 (skey[0]))
            fmt = "(private-key(ecc(curve %s)(flags eddsa)(q%m)(d%m)))";
          else
            fmt = "(private-key(ecc(curve %s)(q%m)(d%m)))";

          rc = gcry_sexp_build (&s_skey, NULL, fmt, curve, skey[1], skey[2]);
          xfree (curve);
        }
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (!rc)
    {
      rc = gcry_pk_testkey (s_skey);
      gcry_sexp_release (s_skey);
    }
  return rc;
}
