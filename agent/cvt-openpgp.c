/* cvt-openpgp.c - Convert an OpenPGP key to our internal format.
 * Copyright (C) 1998-2002, 2006, 2009, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2013, 2014 Werner Koch
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
#include <assert.h>

#include "agent.h"
#include "../common/i18n.h"
#include "cvt-openpgp.h"
#include "../common/host2net.h"


/* Helper to pass data via the callback to do_unprotect. */
struct try_do_unprotect_arg_s
{
  int  is_v4;
  int  is_protected;
  int  pubkey_algo;
  const char *curve;
  int  protect_algo;
  char *iv;
  int  ivlen;
  int  s2k_mode;
  int  s2k_algo;
  byte *s2k_salt;
  u32  s2k_count;
  u16 desired_csum;
  gcry_mpi_t *skey;
  size_t skeysize;
  int skeyidx;
  gcry_sexp_t *r_key;
};



/* Compute the keygrip from the public key and store it at GRIP.  */
static gpg_error_t
get_keygrip (int pubkey_algo, const char *curve, gcry_mpi_t *pkey,
             unsigned char *grip)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey = NULL;

  switch (pubkey_algo)
    {
    case GCRY_PK_DSA:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                             pkey[0], pkey[1], pkey[2], pkey[3]);
      break;

    case GCRY_PK_ELG:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(elg(p%m)(g%m)(y%m)))",
                             pkey[0], pkey[1], pkey[2]);
      break;

    case GCRY_PK_RSA:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(rsa(n%m)(e%m)))", pkey[0], pkey[1]);
      break;

    case GCRY_PK_ECC:
      if (!curve)
        err = gpg_error (GPG_ERR_BAD_SECKEY);
      else
        {
          const char *format;

          if (!strcmp (curve, "Ed25519"))
            format = "(public-key(ecc(curve %s)(flags eddsa)(q%m)))";
          else if (!strcmp (curve, "Curve25519"))
            format = "(public-key(ecc(curve %s)(flags djb-tweak)(q%m)))";
          else
            format = "(public-key(ecc(curve %s)(q%m)))";

          err = gcry_sexp_build (&s_pkey, NULL, format, curve, pkey[0]);
        }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (!err && !gcry_pk_get_keygrip (s_pkey, grip))
    err = gpg_error (GPG_ERR_INTERNAL);

  gcry_sexp_release (s_pkey);
  return err;
}


/* Convert a secret key given as algorithm id and an array of key
   parameters into our s-expression based format.  Note that
   PUBKEY_ALGO has an gcrypt algorithm number. */
static gpg_error_t
convert_secret_key (gcry_sexp_t *r_key, int pubkey_algo, gcry_mpi_t *skey,
                    const char *curve)
{
  gpg_error_t err;
  gcry_sexp_t s_skey = NULL;

  *r_key = NULL;

  switch (pubkey_algo)
    {
    case GCRY_PK_DSA:
      err = gcry_sexp_build (&s_skey, NULL,
                             "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
                             skey[0], skey[1], skey[2], skey[3], skey[4]);
      break;

    case GCRY_PK_ELG:
    case GCRY_PK_ELG_E:
      err = gcry_sexp_build (&s_skey, NULL,
                             "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
                             skey[0], skey[1], skey[2], skey[3]);
      break;


    case GCRY_PK_RSA:
    case GCRY_PK_RSA_E:
    case GCRY_PK_RSA_S:
      err = gcry_sexp_build (&s_skey, NULL,
                             "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
                             skey[0], skey[1], skey[2], skey[3], skey[4],
                             skey[5]);
      break;

    case GCRY_PK_ECC:
      if (!curve)
        err = gpg_error (GPG_ERR_BAD_SECKEY);
      else
        {
          const char *format;

          if (!strcmp (curve, "Ed25519"))
            /* Do not store the OID as name but the real name and the
               EdDSA flag.  */
            format = "(private-key(ecc(curve %s)(flags eddsa)(q%m)(d%m)))";
          else if (!strcmp (curve, "Curve25519"))
            format = "(private-key(ecc(curve %s)(flags djb-tweak)(q%m)(d%m)))";
          else
            format = "(private-key(ecc(curve %s)(q%m)(d%m)))";

          err = gcry_sexp_build (&s_skey, NULL, format, curve, skey[0], skey[1]);
        }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (!err)
    *r_key = s_skey;
  return err;
}


/* Convert a secret key given as algorithm id, an array of key
   parameters, and an S-expression of the original OpenPGP transfer
   key into our s-expression based format.  This is a variant of
   convert_secret_key which is used for the openpgp-native protection
   mode.  Note that PUBKEY_ALGO has an gcrypt algorithm number. */
static gpg_error_t
convert_transfer_key (gcry_sexp_t *r_key, int pubkey_algo, gcry_mpi_t *skey,
                      const char *curve, gcry_sexp_t transfer_key)
{
  gpg_error_t err;
  gcry_sexp_t s_skey = NULL;

  *r_key = NULL;

  switch (pubkey_algo)
    {
    case GCRY_PK_DSA:
      err = gcry_sexp_build
        (&s_skey, NULL,
         "(protected-private-key(dsa(p%m)(q%m)(g%m)(y%m)"
         "(protected openpgp-native%S)))",
         skey[0], skey[1], skey[2], skey[3], transfer_key);
      break;

    case GCRY_PK_ELG:
      err = gcry_sexp_build
        (&s_skey, NULL,
         "(protected-private-key(elg(p%m)(g%m)(y%m)"
         "(protected openpgp-native%S)))",
         skey[0], skey[1], skey[2], transfer_key);
      break;


    case GCRY_PK_RSA:
      err = gcry_sexp_build
        (&s_skey, NULL,
         "(protected-private-key(rsa(n%m)(e%m)"
         "(protected openpgp-native%S)))",
         skey[0], skey[1], transfer_key );
      break;

    case GCRY_PK_ECC:
      if (!curve)
        err = gpg_error (GPG_ERR_BAD_SECKEY);
      else
        {
          const char *format;

          if (!strcmp (curve, "Ed25519"))
            /* Do not store the OID as name but the real name and the
               EdDSA flag.  */
            format = "(protected-private-key(ecc(curve %s)(flags eddsa)(q%m)"
              "(protected openpgp-native%S)))";
          else if (!strcmp (curve, "Curve25519"))
            format = "(protected-private-key(ecc(curve %s)(flags djb-tweak)(q%m)"
              "(protected openpgp-native%S)))";
          else
            format = "(protected-private-key(ecc(curve %s)(q%m)"
              "(protected openpgp-native%S)))";

          err = gcry_sexp_build (&s_skey, NULL, format, curve, skey[0], transfer_key);
        }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (!err)
    *r_key = s_skey;
  return err;
}


/* Hash the passphrase and set the key. */
static gpg_error_t
hash_passphrase_and_set_key (const char *passphrase,
                             gcry_cipher_hd_t hd, int protect_algo,
                             int s2k_mode, int s2k_algo,
                             byte *s2k_salt, u32 s2k_count)
{
  gpg_error_t err;
  unsigned char *key;
  size_t keylen;

  keylen = gcry_cipher_get_algo_keylen (protect_algo);
  if (!keylen)
    return gpg_error (GPG_ERR_INTERNAL);

  key = xtrymalloc_secure (keylen);
  if (!key)
    return gpg_error_from_syserror ();

  err = s2k_hash_passphrase (passphrase,
                             s2k_algo, s2k_mode, s2k_salt, s2k_count,
                             key, keylen);
  if (!err)
    err = gcry_cipher_setkey (hd, key, keylen);

  xfree (key);
  return err;
}


static u16
checksum (const unsigned char *p, unsigned int n)
{
  u16 a;

  for (a=0; n; n-- )
    a += *p++;
  return a;
}


/* Return the number of expected key parameters.  */
static void
get_npkey_nskey (int pubkey_algo, size_t *npkey, size_t *nskey)
{
  switch (pubkey_algo)
    {
    case GCRY_PK_RSA:   *npkey = 2; *nskey = 6; break;
    case GCRY_PK_ELG:   *npkey = 3; *nskey = 4; break;
    case GCRY_PK_ELG_E: *npkey = 3; *nskey = 4; break;
    case GCRY_PK_DSA:   *npkey = 4; *nskey = 5; break;
    case GCRY_PK_ECC:   *npkey = 1; *nskey = 2; break;
    default:            *npkey = 0; *nskey = 0; break;
    }
}


/* Helper for do_unprotect.  PUBKEY_ALOGO is the gcrypt algo number.
   On success R_NPKEY and R_NSKEY receive the number or parameters for
   the algorithm PUBKEY_ALGO and R_SKEYLEN the used length of
   SKEY.  */
static int
prepare_unprotect (int pubkey_algo, gcry_mpi_t *skey, size_t skeysize,
                   int s2k_mode,
                   unsigned int *r_npkey, unsigned int *r_nskey,
                   unsigned int *r_skeylen)
{
  size_t npkey, nskey, skeylen;
  int i;

  /* Count the actual number of MPIs is in the array and set the
     remainder to NULL for easier processing later on.  */
  for (skeylen = 0; skey[skeylen]; skeylen++)
    ;
  for (i=skeylen; i < skeysize; i++)
    skey[i] = NULL;

  /* Check some args.  */
  if (s2k_mode == 1001)
    {
      /* Stub key.  */
      log_info (_("secret key parts are not available\n"));
      return gpg_error (GPG_ERR_UNUSABLE_SECKEY);
    }

  if (gcry_pk_test_algo (pubkey_algo))
    {
      log_info (_("public key algorithm %d (%s) is not supported\n"),
                pubkey_algo, gcry_pk_algo_name (pubkey_algo));
      return gpg_error (GPG_ERR_PUBKEY_ALGO);
    }

  /* Get properties of the public key algorithm and do some
     consistency checks.  Note that we need at least NPKEY+1 elements
     in the SKEY array. */
  get_npkey_nskey (pubkey_algo, &npkey, &nskey);
  if (!npkey || !nskey || npkey >= nskey)
    return gpg_error (GPG_ERR_INTERNAL);
  if (skeylen <= npkey)
    return gpg_error (GPG_ERR_MISSING_VALUE);
  if (nskey+1 >= skeysize)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);

  /* Check that the public key parameters are all available and not
     encrypted.  */
  for (i=0; i < npkey; i++)
    {
      if (!skey[i] || gcry_mpi_get_flag (skey[i], GCRYMPI_FLAG_USER1))
        return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  if (r_npkey)
    *r_npkey = npkey;
  if (r_nskey)
    *r_nskey = nskey;
  if (r_skeylen)
    *r_skeylen = skeylen;
  return 0;
}


/* Note that this function modifies SKEY.  SKEYSIZE is the allocated
   size of the array including the NULL item; this is used for a
   bounds check.  On success a converted key is stored at R_KEY.  */
static int
do_unprotect (const char *passphrase,
              int pkt_version, int pubkey_algo, int is_protected,
              const char *curve, gcry_mpi_t *skey, size_t skeysize,
              int protect_algo, void *protect_iv, size_t protect_ivlen,
              int s2k_mode, int s2k_algo, byte *s2k_salt, u32 s2k_count,
              u16 desired_csum, gcry_sexp_t *r_key)
{
  gpg_error_t err;
  unsigned int npkey, nskey, skeylen;
  gcry_cipher_hd_t cipher_hd = NULL;
  u16 actual_csum;
  size_t nbytes;
  int i;
  gcry_mpi_t tmpmpi;

  *r_key = NULL;

  err = prepare_unprotect (pubkey_algo, skey, skeysize, s2k_mode,
                           &npkey, &nskey, &skeylen);
  if (err)
    return err;

  /* Check whether SKEY is at all protected.  If it is not protected
     merely verify the checksum.  */
  if (!is_protected)
    {
      actual_csum = 0;
      for (i=npkey; i < nskey; i++)
        {
          if (!skey[i] || gcry_mpi_get_flag (skey[i], GCRYMPI_FLAG_USER1))
            return gpg_error (GPG_ERR_BAD_SECKEY);

          if (gcry_mpi_get_flag (skey[i], GCRYMPI_FLAG_OPAQUE))
            {
              unsigned int nbits;
              const unsigned char *buffer;
              buffer = gcry_mpi_get_opaque (skey[i], &nbits);
              nbytes = (nbits+7)/8;
              actual_csum += checksum (buffer, nbytes);
            }
          else
            {
              unsigned char *buffer;

              err = gcry_mpi_aprint (GCRYMPI_FMT_PGP, &buffer, &nbytes,
                                     skey[i]);
              if (!err)
                actual_csum += checksum (buffer, nbytes);
              xfree (buffer);
            }
          if (err)
            return err;
        }

      if (actual_csum != desired_csum)
        return gpg_error (GPG_ERR_CHECKSUM);

      goto do_convert;
    }


  if (gcry_cipher_test_algo (protect_algo))
    {
      /* The algorithm numbers are Libgcrypt numbers but fortunately
         the OpenPGP algorithm numbers map one-to-one to the Libgcrypt
         numbers.  */
      log_info (_("protection algorithm %d (%s) is not supported\n"),
                protect_algo, gnupg_cipher_algo_name (protect_algo));
      return gpg_error (GPG_ERR_CIPHER_ALGO);
    }

  if (gcry_md_test_algo (s2k_algo))
    {
      log_info (_("protection hash algorithm %d (%s) is not supported\n"),
                s2k_algo, gcry_md_algo_name (s2k_algo));
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  err = gcry_cipher_open (&cipher_hd, protect_algo,
                          GCRY_CIPHER_MODE_CFB,
                          (GCRY_CIPHER_SECURE
                           | (protect_algo >= 100 ?
                              0 : GCRY_CIPHER_ENABLE_SYNC)));
  if (err)
    {
      log_error ("failed to open cipher_algo %d: %s\n",
                 protect_algo, gpg_strerror (err));
      return err;
    }

  err = hash_passphrase_and_set_key (passphrase, cipher_hd, protect_algo,
                                     s2k_mode, s2k_algo, s2k_salt, s2k_count);
  if (err)
    {
      gcry_cipher_close (cipher_hd);
      return err;
    }

  gcry_cipher_setiv (cipher_hd, protect_iv, protect_ivlen);

  actual_csum = 0;
  if (pkt_version >= 4)
    {
      int ndata;
      unsigned int ndatabits;
      const unsigned char *p;
      unsigned char *data;
      u16 csum_pgp7 = 0;

      if (!gcry_mpi_get_flag (skey[npkey], GCRYMPI_FLAG_OPAQUE ))
        {
          gcry_cipher_close (cipher_hd);
          return gpg_error (GPG_ERR_BAD_SECKEY);
        }
      p = gcry_mpi_get_opaque (skey[npkey], &ndatabits);
      ndata = (ndatabits+7)/8;

      if (ndata > 1)
        csum_pgp7 = buf16_to_u16 (p+ndata-2);
      data = xtrymalloc_secure (ndata);
      if (!data)
        {
          err = gpg_error_from_syserror ();
          gcry_cipher_close (cipher_hd);
          return err;
        }
      gcry_cipher_decrypt (cipher_hd, data, ndata, p, ndata);

      p = data;
      if (is_protected == 2)
        {
          /* This is the new SHA1 checksum method to detect tampering
             with the key as used by the Klima/Rosa attack.  */
          desired_csum = 0;
          actual_csum = 1;  /* Default to bad checksum.  */

          if (ndata < 20)
            log_error ("not enough bytes for SHA-1 checksum\n");
          else
            {
              gcry_md_hd_t h;

              if (gcry_md_open (&h, GCRY_MD_SHA1, 1))
                BUG(); /* Algo not available. */
              gcry_md_write (h, data, ndata - 20);
              gcry_md_final (h);
              if (!memcmp (gcry_md_read (h, GCRY_MD_SHA1), data+ndata-20, 20))
                actual_csum = 0; /* Digest does match.  */
              gcry_md_close (h);
            }
        }
      else
        {
          /* Old 16 bit checksum method.  */
          if (ndata < 2)
            {
              log_error ("not enough bytes for checksum\n");
              desired_csum = 0;
              actual_csum = 1;  /* Mark checksum bad.  */
            }
          else
            {
              desired_csum = buf16_to_u16 (data+ndata-2);
              actual_csum = checksum (data, ndata-2);
              if (desired_csum != actual_csum)
                {
                  /* This is a PGP 7.0.0 workaround */
                  desired_csum = csum_pgp7; /* Take the encrypted one.  */
                }
            }
        }

      /* Better check it here.  Otherwise the gcry_mpi_scan would fail
         because the length may have an arbitrary value.  */
      if (desired_csum == actual_csum)
        {
          for (i=npkey; i < nskey; i++ )
            {
              if (gcry_mpi_scan (&tmpmpi, GCRYMPI_FMT_PGP, p, ndata, &nbytes))
                {
                  /* Checksum was okay, but not correctly decrypted.  */
                  desired_csum = 0;
                  actual_csum = 1;   /* Mark checksum bad.  */
                  break;
                }
              gcry_mpi_release (skey[i]);
              skey[i] = tmpmpi;
              ndata -= nbytes;
              p += nbytes;
            }
          skey[i] = NULL;
          skeylen = i;
          assert (skeylen <= skeysize);

          /* Note: at this point NDATA should be 2 for a simple
             checksum or 20 for the sha1 digest.  */
        }
      xfree(data);
    }
  else /* Packet version <= 3.  */
    {
      unsigned char *buffer;

      for (i = npkey; i < nskey; i++)
        {
          const unsigned char *p;
          size_t ndata;
          unsigned int ndatabits;

          if (!skey[i] || !gcry_mpi_get_flag (skey[i], GCRYMPI_FLAG_OPAQUE))
            {
              gcry_cipher_close (cipher_hd);
              return gpg_error (GPG_ERR_BAD_SECKEY);
            }
          p = gcry_mpi_get_opaque (skey[i], &ndatabits);
          ndata = (ndatabits+7)/8;

          if (!(ndata >= 2) || !(ndata == (buf16_to_ushort (p) + 7)/8 + 2))
            {
              gcry_cipher_close (cipher_hd);
              return gpg_error (GPG_ERR_BAD_SECKEY);
            }

          buffer = xtrymalloc_secure (ndata);
          if (!buffer)
            {
              err = gpg_error_from_syserror ();
              gcry_cipher_close (cipher_hd);
              return err;
            }

          gcry_cipher_sync (cipher_hd);
          buffer[0] = p[0];
          buffer[1] = p[1];
          gcry_cipher_decrypt (cipher_hd, buffer+2, ndata-2, p+2, ndata-2);
          actual_csum += checksum (buffer, ndata);
          err = gcry_mpi_scan (&tmpmpi, GCRYMPI_FMT_PGP, buffer, ndata, &ndata);
          xfree (buffer);
          if (err)
            {
              /* Checksum was okay, but not correctly decrypted.  */
              desired_csum = 0;
              actual_csum = 1;   /* Mark checksum bad.  */
              break;
            }
          gcry_mpi_release (skey[i]);
          skey[i] = tmpmpi;
        }
    }
  gcry_cipher_close (cipher_hd);

  /* Now let's see whether we have used the correct passphrase. */
  if (actual_csum != desired_csum)
    return gpg_error (GPG_ERR_BAD_PASSPHRASE);

 do_convert:
  if (nskey != skeylen)
    err = gpg_error (GPG_ERR_BAD_SECKEY);
  else
    err = convert_secret_key (r_key, pubkey_algo, skey, curve);
  if (err)
    return err;

  /* The checksum may fail, thus we also check the key itself.  */
  err = gcry_pk_testkey (*r_key);
  if (err)
    {
      gcry_sexp_release (*r_key);
      *r_key = NULL;
      return gpg_error (GPG_ERR_BAD_PASSPHRASE);
    }

  return 0;
}


/* Callback function to try the unprotection from the passphrase query
   code.  */
static gpg_error_t
try_do_unprotect_cb (struct pin_entry_info_s *pi)
{
  gpg_error_t err;
  struct try_do_unprotect_arg_s *arg = pi->check_cb_arg;

  err = do_unprotect (pi->pin,
                      arg->is_v4? 4:3,
                      arg->pubkey_algo, arg->is_protected,
                      arg->curve,
                      arg->skey, arg->skeysize,
                      arg->protect_algo, arg->iv, arg->ivlen,
                      arg->s2k_mode, arg->s2k_algo,
                      arg->s2k_salt, arg->s2k_count,
                      arg->desired_csum, arg->r_key);
  /* SKEY may be modified now, thus we need to re-compute SKEYIDX.  */
  for (arg->skeyidx = 0; (arg->skeyidx < arg->skeysize
                          && arg->skey[arg->skeyidx]); arg->skeyidx++)
    ;
  return err;
}


/* See convert_from_openpgp for the core of the description.  This
   function adds an optional PASSPHRASE argument and uses this to
   silently decrypt the key; CACHE_NONCE and R_PASSPHRASE must both be
   NULL in this mode.  */
static gpg_error_t
convert_from_openpgp_main (ctrl_t ctrl, gcry_sexp_t s_pgp, int dontcare_exist,
                           unsigned char *grip, const char *prompt,
                           const char *cache_nonce, const char *passphrase,
                           unsigned char **r_key, char **r_passphrase)
{
  gpg_error_t err;
  int unattended;
  int from_native;
  gcry_sexp_t top_list;
  gcry_sexp_t list = NULL;
  const char *value;
  size_t valuelen;
  char *string;
  int  idx;
  int  is_v4, is_protected;
  int  pubkey_algo;
  int  protect_algo = 0;
  char iv[16];
  int  ivlen = 0;
  int  s2k_mode = 0;
  int  s2k_algo = 0;
  byte s2k_salt[8];
  u32  s2k_count = 0;
  size_t npkey, nskey;
  gcry_mpi_t skey[10];  /* We support up to 9 parameters.  */
  char *curve = NULL;
  u16 desired_csum;
  int skeyidx = 0;
  gcry_sexp_t s_skey = NULL;

  *r_key = NULL;
  if (r_passphrase)
    *r_passphrase = NULL;
  unattended = !r_passphrase;
  from_native = (!cache_nonce && passphrase && !r_passphrase);

  top_list = gcry_sexp_find_token (s_pgp, "openpgp-private-key", 0);
  if (!top_list)
    goto bad_seckey;

  list = gcry_sexp_find_token (top_list, "version", 0);
  if (!list)
    goto bad_seckey;
  value = gcry_sexp_nth_data (list, 1, &valuelen);
  if (!value || valuelen != 1 || !(value[0] == '3' || value[0] == '4'))
    goto bad_seckey;
  is_v4 = (value[0] == '4');

  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "protection", 0);
  if (!list)
    goto bad_seckey;
  value = gcry_sexp_nth_data (list, 1, &valuelen);
  if (!value)
    goto bad_seckey;
  if (valuelen == 4 && !memcmp (value, "sha1", 4))
    is_protected = 2;
  else if (valuelen == 3 && !memcmp (value, "sum", 3))
    is_protected = 1;
  else if (valuelen == 4 && !memcmp (value, "none", 4))
    is_protected = 0;
  else
    goto bad_seckey;

  if (is_protected)
    {
      string = gcry_sexp_nth_string (list, 2);
      if (!string)
        goto bad_seckey;
      protect_algo = gcry_cipher_map_name (string);
      xfree (string);

      value = gcry_sexp_nth_data (list, 3, &valuelen);
      if (!value || !valuelen || valuelen > sizeof iv)
        goto bad_seckey;
      memcpy (iv, value, valuelen);
      ivlen = valuelen;

      string = gcry_sexp_nth_string (list, 4);
      if (!string)
        goto bad_seckey;
      s2k_mode = strtol (string, NULL, 10);
      xfree (string);

      string = gcry_sexp_nth_string (list, 5);
      if (!string)
        goto bad_seckey;
      s2k_algo = gcry_md_map_name (string);
      xfree (string);

      value = gcry_sexp_nth_data (list, 6, &valuelen);
      if (!value || !valuelen || valuelen > sizeof s2k_salt)
        goto bad_seckey;
      memcpy (s2k_salt, value, valuelen);

      string = gcry_sexp_nth_string (list, 7);
      if (!string)
        goto bad_seckey;
      s2k_count = strtoul (string, NULL, 10);
      xfree (string);
    }

  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "algo", 0);
  if (!list)
    goto bad_seckey;
  string = gcry_sexp_nth_string (list, 1);
  if (!string)
    goto bad_seckey;
  pubkey_algo = gcry_pk_map_name (string);
  xfree (string);

  get_npkey_nskey (pubkey_algo, &npkey, &nskey);
  if (!npkey || !nskey || npkey >= nskey)
    goto bad_seckey;

  if (npkey == 1) /* This is ECC */
    {
      gcry_sexp_release (list);
      list = gcry_sexp_find_token (top_list, "curve", 0);
      if (!list)
        goto bad_seckey;
      curve = gcry_sexp_nth_string (list, 1);
      if (!curve)
        goto bad_seckey;
    }

  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "skey", 0);
  if (!list)
    goto bad_seckey;
  for (idx=0;;)
    {
      int is_enc;

      value = gcry_sexp_nth_data (list, ++idx, &valuelen);
      if (!value && skeyidx >= npkey)
        break;  /* Ready.  */

      /* Check for too many parameters.  Note that depending on the
         protection mode and version number we may see less than NSKEY
         (but at least NPKEY+1) parameters.  */
      if (idx >= 2*nskey)
        goto bad_seckey;
      if (skeyidx >= DIM (skey)-1)
        goto bad_seckey;

      if (!value || valuelen != 1 || !(value[0] == '_' || value[0] == 'e'))
        goto bad_seckey;
      is_enc = (value[0] == 'e');
      value = gcry_sexp_nth_data (list, ++idx, &valuelen);
      if (!value || !valuelen)
        goto bad_seckey;
      if (is_enc)
        {
          /* Encrypted parameters need to be stored as opaque.  */
          skey[skeyidx] = gcry_mpi_set_opaque_copy (NULL, value, valuelen*8);
          if (!skey[skeyidx])
            goto outofmem;
          gcry_mpi_set_flag (skey[skeyidx], GCRYMPI_FLAG_USER1);
        }
      else
        {
          if (gcry_mpi_scan (skey + skeyidx, GCRYMPI_FMT_STD,
                             value, valuelen, NULL))
            goto bad_seckey;
        }
      skeyidx++;
    }
  skey[skeyidx++] = NULL;

  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "csum", 0);
  if (list)
    {
      string = gcry_sexp_nth_string (list, 1);
      if (!string)
        goto bad_seckey;
      desired_csum = strtoul (string, NULL, 10);
      xfree (string);
    }
  else
    desired_csum = 0;


  gcry_sexp_release (list); list = NULL;
  gcry_sexp_release (top_list); top_list = NULL;

#if 0
  log_debug ("XXX is_v4=%d\n", is_v4);
  log_debug ("XXX pubkey_algo=%d\n", pubkey_algo);
  log_debug ("XXX is_protected=%d\n", is_protected);
  log_debug ("XXX protect_algo=%d\n", protect_algo);
  log_printhex ("XXX iv", iv, ivlen);
  log_debug ("XXX ivlen=%d\n", ivlen);
  log_debug ("XXX s2k_mode=%d\n", s2k_mode);
  log_debug ("XXX s2k_algo=%d\n", s2k_algo);
  log_printhex ("XXX s2k_salt", s2k_salt, sizeof s2k_salt);
  log_debug ("XXX s2k_count=%lu\n", (unsigned long)s2k_count);
  log_debug ("XXX curve='%s'\n", curve);
  for (idx=0; skey[idx]; idx++)
    gcry_log_debugmpi (gcry_mpi_get_flag (skey[idx], GCRYMPI_FLAG_USER1)
                       ? "skey(e)" : "skey(_)", skey[idx]);
#endif /*0*/

  err = get_keygrip (pubkey_algo, curve, skey, grip);
  if (err)
    goto leave;

  if (!dontcare_exist && !from_native && !agent_key_available (grip))
    {
      err = gpg_error (GPG_ERR_EEXIST);
      goto leave;
    }

  if (unattended && !from_native)
    {
      err = prepare_unprotect (pubkey_algo, skey, DIM(skey), s2k_mode,
                               NULL, NULL, NULL);
      if (err)
        goto leave;

      err = convert_transfer_key (&s_skey, pubkey_algo, skey, curve, s_pgp);
      if (err)
        goto leave;
    }
  else
    {
      struct pin_entry_info_s *pi;
      struct try_do_unprotect_arg_s pi_arg;

      pi = xtrycalloc_secure (1, sizeof (*pi) + MAX_PASSPHRASE_LEN + 1);
      if (!pi)
        return gpg_error_from_syserror ();
      pi->max_length = MAX_PASSPHRASE_LEN + 1;
      pi->min_digits = 0;  /* We want a real passphrase.  */
      pi->max_digits = 16;
      pi->max_tries = 3;
      pi->check_cb = try_do_unprotect_cb;
      pi->check_cb_arg = &pi_arg;
      pi_arg.is_v4 = is_v4;
      pi_arg.is_protected = is_protected;
      pi_arg.pubkey_algo = pubkey_algo;
      pi_arg.curve = curve;
      pi_arg.protect_algo = protect_algo;
      pi_arg.iv = iv;
      pi_arg.ivlen = ivlen;
      pi_arg.s2k_mode = s2k_mode;
      pi_arg.s2k_algo = s2k_algo;
      pi_arg.s2k_salt = s2k_salt;
      pi_arg.s2k_count = s2k_count;
      pi_arg.desired_csum = desired_csum;
      pi_arg.skey = skey;
      pi_arg.skeysize = DIM (skey);
      pi_arg.skeyidx = skeyidx;
      pi_arg.r_key = &s_skey;

      err = gpg_error (GPG_ERR_BAD_PASSPHRASE);
      if (!is_protected)
        {
          err = try_do_unprotect_cb (pi);
        }
      else if (cache_nonce)
        {
          char *cache_value;

          cache_value = agent_get_cache (cache_nonce, CACHE_MODE_NONCE);
          if (cache_value)
            {
              if (strlen (cache_value) < pi->max_length)
                strcpy (pi->pin, cache_value);
              xfree (cache_value);
            }
          if (*pi->pin)
            err = try_do_unprotect_cb (pi);
        }
      else if (from_native)
        {
          if (strlen (passphrase) < pi->max_length)
            strcpy (pi->pin, passphrase);
          err = try_do_unprotect_cb (pi);
        }
      if (gpg_err_code (err) == GPG_ERR_BAD_PASSPHRASE && !from_native)
        err = agent_askpin (ctrl, prompt, NULL, NULL, pi, NULL, 0);
      skeyidx = pi_arg.skeyidx;
      if (!err && r_passphrase && is_protected)
        {
          *r_passphrase = xtrystrdup (pi->pin);
          if (!*r_passphrase)
            err = gpg_error_from_syserror ();
        }
      xfree (pi);
      if (err)
        goto leave;
    }

  /* Save some memory and get rid of the SKEY array now.  */
  for (idx=0; idx < skeyidx; idx++)
    gcry_mpi_release (skey[idx]);
  skeyidx = 0;

  /* Note that the padding is not required - we use it only because
     that function allows us to create the result in secure memory.  */
  err = make_canon_sexp_pad (s_skey, 1, r_key, NULL);

 leave:
  xfree (curve);
  gcry_sexp_release (s_skey);
  gcry_sexp_release (list);
  gcry_sexp_release (top_list);
  for (idx=0; idx < skeyidx; idx++)
    gcry_mpi_release (skey[idx]);
  if (err && r_passphrase)
    {
      xfree (*r_passphrase);
      *r_passphrase = NULL;
    }
  return err;

 bad_seckey:
  err = gpg_error (GPG_ERR_BAD_SECKEY);
  goto leave;

 outofmem:
  err = gpg_error (GPG_ERR_ENOMEM);
  goto leave;

}


/* Convert an OpenPGP transfer key into our internal format.  Before
   asking for a passphrase we check whether the key already exists in
   our key storage.  S_PGP is the OpenPGP key in transfer format.  If
   CACHE_NONCE is given the passphrase will be looked up in the cache.
   On success R_KEY will receive a canonical encoded S-expression with
   the unprotected key in our internal format; the caller needs to
   release that memory.  The passphrase used to decrypt the OpenPGP
   key will be returned at R_PASSPHRASE; the caller must release this
   passphrase.  If R_PASSPHRASE is NULL the unattended conversion mode
   will be used which uses the openpgp-native protection format for
   the key.  The keygrip will be stored at the 20 byte buffer pointed
   to by GRIP.  On error NULL is stored at all return arguments.  */
gpg_error_t
convert_from_openpgp (ctrl_t ctrl, gcry_sexp_t s_pgp, int dontcare_exist,
                      unsigned char *grip, const char *prompt,
                      const char *cache_nonce,
                      unsigned char **r_key, char **r_passphrase)
{
  return convert_from_openpgp_main (ctrl, s_pgp, dontcare_exist, grip, prompt,
                                    cache_nonce, NULL,
                                    r_key, r_passphrase);
}

/* This function is called by agent_unprotect to re-protect an
   openpgp-native protected private-key into the standard private-key
   protection format.  */
gpg_error_t
convert_from_openpgp_native (ctrl_t ctrl,
                             gcry_sexp_t s_pgp, const char *passphrase,
                             unsigned char **r_key)
{
  gpg_error_t err;
  unsigned char grip[20];

  if (!passphrase)
    return gpg_error (GPG_ERR_INTERNAL);

  err = convert_from_openpgp_main (ctrl, s_pgp, 0, grip, NULL,
                                   NULL, passphrase,
                                   r_key, NULL);

  /* On success try to re-write the key.  */
  if (!err)
    {
      if (*passphrase)
        {
          unsigned char *protectedkey = NULL;
          size_t protectedkeylen;

          if (!agent_protect (*r_key, passphrase,
                              &protectedkey, &protectedkeylen,
                              ctrl->s2k_count, -1))
            agent_write_private_key (grip, protectedkey, protectedkeylen, 1);
          xfree (protectedkey);
        }
      else
        {
          /* Empty passphrase: write key without protection.  */
          agent_write_private_key (grip,
                                   *r_key,
                                   gcry_sexp_canon_len (*r_key, 0, NULL,NULL),
                                   1);
        }
    }

  return err;
}


/* Given an ARRAY of mpis with the key parameters, protect the secret
   parameters in that array and replace them by one opaque encoded
   mpi.  NPKEY is the number of public key parameters and NSKEY is
   the number of secret key parameters (including the public ones).
   On success the array will have NPKEY+1 elements.  */
static gpg_error_t
apply_protection (gcry_mpi_t *array, int npkey, int nskey,
                  const char *passphrase,
                  int protect_algo, void *protect_iv, size_t protect_ivlen,
                  int s2k_mode, int s2k_algo, byte *s2k_salt, u32 s2k_count)
{
  gpg_error_t err;
  int i, j;
  gcry_cipher_hd_t cipherhd;
  unsigned char *bufarr[10];
  size_t narr[10];
  unsigned int nbits[10];
  int ndata;
  unsigned char *p, *data;

  assert (npkey < nskey);
  assert (nskey < DIM (bufarr));

  /* Collect only the secret key parameters into BUFARR et al and
     compute the required size of the data buffer.  */
  ndata = 20; /* Space for the SHA-1 checksum.  */
  for (i = npkey, j = 0; i < nskey; i++, j++ )
    {
      err = gcry_mpi_aprint (GCRYMPI_FMT_USG, bufarr+j, narr+j, array[i]);
      if (err)
        {
          for (i = 0; i < j; i++)
            xfree (bufarr[i]);
          return err;
        }
      nbits[j] = gcry_mpi_get_nbits (array[i]);
      ndata += 2 + narr[j];
    }

  /* Allocate data buffer and stuff it with the secret key parameters.  */
  data = xtrymalloc_secure (ndata);
  if (!data)
    {
      err = gpg_error_from_syserror ();
      for (i = 0; i < (nskey-npkey); i++ )
        xfree (bufarr[i]);
      return err;
    }
  p = data;
  for (i = 0; i < (nskey-npkey); i++ )
    {
      *p++ = nbits[i] >> 8 ;
      *p++ = nbits[i];
      memcpy (p, bufarr[i], narr[i]);
      p += narr[i];
      xfree (bufarr[i]);
      bufarr[i] = NULL;
    }
  assert (p == data + ndata - 20);

  /* Append a hash of the secret key parameters.  */
  gcry_md_hash_buffer (GCRY_MD_SHA1, p, data, ndata - 20);

  /* Encrypt it.  */
  err = gcry_cipher_open (&cipherhd, protect_algo,
                          GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
  if (!err)
    err = hash_passphrase_and_set_key (passphrase, cipherhd, protect_algo,
                                       s2k_mode, s2k_algo, s2k_salt, s2k_count);
  if (!err)
    err = gcry_cipher_setiv (cipherhd, protect_iv, protect_ivlen);
  if (!err)
    err = gcry_cipher_encrypt (cipherhd, data, ndata, NULL, 0);
  gcry_cipher_close (cipherhd);
  if (err)
    {
      xfree (data);
      return err;
    }

  /* Replace the secret key parameters in the array by one opaque value.  */
  for (i = npkey; i < nskey; i++ )
    {
      gcry_mpi_release (array[i]);
      array[i] = NULL;
    }
  array[npkey] = gcry_mpi_set_opaque (NULL, data, ndata*8);
  return 0;
}


/*
 * Examining S_KEY in S-Expression and extract data.
 * When REQ_PRIVATE_KEY_DATA == 1, S_KEY's CAR should be 'private-key',
 * but it also allows shadowed or protected versions.
 * On success, it returns 0, otherwise error number.
 * R_ALGONAME is static string which is no need to free by caller.
 * R_NPKEY is pointer to number of public key data.
 * R_NSKEY is pointer to number of private key data.
 * R_ELEMS is static string which is no need to free by caller.
 * ARRAY contains public and private key data.
 * ARRAYSIZE is the allocated size of the array for cross-checking.
 * R_CURVE is pointer to S-Expression of the curve (can be NULL).
 * R_FLAGS is pointer to S-Expression of the flags (can be NULL).
 */
gpg_error_t
extract_private_key (gcry_sexp_t s_key, int req_private_key_data,
                     const char **r_algoname, int *r_npkey, int *r_nskey,
                     const char **r_elems,
                     gcry_mpi_t *array, int arraysize,
                     gcry_sexp_t *r_curve, gcry_sexp_t *r_flags)
{
  gpg_error_t err;
  gcry_sexp_t list, l2;
  char *name;
  const char *algoname, *format;
  int npkey, nskey;
  gcry_sexp_t curve = NULL;
  gcry_sexp_t flags = NULL;

  *r_curve = NULL;
  *r_flags = NULL;

  if (!req_private_key_data)
    {
      list = gcry_sexp_find_token (s_key, "shadowed-private-key", 0 );
      if (!list)
        list = gcry_sexp_find_token (s_key, "protected-private-key", 0 );
      if (!list)
        list = gcry_sexp_find_token (s_key, "private-key", 0 );
    }
  else
    list = gcry_sexp_find_token (s_key, "private-key", 0);

  if (!list)
    {
      log_error ("invalid private key format\n");
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  name = gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      gcry_sexp_release (list);
      return gpg_error (GPG_ERR_INV_OBJ); /* Invalid structure of object. */
    }

  if (arraysize < 7)
    BUG ();

  /* Map NAME to a name as used by Libgcrypt.  We do not use the
     Libgcrypt function here because we need a lowercase name and
     require special treatment for some algorithms.  */
  strlwr (name);
  if (!strcmp (name, "rsa"))
    {
      algoname = "rsa";
      format = "ned?p?q?u?";
      npkey = 2;
      nskey = 6;
      err = gcry_sexp_extract_param (list, NULL, format,
                                     array+0, array+1, array+2, array+3,
                                     array+4, array+5, NULL);
    }
  else if (!strcmp (name, "elg"))
    {
      algoname = "elg";
      format = "pgyx?";
      npkey = 3;
      nskey = 4;
      err = gcry_sexp_extract_param (list, NULL, format,
                                     array+0, array+1, array+2, array+3,
                                     NULL);
    }
  else if (!strcmp (name, "dsa"))
    {
      algoname = "dsa";
      format = "pqgyx?";
      npkey = 4;
      nskey = 5;
      err = gcry_sexp_extract_param (list, NULL, format,
                                     array+0, array+1, array+2, array+3,
                                     array+4, NULL);
    }
  else if (!strcmp (name, "ecc") || !strcmp (name, "ecdsa"))
    {
      algoname = "ecc";
      format = "qd?";
      npkey = 1;
      nskey = 2;
      curve = gcry_sexp_find_token (list, "curve", 0);
      flags = gcry_sexp_find_token (list, "flags", 0);
      err = gcry_sexp_extract_param (list, NULL, format,
                                     array+0, array+1, NULL);
    }
  else
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
    }
  xfree (name);
  gcry_sexp_release (list);
  if (err)
    {
      gcry_sexp_release (curve);
      gcry_sexp_release (flags);
      return err;
    }
  else
    {
      *r_algoname = algoname;
      if (r_elems)
        *r_elems = format;
      *r_npkey = npkey;
      if (r_nskey)
        *r_nskey = nskey;
      *r_curve = curve;
      *r_flags = flags;

      return 0;
    }
}

/* Convert our key S_KEY into an OpenPGP key transfer format.  On
   success a canonical encoded S-expression is stored at R_TRANSFERKEY
   and its length at R_TRANSFERKEYLEN; this S-expression is also
   padded to a multiple of 64 bits.  */
gpg_error_t
convert_to_openpgp (ctrl_t ctrl, gcry_sexp_t s_key, const char *passphrase,
                    unsigned char **r_transferkey, size_t *r_transferkeylen)
{
  gpg_error_t err;
  const char *algoname;
  int npkey, nskey;
  gcry_mpi_t array[10];
  gcry_sexp_t curve = NULL;
  gcry_sexp_t flags = NULL;
  char protect_iv[16];
  char salt[8];
  unsigned long s2k_count;
  int i, j;

  (void)ctrl;

  *r_transferkey = NULL;

  for (i=0; i < DIM (array); i++)
    array[i] = NULL;

  err = extract_private_key (s_key, 1, &algoname, &npkey, &nskey, NULL,
                             array, DIM (array), &curve, &flags);
  if (err)
    return err;

  gcry_create_nonce (protect_iv, sizeof protect_iv);
  gcry_create_nonce (salt, sizeof salt);
  /* We need to use the encoded S2k count.  It is not possible to
     encode it after it has been used because the encoding procedure
     may round the value up.  */
  s2k_count = get_standard_s2k_count_rfc4880 ();
  err = apply_protection (array, npkey, nskey, passphrase,
                          GCRY_CIPHER_AES, protect_iv, sizeof protect_iv,
                          3, GCRY_MD_SHA1, salt, s2k_count);
  /* Turn it into the transfer key S-expression.  Note that we always
     return a protected key.  */
  if (!err)
    {
      char countbuf[35];
      membuf_t mbuf;
      void *format_args[10+2];
      gcry_sexp_t tmpkey;
      gcry_sexp_t tmpsexp = NULL;

      snprintf (countbuf, sizeof countbuf, "%lu", s2k_count);

      init_membuf (&mbuf, 50);
      put_membuf_str (&mbuf, "(skey");
      for (i=j=0; i < npkey; i++)
        {
          put_membuf_str (&mbuf, " _ %m");
          format_args[j++] = array + i;
        }
      put_membuf_str (&mbuf, " e %m");
      format_args[j++] = array + npkey;
      put_membuf_str (&mbuf, ")\n");
      put_membuf (&mbuf, "", 1);

      tmpkey = NULL;
      {
        char *format = get_membuf (&mbuf, NULL);
        if (!format)
          err = gpg_error_from_syserror ();
        else
          err = gcry_sexp_build_array (&tmpkey, NULL, format, format_args);
        xfree (format);
      }
      if (!err)
        err = gcry_sexp_build (&tmpsexp, NULL,
                               "(openpgp-private-key\n"
                               " (version 1:4)\n"
                               " (algo %s)\n"
                               " %S%S\n"
                               " (protection sha1 aes %b 1:3 sha1 %b %s))\n",
                               algoname,
                               curve,
                               tmpkey,
                               (int)sizeof protect_iv, protect_iv,
                               (int)sizeof salt, salt,
                               countbuf);
      gcry_sexp_release (tmpkey);
      if (!err)
        err = make_canon_sexp_pad (tmpsexp, 0, r_transferkey, r_transferkeylen);
      gcry_sexp_release (tmpsexp);
    }

  for (i=0; i < DIM (array); i++)
    gcry_mpi_release (array[i]);
  gcry_sexp_release (curve);
  gcry_sexp_release (flags);

  return err;
}
