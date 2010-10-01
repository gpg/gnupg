/* cvt-openpgp.c - Convert an OpenPGP key to our internal format.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2006, 2009,
 *               2010 Free Software Foundation, Inc.
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

#include "agent.h"
#include "i18n.h"
#include "cvt-openpgp.h"


/* Helper to pass data via the callback to do_unprotect. */
struct try_do_unprotect_arg_s 
{
  int  is_v4;
  int  is_protected;
  int  pubkey_algo;
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
get_keygrip (int pubkey_algo, gcry_mpi_t *pkey, unsigned char *grip)
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
    case GCRY_PK_ELG_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(elg(p%m)(g%m)(y%m)))",
                             pkey[0], pkey[1], pkey[2]);
      break;

    case GCRY_PK_RSA:
    case GCRY_PK_RSA_E:
    case GCRY_PK_RSA_S:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(rsa(n%m)(e%m)))", pkey[0], pkey[1]);
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
   parameters into our s-expression based format.  */
static gpg_error_t
convert_secret_key (gcry_sexp_t *r_key, int pubkey_algo, gcry_mpi_t *skey)
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


/* Note that this function modified SKEY.  SKEYSIZE is the allocated
   size of the array including the NULL item; this is used for a
   bounds check.  On success a converted key is stored at R_KEY.  */
static int
do_unprotect (const char *passphrase,
              int pkt_version, int pubkey_algo, int is_protected,
              gcry_mpi_t *skey, size_t skeysize,
              int protect_algo, void *protect_iv, size_t protect_ivlen,
              int s2k_mode, int s2k_algo, byte *s2k_salt, u32 s2k_count,
              u16 desired_csum, gcry_sexp_t *r_key)
{
  gpg_error_t err;
  size_t npkey, nskey, skeylen;
  gcry_cipher_hd_t cipher_hd = NULL;
  u16 actual_csum;
  size_t nbytes;
  int i;
  gcry_mpi_t tmpmpi;

  *r_key = NULL;

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
      /* The algorithm numbers are Libgcrypt numbers but fortunately
         the OpenPGP algorithm numbers map one-to-one to the Libgcrypt
         numbers.  */
      log_info (_("public key algorithm %d (%s) is not supported\n"),
                pubkey_algo, gcry_pk_algo_name (pubkey_algo));
      return gpg_error (GPG_ERR_PUBKEY_ALGO);
    }

  /* Get properties of the public key algorithm and do some
     consistency checks.  Note that we need at least NPKEY+1 elements
     in the SKEY array. */
  if ( (err = gcry_pk_algo_info (pubkey_algo, GCRYCTL_GET_ALGO_NPKEY,
                                 NULL, &npkey))
       || (err = gcry_pk_algo_info (pubkey_algo, GCRYCTL_GET_ALGO_NSKEY,
                                    NULL, &nskey)))
    return err;
  if (!npkey || npkey >= nskey)
    return gpg_error (GPG_ERR_INTERNAL);
  if (skeylen <= npkey)
    return gpg_error (GPG_ERR_MISSING_VALUE);
  if (nskey+1 >= skeysize)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
  
  /* Check whether SKEY is at all protected.  If it is not protected
     merely verify the checksum.  */
  if (!is_protected)
    {
      unsigned char *buffer;

      actual_csum = 0;
      for (i=npkey; i < nskey; i++)
        {
          if (!skey[i] || gcry_mpi_get_flag (skey[i], GCRYMPI_FLAG_OPAQUE))
            return gpg_error (GPG_ERR_BAD_SECKEY);
          
          err = gcry_mpi_print (GCRYMPI_FMT_PGP, NULL, 0, &nbytes, skey[i]);
          if (!err)
            {
              buffer = (gcry_is_secure (skey[i])?
                        xtrymalloc_secure (nbytes) : xtrymalloc (nbytes));
              if (!buffer)
                return gpg_error_from_syserror ();
              err = gcry_mpi_print (GCRYMPI_FMT_PGP, buffer, nbytes,
                                    NULL, skey[i]);
              if (!err)
                actual_csum += checksum (buffer, nbytes);
              xfree (buffer);
            }
          if (err)
            return err;
        }
      
      if (actual_csum != desired_csum)
        return gpg_error (GPG_ERR_CHECKSUM);
      return 0;
    }


  if (gcry_cipher_test_algo (protect_algo))
    {
      /* The algorithm numbers are Libgcrypt numbers but fortunately
         the OpenPGP algorithm numbers map one-to-one to the Libgcrypt
         numbers.  */
      log_info (_("protection algorithm %d (%s) is not supported\n"),
                protect_algo, gcry_cipher_algo_name (protect_algo));
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
      unsigned char *p, *data;
      u16 csum_pgp7 = 0;

      if (!gcry_mpi_get_flag (skey[npkey], GCRYMPI_FLAG_OPAQUE ))
        {
          gcry_cipher_close (cipher_hd);
          return gpg_error (GPG_ERR_BAD_SECKEY);
        }
      p = gcry_mpi_get_opaque (skey[npkey], &ndatabits);
      ndata = (ndatabits+7)/8;

      if (ndata > 1)
        csum_pgp7 = p[ndata-2] << 8 | p[ndata-1];
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
              desired_csum = (data[ndata-2] << 8 | data[ndata-1]);
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
          unsigned char *p;
          size_t ndata;
          unsigned int ndatabits;

          if (!skey[i] || !gcry_mpi_get_flag (skey[i], GCRYMPI_FLAG_OPAQUE))
            {
              gcry_cipher_close (cipher_hd);
              return gpg_error (GPG_ERR_BAD_SECKEY);
            }
          p = gcry_mpi_get_opaque (skey[i], &ndatabits);
          ndata = (ndatabits+7)/8;

          if (!(ndata >= 2) || !(ndata == ((p[0] << 8 | p[1]) + 7)/8 + 2))
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

  if (nskey != skeylen)
    err = gpg_error (GPG_ERR_BAD_SECKEY);
  else
    err = convert_secret_key (r_key, pubkey_algo, skey);
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


/* Callback function to try the unprotection from the passpharse query
   code.  */
static int
try_do_unprotect_cb (struct pin_entry_info_s *pi)
{
  gpg_error_t err;
  struct try_do_unprotect_arg_s *arg = pi->check_cb_arg;

  err = do_unprotect (pi->pin,
                      arg->is_v4? 4:3,
                      arg->pubkey_algo, arg->is_protected,
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


/* Convert an OpenPGP transfer key into our internal format.  Before
   asking for a passphrase we check whether the key already exists in
   our key storage.  S_PGP is the OpenPGP key in transfer format.  If
   CACHE_NONCE is given the passphrase will be looked up in the cache.
   On success R_KEY will receive a canonical encoded S-expression with
   the unprotected key in our internal format; the caller needs to
   release that memory.  The passphrase used to decrypt the OpenPGP
   key will be returned at R_PASSPHRASE; the caller must release this
   passphrase.  The keygrip will be stored at the 20 byte buffer
   pointed to by GRIP.  On error NULL is stored at all return
   arguments.  */
gpg_error_t
convert_from_openpgp (ctrl_t ctrl, gcry_sexp_t s_pgp, 
                      unsigned char *grip, const char *prompt,
                      const char *cache_nonce,
                      unsigned char **r_key, char **r_passphrase)
{
  gpg_error_t err;
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
  u16 desired_csum;
  int skeyidx = 0;
  gcry_sexp_t s_skey;
  struct pin_entry_info_s *pi;
  struct try_do_unprotect_arg_s pi_arg;

  *r_key = NULL;
  *r_passphrase = NULL;

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
      if (!protect_algo && !!strcmp (string, "IDEA"))
        protect_algo = GCRY_CIPHER_IDEA;
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

  if (gcry_pk_algo_info (pubkey_algo, GCRYCTL_GET_ALGO_NPKEY, NULL, &npkey)
      || gcry_pk_algo_info (pubkey_algo, GCRYCTL_GET_ALGO_NSKEY, NULL, &nskey)
      || !npkey || npkey >= nskey)
    goto bad_seckey;

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
          void *p = xtrymalloc (valuelen);
          if (!p)
            goto outofmem;
          memcpy (p, value, valuelen);
          skey[skeyidx] = gcry_mpi_set_opaque (NULL, p, valuelen*8);
          if (!skey[skeyidx])
            goto outofmem;
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

  /* log_debug ("XXX is_v4=%d\n", is_v4); */
  /* log_debug ("XXX pubkey_algo=%d\n", pubkey_algo); */
  /* log_debug ("XXX is_protected=%d\n", is_protected); */
  /* log_debug ("XXX protect_algo=%d\n", protect_algo); */
  /* log_printhex ("XXX iv", iv, ivlen); */
  /* log_debug ("XXX ivlen=%d\n", ivlen); */
  /* log_debug ("XXX s2k_mode=%d\n", s2k_mode); */
  /* log_debug ("XXX s2k_algo=%d\n", s2k_algo); */
  /* log_printhex ("XXX s2k_salt", s2k_salt, sizeof s2k_salt); */
  /* log_debug ("XXX s2k_count=%lu\n", (unsigned long)s2k_count); */
  /* for (idx=0; skey[idx]; idx++) */
  /*   { */
  /*     int is_enc = gcry_mpi_get_flag (skey[idx], GCRYMPI_FLAG_OPAQUE); */
  /*     log_info ("XXX skey[%d]%s:", idx, is_enc? " (enc)":""); */
  /*     if (is_enc) */
  /*       { */
  /*         void *p; */
  /*         unsigned int nbits; */
  /*         p = gcry_mpi_get_opaque (skey[idx], &nbits); */
  /*         log_printhex (NULL, p, (nbits+7)/8); */
  /*       } */
  /*     else */
  /*       gcry_mpi_dump (skey[idx]); */
  /*     log_printf ("\n"); */
  /*   } */

  err = get_keygrip (pubkey_algo, skey, grip);
  if (err)
    goto leave;

  if (!agent_key_available (grip))
    {
      err = gpg_error (GPG_ERR_EEXIST);
      goto leave;
    }

  pi = xtrycalloc_secure (1, sizeof (*pi) + 100);
  if (!pi)
    return gpg_error_from_syserror ();
  pi->max_length = 100;
  pi->min_digits = 0;  /* We want a real passphrase.  */
  pi->max_digits = 16;
  pi->max_tries = 3;
  pi->check_cb = try_do_unprotect_cb;
  pi->check_cb_arg = &pi_arg;
  pi_arg.is_v4 = is_v4;
  pi_arg.is_protected = is_protected;
  pi_arg.pubkey_algo = pubkey_algo;
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
  if (cache_nonce)
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
  if (gpg_err_code (err) == GPG_ERR_BAD_PASSPHRASE)
    err = agent_askpin (ctrl, prompt, NULL, NULL, pi, NULL);
  skeyidx = pi_arg.skeyidx;
  if (!err)
    {
      *r_passphrase = xtrystrdup (pi->pin);
      if (!*r_passphrase)
        err = gpg_error_from_syserror ();
    }
  xfree (pi);
  if (err)
    goto leave;

  /* Save some memory and get rid of the SKEY array now.  */
  for (idx=0; idx < skeyidx; idx++)
    gcry_mpi_release (skey[idx]);
  skeyidx = 0;

  /* Note that the padding is not required - we use it only because
     that function allows us to created the result in secure memory.  */
  err = make_canon_sexp_pad (s_skey, 1, r_key, NULL);
  gcry_sexp_release (s_skey);

 leave:
  gcry_sexp_release (list);
  gcry_sexp_release (top_list);
  for (idx=0; idx < skeyidx; idx++)
    gcry_mpi_release (skey[idx]);
  if (err)
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



static gpg_error_t
key_from_sexp (gcry_sexp_t sexp, const char *elems, gcry_mpi_t *array)
{
  gpg_error_t err = 0;
  gcry_sexp_t l2;
  int idx;

  for (idx=0; *elems; elems++, idx++)
    {
      l2 = gcry_sexp_find_token (sexp, elems, 1);
      if (!l2)
        {
          err = gpg_error (GPG_ERR_NO_OBJ); /* Required parameter not found.  */
          goto leave;
        }
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx]) 
        {
          err = gpg_error (GPG_ERR_INV_OBJ); /* Required parameter invalid.  */
          goto leave;
        }
    }
  
 leave:
  if (err)
    {
      int i;

      for (i=0; i < idx; i++)
        {
          gcry_mpi_release (array[i]);
          array[i] = NULL;
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
          err = gpg_error_from_syserror ();
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


/* Convert our key S_KEY into an OpenPGP key transfer format.  On
   success a canonical encoded S-expression is stored at R_TRANSFERKEY
   and its length at R_TRANSFERKEYLEN; this S-expression is also
   padded to a multiple of 64 bits.  */
gpg_error_t
convert_to_openpgp (ctrl_t ctrl, gcry_sexp_t s_key, const char *passphrase,
                    unsigned char **r_transferkey, size_t *r_transferkeylen)
{
  gpg_error_t err;
  gcry_sexp_t list, l2;
  char *name;
  int algo;
  const char *algoname;
  const char *elems;
  int npkey, nskey;
  gcry_mpi_t array[10];
  char protect_iv[16];
  char salt[8];
  unsigned long s2k_count;
  int i, j;

  (void)ctrl;

  *r_transferkey = NULL;

  for (i=0; i < DIM (array); i++)
    array[i] = NULL;

  list = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!list)
    return gpg_error (GPG_ERR_NO_OBJ); /* Does not contain a key object.  */
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  name = gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      gcry_sexp_release (list);
      return gpg_error (GPG_ERR_INV_OBJ); /* Invalid structure of object. */
    }
  
  algo = gcry_pk_map_name (name);
  xfree (name);

  switch (algo)
    {
    case GCRY_PK_RSA:   algoname = "rsa";   npkey = 2; elems = "nedpqu";  break;
    case GCRY_PK_ELG:   algoname = "elg";   npkey = 3; elems = "pgyx";    break;
    case GCRY_PK_ELG_E: algoname = "elg";   npkey = 3; elems = "pgyx";    break;
    case GCRY_PK_DSA:   algoname = "dsa";   npkey = 4; elems = "pqgyx";   break;
    case GCRY_PK_ECDSA: algoname = "ecdsa"; npkey = 6; elems = "pabgnqd"; break;
    default:            algoname = "";      npkey = 0; elems = NULL;      break;
    }
  assert (!elems || strlen (elems) < DIM (array) );
  nskey = elems? strlen (elems) : 0;

  if (!elems)
    err = gpg_error (GPG_ERR_PUBKEY_ALGO);
  else
    err = key_from_sexp (list, elems, array);
  gcry_sexp_release (list);
  if (err)
    return err;

  gcry_create_nonce (protect_iv, sizeof protect_iv);
  gcry_create_nonce (salt, sizeof salt);
  s2k_count = get_standard_s2k_count ();
  err = apply_protection (array, npkey, nskey, passphrase,
                          GCRY_CIPHER_AES, protect_iv, sizeof protect_iv,
                          3, GCRY_MD_SHA1, salt, s2k_count);
  /* Turn it into the transfer key S-expression.  Note that we always
     return a protected key.  */
  if (!err)
    {
      char countbuf[35];
      membuf_t mbuf;
      void *format_args_buf_ptr[1];
      int   format_args_buf_int[1];
      void *format_args[10+2];
      size_t n;
      gcry_sexp_t tmpkey, tmpsexp;
      
      snprintf (countbuf, sizeof countbuf, "%lu", s2k_count);
      
      init_membuf (&mbuf, 50);
      put_membuf_str (&mbuf, "(skey");
      for (i=j=0; i < npkey; i++)
        {
          put_membuf_str (&mbuf, " _ %m");
          format_args[j++] = array + i;
        }
      put_membuf_str (&mbuf, " e %b");
      format_args_buf_ptr[0] = gcry_mpi_get_opaque (array[npkey], &n);
      format_args_buf_int[0] = (n+7)/8;
      format_args[j++] = format_args_buf_int;
      format_args[j++] = format_args_buf_ptr;
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
                               " %S\n"
                               " (protection sha1 aes %b 1:3 sha1 %b %s))\n",
                               algoname,
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
  
  return err;
}

