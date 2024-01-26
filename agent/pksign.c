/* pksign.c - public key signing (well, actually using a secret key)
 * Copyright (C) 2001-2004, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2001-2004, 2010, 2013  Werner Koch
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#include "agent.h"
#include "../common/i18n.h"


static int
do_encode_md (const byte * md, size_t mdlen, int algo, gcry_sexp_t * r_hash,
	      int raw_value)
{
  gcry_sexp_t hash;
  int rc;

  if (!raw_value)
    {
      const char *s;
      char tmp[16+1];
      int i;

      s = gcry_md_algo_name (algo);
      if (!s || strlen (s) >= 16)
        {
          hash = NULL;
          rc = gpg_error (GPG_ERR_DIGEST_ALGO);
        }
      else
	{
	  for (i=0; s[i]; i++)
	    tmp[i] = ascii_tolower (s[i]);
	  tmp[i] = '\0';

          rc = gcry_sexp_build (&hash, NULL,
                                "(data (flags pkcs1) (hash %s %b))",
                                tmp, (int)mdlen, md);
	}
    }
  else
    {
      rc = gcry_sexp_build (&hash, NULL,
                            "(data (flags raw) (value %b))",
                            (int)mdlen, md);
    }

  *r_hash = hash;
  return rc;
}


/* Return the number of bits of the Q parameter from the DSA key
   KEY.  */
static unsigned int
get_dsa_qbits (gcry_sexp_t key)
{
  gcry_sexp_t l1, l2;
  gcry_mpi_t q;
  unsigned int nbits;

  l1 = gcry_sexp_find_token (key, "private-key", 0);
  if (!l1)
    l1 = gcry_sexp_find_token (key, "protected-private-key", 0);
  if (!l1)
    l1 = gcry_sexp_find_token (key, "shadowed-private-key", 0);
  if (!l1)
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


/* Return an appropriate hash algorithm to be used with RFC-6979 for a
   message digest of length MDLEN.  Although a fallback of SHA-256 is
   used the current implementation in Libgcrypt will reject a hash
   algorithm which does not match the length of the message.  */
static const char *
rfc6979_hash_algo_string (size_t mdlen)
{
  switch (mdlen)
    {
    case 20: return "sha1";
    case 28: return "sha224";
    case 32: return "sha256";
    case 48: return "sha384";
    case 64: return "sha512";
    default: return "sha256";
    }
}


/* Encode a message digest for use with the EdDSA algorithm
   (i.e. curve Ed25519). */
static gpg_error_t
do_encode_eddsa (size_t nbits, const byte *md, size_t mdlen,
                 gcry_sexp_t *r_hash)
{
  gpg_error_t err;
  gcry_sexp_t hash;
  const char *fmt;

  if (nbits == 448)
    fmt = "(data(value %b))";
  else
    fmt = "(data(flags eddsa)(hash-algo sha512)(value %b))";

  *r_hash = NULL;
  err = gcry_sexp_build (&hash, NULL, fmt, (int)mdlen, md);
  if (!err)
    *r_hash = hash;
  return err;
}


/* Encode a message digest for use with an DSA algorithm. */
static gpg_error_t
do_encode_dsa (const byte *md, size_t mdlen, int pkalgo, gcry_sexp_t pkey,
               gcry_sexp_t *r_hash)
{
  gpg_error_t err;
  gcry_sexp_t hash;
  unsigned int qbits;

  *r_hash = NULL;

  if (pkalgo == GCRY_PK_ECC)
    qbits = gcry_pk_get_nbits (pkey);
  else if (pkalgo == GCRY_PK_DSA)
    qbits = get_dsa_qbits (pkey);
  else
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  if (pkalgo == GCRY_PK_DSA && (qbits%8))
    {
      /* FIXME: We check the QBITS but print a message about the hash
         length.  */
      log_error (_("DSA requires the hash length to be a"
                   " multiple of 8 bits\n"));
      return gpg_error (GPG_ERR_INV_LENGTH);
    }

  /* Don't allow any Q smaller than 160 bits.  We don't want someone
     to issue signatures from a key with a 16-bit Q or something like
     that, which would look correct but allow trivial forgeries.  Yes,
     I know this rules out using MD5 with DSA. ;) */
  if (qbits < 160)
    {
      log_error (_("%s key uses an unsafe (%u bit) hash\n"),
                 gcry_pk_algo_name (pkalgo), qbits);
      return gpg_error (GPG_ERR_INV_LENGTH);
    }

  /* ECDSA 521 is special as it is larger than the largest hash
     we have (SHA-512).  Thus we change the size for further
     processing to 512.  */
  if (pkalgo == GCRY_PK_ECC && qbits > 512)
    qbits = 512;

  /* Check if we're too short.  Too long is safe as we'll
     automatically left-truncate.  */
  if (mdlen < qbits/8)
    {
      log_error (_("a %zu bit hash is not valid for a %u bit %s key\n"),
                 mdlen*8,
                 gcry_pk_get_nbits (pkey),
                 gcry_pk_algo_name (pkalgo));
      return gpg_error (GPG_ERR_INV_LENGTH);
    }

  /* Truncate.  */
  if (mdlen > qbits/8)
    mdlen = qbits/8;

  /* Create the S-expression.  */
  err = gcry_sexp_build (&hash, NULL,
                         "(data (flags rfc6979) (hash %s %b))",
                         rfc6979_hash_algo_string (mdlen),
                         (int)mdlen, md);
  if (!err)
    *r_hash = hash;
  return err;
}


/* Special version of do_encode_md to take care of pkcs#1 padding.
   For TLS-MD5SHA1 we need to do the padding ourself as Libgrypt does
   not know about this special scheme.  Fixme: We should have a
   pkcs1-only-padding flag for Libgcrypt. */
static int
do_encode_raw_pkcs1 (const byte *md, size_t mdlen, unsigned int nbits,
                     gcry_sexp_t *r_hash)
{
  int rc;
  gcry_sexp_t hash;
  unsigned char *frame;
  size_t i, n, nframe;

  nframe = (nbits+7) / 8;
  if ( !mdlen || mdlen + 8 + 4 > nframe )
    {
      /* Can't encode this hash into a frame of size NFRAME. */
      return gpg_error (GPG_ERR_TOO_SHORT);
    }

  frame = xtrymalloc (nframe);
  if (!frame)
    return gpg_error_from_syserror ();

  /* Assemble the pkcs#1 block type 1. */
  n = 0;
  frame[n++] = 0;
  frame[n++] = 1; /* Block type. */
  i = nframe - mdlen - 3 ;
  log_assert (i >= 8); /* At least 8 bytes of padding.  */
  memset (frame+n, 0xff, i );
  n += i;
  frame[n++] = 0;
  memcpy (frame+n, md, mdlen );
  n += mdlen;
  log_assert (n == nframe);

  /* Create the S-expression.  */
  rc = gcry_sexp_build (&hash, NULL,
                        "(data (flags raw) (value %b))",
                        (int)nframe, frame);
  xfree (frame);

  *r_hash = hash;
  return rc;
}



/* SIGN whatever information we have accumulated in CTRL and return
 * the signature S-expression.  LOOKUP is an optional function to
 * provide a way for lower layers to ask for the caching TTL.  If a
 * CACHE_NONCE is given that cache item is first tried to get a
 * passphrase.  If OVERRIDEDATA is not NULL, OVERRIDEDATALEN bytes
 * from this buffer are used instead of the data in CTRL.  The
 * override feature is required to allow the use of Ed25519 with ssh
 * because Ed25519 does the hashing itself.  */
gpg_error_t
agent_pksign_do (ctrl_t ctrl, const char *cache_nonce,
                 const char *desc_text,
		 gcry_sexp_t *signature_sexp,
                 cache_mode_t cache_mode, lookup_ttl_t lookup_ttl,
                 const void *overridedata, size_t overridedatalen)
{
  gpg_error_t err = 0;
  gcry_sexp_t s_skey = NULL;
  gcry_sexp_t s_sig  = NULL;
  gcry_sexp_t s_hash = NULL;
  gcry_sexp_t s_pkey = NULL;
  unsigned char *shadow_info = NULL;
  int no_shadow_info = 0;
  const unsigned char *data;
  int datalen;
  int check_signature = 0;
  int algo;

  if (overridedata)
    {
      data = overridedata;
      datalen = overridedatalen;
    }
  else if (ctrl->digest.data)
    {
      data = ctrl->digest.data;
      datalen = ctrl->digest.valuelen;
    }
  else
    {
      data = ctrl->digest.value;
      datalen = ctrl->digest.valuelen;
    }

  if (!ctrl->have_keygrip)
    return gpg_error (GPG_ERR_NO_SECKEY);

  err = agent_key_from_file (ctrl, cache_nonce, desc_text, NULL,
                             &shadow_info, cache_mode, lookup_ttl,
                             &s_skey, NULL, NULL);
  if (gpg_err_code (err) == GPG_ERR_NO_SECKEY)
    no_shadow_info = 1;
  else if (err)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }
  else
    algo = get_pk_algo_from_key (s_skey);

  if (shadow_info || no_shadow_info)
    {
      /* Divert operation to the smartcard.  With NO_SHADOW_INFO set
       * we don't have the keystub but we want to see whether the key
       * is on the active card.  */
      size_t len;
      unsigned char *buf = NULL;

      if (no_shadow_info)
        {
          /* Try to get the public key from the card or fail with the
           * original NO_SECKEY error.  We also write a stub file (we
           * are here only because no stub exists). */
          char *serialno;
          unsigned char *pkbuf = NULL;
          size_t pkbuflen;
          char hexgrip[2*KEYGRIP_LEN+1];
          char *keyref;

          if (agent_card_serialno (ctrl, &serialno, NULL))
            {
              /* No card available or error reading the card.  */
              err = gpg_error (GPG_ERR_NO_SECKEY);
              goto leave;
            }
          bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
          if (agent_card_readkey (ctrl, hexgrip, &pkbuf, &keyref))
            {
              /* No such key on the card.  */
              xfree (serialno);
              err = gpg_error (GPG_ERR_NO_SECKEY);
              goto leave;
            }
          pkbuflen = gcry_sexp_canon_len (pkbuf, 0, NULL, NULL);
          err = gcry_sexp_sscan (&s_pkey, NULL, (char*)pkbuf, pkbuflen);
          if (err)
            {
              xfree (serialno);
              xfree (pkbuf);
              xfree (keyref);
              log_error ("%s: corrupted key returned by scdaemon\n", __func__);
              goto leave;
            }

          if (keyref && !ctrl->ephemeral_mode)
            {
              char *dispserialno;

              agent_card_getattr (ctrl, "$DISPSERIALNO", &dispserialno,
                                  hexgrip);
              agent_write_shadow_key (ctrl,
                                      ctrl->keygrip, serialno, keyref, pkbuf,
                                      0, dispserialno);
              xfree (dispserialno);
            }
          algo = get_pk_algo_from_key (s_pkey);

          xfree (serialno);
          xfree (pkbuf);
          xfree (keyref);
        }
      else
        {
          /* Get the public key from the stub file.  */
          err = agent_public_key_from_file (ctrl, ctrl->keygrip, &s_pkey);
          if (err)
            {
              log_error ("failed to read the public key\n");
              goto leave;
            }
        }

      {
	if (agent_is_tpm2_key (s_skey))
	  err = divert_tpm2_pksign (ctrl,
				    data, datalen,
				    ctrl->digest.algo,
				    shadow_info, &buf, &len);
	else
	  err = divert_pksign (ctrl,
			       ctrl->keygrip,
			       data, datalen,
			       ctrl->digest.algo,
			       &buf, &len);
      }
      if (err)
        {
          log_error ("smartcard signing failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (algo == GCRY_PK_RSA)
        {
          unsigned char *p = buf;

          check_signature = 1;

          /*
           * Smartcard returns fixed-size data, which is good for
           * PKCS1.  If variable-size unsigned MPI is needed, remove
           * zeros.
           */
          if (ctrl->digest.algo == MD_USER_TLS_MD5SHA1
              || ctrl->digest.raw_value)
            {
              int i;

              for (i = 0; i < len - 1; i++)
                if (p[i])
                  break;
              p += i;
              len -= i;
            }

          err = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%b)))",
                                 (int)len, p);
        }
      else if (algo == GCRY_PK_EDDSA)
        {
          err = gcry_sexp_build (&s_sig, NULL, "(sig-val(eddsa(r%b)(s%b)))",
                                 (int)len/2, buf, (int)len/2, buf + len/2);
        }
      else if (algo == GCRY_PK_ECC)
        {
          unsigned char *r_buf, *s_buf;
          int r_buflen, s_buflen;
          int i;

          r_buflen = s_buflen = len/2;

          /*
           * Smartcard returns fixed-size data.  For ECDSA signature,
           * variable-size unsigned MPI is assumed, thus, remove
           * zeros.
           */
          r_buf = buf;
          for (i = 0; i < r_buflen - 1; i++)
            if (r_buf[i])
              break;
          r_buf += i;
          r_buflen -= i;

          s_buf = buf + len/2;
          for (i = 0; i < s_buflen - 1; i++)
            if (s_buf[i])
              break;
          s_buf += i;
          s_buflen -= i;

          err = gcry_sexp_build (&s_sig, NULL, "(sig-val(ecdsa(r%b)(s%b)))",
                                 r_buflen, r_buf,
                                 s_buflen, s_buf);
        }
      else
        err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

      xfree (buf);
      if (err)
	{
	  log_error ("failed to convert sigbuf returned by divert_pksign "
		     "into S-Exp: %s", gpg_strerror (err));
	  goto leave;
	}
    }
  else
    {
      /* No smartcard, but a private key (in S_SKEY). */

      /* Put the hash into a sexp */
      if (algo == GCRY_PK_EDDSA)
        err = do_encode_eddsa (gcry_pk_get_nbits (s_skey), data, datalen,
                               &s_hash);
      else if (ctrl->digest.algo == MD_USER_TLS_MD5SHA1)
        err = do_encode_raw_pkcs1 (data, datalen,
                                   gcry_pk_get_nbits (s_skey),
                                   &s_hash);
      else if (algo == GCRY_PK_DSA || algo == GCRY_PK_ECC)
        err = do_encode_dsa (data, datalen,
                             algo, s_skey,
                             &s_hash);
      else if (ctrl->digest.is_pss)
        {
          log_info ("signing with rsaPSS is currently only supported"
                    " for (some) smartcards\n");
          err = gpg_error (GPG_ERR_NOT_SUPPORTED);
        }
      else
        err = do_encode_md (data, datalen,
                            ctrl->digest.algo,
                            &s_hash,
                            ctrl->digest.raw_value);
      if (err)
        goto leave;

      if (DBG_CRYPTO)
        {
          gcry_log_debugsxp ("skey", s_skey);
          gcry_log_debugsxp ("hash", s_hash);
        }

      /* sign */
      err = gcry_pk_sign (&s_sig, s_hash, s_skey);
      if (err)
        {
          log_error ("signing failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (DBG_CRYPTO)
        gcry_log_debugsxp ("rslt", s_sig);
    }

  /* Check that the signature verification worked and nothing is
   * fooling us e.g. by a bug in the signature create code or by
   * deliberately introduced faults.  Because Libgcrypt 1.7 does this
   * for RSA internally there is no need to do it here again.  We do
   * this always for card based RSA keys, though.  */
  if (check_signature)
    {
      gcry_sexp_t sexp_key = s_pkey? s_pkey: s_skey;

      if (s_hash == NULL)
        {
          if (ctrl->digest.is_pss)
            {
              err = gcry_sexp_build (&s_hash, NULL,
                                     "(data (flags raw) (value %b))",
                                     (int)datalen, data);
            }
          else if (algo == GCRY_PK_DSA || algo == GCRY_PK_ECC)
            err = do_encode_dsa (data, datalen, algo, sexp_key, &s_hash);
          else if (ctrl->digest.algo == MD_USER_TLS_MD5SHA1)
            err = do_encode_raw_pkcs1 (data, datalen,
                                       gcry_pk_get_nbits (sexp_key), &s_hash);
          else
            err = do_encode_md (data, datalen, ctrl->digest.algo, &s_hash,
                                ctrl->digest.raw_value);
        }

      if (!err)
        err = gcry_pk_verify (s_sig, s_hash, sexp_key);

      if (err)
        {
          log_error (_("checking created signature failed: %s\n"),
                     gpg_strerror (err));
          if (DBG_CRYPTO)
            {
              gcry_log_debugsxp ("verify s_hsh", s_hash);
              gcry_log_debugsxp ("verify s_sig", s_sig);
              gcry_log_debugsxp ("verify s_key", sexp_key);
            }
          gcry_sexp_release (s_sig);
          s_sig = NULL;
        }
    }

 leave:

  *signature_sexp = s_sig;

  gcry_sexp_release (s_pkey);
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_hash);
  xfree (shadow_info);

  return err;
}


/* SIGN whatever information we have accumulated in CTRL and write it
 * back to OUTFP.  If a CACHE_NONCE is given that cache item is first
 * tried to get a passphrase.  */
gpg_error_t
agent_pksign (ctrl_t ctrl, const char *cache_nonce, const char *desc_text,
              membuf_t *outbuf, cache_mode_t cache_mode)
{
  gpg_error_t err;
  gcry_sexp_t s_sig = NULL;
  char *buf = NULL;
  size_t len = 0;

  err = agent_pksign_do (ctrl, cache_nonce, desc_text, &s_sig, cache_mode,
                         NULL, NULL, 0);
  if (err)
    goto leave;

  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
  log_assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, buf, len);
  log_assert (len);
  put_membuf (outbuf, buf, len);

 leave:
  gcry_sexp_release (s_sig);
  xfree (buf);

  return err;
}
