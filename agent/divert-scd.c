/* divert-scd.c - divert operations to the scdaemon
 *	Copyright (C) 2002, 2003, 2009 Free Software Foundation, Inc.
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
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "../common/i18n.h"
#include "../common/sexp-parse.h"


/* Put the DIGEST into an DER encoded container and return it in R_VAL. */
static int
encode_md_for_card (const unsigned char *digest, size_t digestlen, int algo,
                    unsigned char **r_val, size_t *r_len)
{
  unsigned char *frame;
  unsigned char asn[100];
  size_t asnlen;

  *r_val = NULL;
  *r_len = 0;

  asnlen = DIM(asn);
  if (!algo || gcry_md_test_algo (algo))
    return gpg_error (GPG_ERR_DIGEST_ALGO);
  if (gcry_md_algo_info (algo, GCRYCTL_GET_ASNOID, asn, &asnlen))
    {
      log_error ("no object identifier for algo %d\n", algo);
      return gpg_error (GPG_ERR_INTERNAL);
    }

  frame = xtrymalloc (asnlen + digestlen);
  if (!frame)
    return out_of_core ();
  memcpy (frame, asn, asnlen);
  memcpy (frame+asnlen, digest, digestlen);
  if (DBG_CRYPTO)
    log_printhex (frame, asnlen+digestlen, "encoded hash:");

  *r_val = frame;
  *r_len = asnlen+digestlen;
  return 0;
}


/* This function is used when a sign operation has been diverted to a
 * smartcard.
 *
 * Note: If SHADOW_INFO is NULL the user can't be asked to insert the
 * card, we simply try to use an inserted card with the given keygrip.
 *
 * FIXME: Explain the other args.  */
int
divert_pksign (ctrl_t ctrl, const unsigned char *grip,
               const unsigned char *digest, size_t digestlen, int algo,
               unsigned char **r_sig,
               size_t *r_siglen)
{
  int rc;
  char hexgrip[41];
  size_t siglen;
  unsigned char *sigval = NULL;

  bin2hex (grip, 20, hexgrip);

  if (!algo)
    {
      /* This is the PureEdDSA case.  (DIGEST,DIGESTLEN) this the
       * entire data which will be signed.  */
      rc = agent_card_pksign (ctrl, hexgrip,
                              0, digest, digestlen, &sigval, &siglen);
    }
  else if (algo == MD_USER_TLS_MD5SHA1)
    {
      int save = ctrl->use_auth_call;
      ctrl->use_auth_call = 1;
      rc = agent_card_pksign (ctrl, hexgrip,
                              algo, digest, digestlen, &sigval, &siglen);
      ctrl->use_auth_call = save;
    }
  else
    {
      unsigned char *data;
      size_t ndata;

      rc = encode_md_for_card (digest, digestlen, algo, &data, &ndata);
      if (!rc)
        {
          rc = agent_card_pksign (ctrl, hexgrip,
                                  algo, data, ndata, &sigval, &siglen);
          xfree (data);
        }
    }

  if (!rc)
    {
      *r_sig = sigval;
      *r_siglen = siglen;
    }

  return rc;
}


/* Decrypt the value given as an s-expression in CIPHER using the
   key identified by SHADOW_INFO and return the plaintext in an
   allocated buffer in R_BUF.  The padding information is stored at
   R_PADDING with -1 for not known, when it's not NULL.  */
int
divert_pkdecrypt (ctrl_t ctrl,
                  const unsigned char *grip,
                  const unsigned char *cipher,
                  char **r_buf, size_t *r_len, int *r_padding)
{
  int rc;
  char hexgrip[41];
  const unsigned char *s;
  size_t n;
  int depth;
  const unsigned char *ciphertext;
  size_t ciphertextlen;
  unsigned char *plaintext;
  size_t plaintextlen;

  bin2hex (grip, 20, hexgrip);

  if (r_padding)
    *r_padding = -1;
  s = cipher;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, n, "enc-val"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  /* First check whether we have a flags parameter and skip it.  */
  if (smatch (&s, n, "flags"))
    {
      depth = 1;
      if (sskip (&s, &depth) || depth)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (*s != '(')
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
    }

  if (smatch (&s, n, "rsa"))
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (!smatch (&s, n, "a"))
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      n = snext (&s);
    }
  else if (smatch (&s, n, "ecdh"))
    {
      if (*s != '(')
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      s++;
      n = snext (&s);
      if (!n)
        return gpg_error (GPG_ERR_INV_SEXP);
      if (smatch (&s, n, "s"))
        {
          n = snext (&s);
          s += n;
          if (*s++ != ')')
            return gpg_error (GPG_ERR_INV_SEXP);
          if (*s++ != '(')
            return gpg_error (GPG_ERR_UNKNOWN_SEXP);
          n = snext (&s);
          if (!n)
            return gpg_error (GPG_ERR_INV_SEXP);
        }
      if (!smatch (&s, n, "e"))
        return gpg_error (GPG_ERR_UNKNOWN_SEXP);
      n = snext (&s);
    }
  else
    {
      if (opt.verbose)
        {
          if (smatch (&s, n, "elg"))
            log_info ("unknown algorithm is \"elg\"\n");
          else if (smatch (&s, n, "dsa"))
            log_info ("unknown algorithm is \"dsa\"\n");
          else if (smatch (&s, n, "kyber"))
            log_info ("unknown algorithm is \"kyber\"\n");
          else
            log_printhex (s, n, "unknown algorithm is");
        }
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }

  if (!n)
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  ciphertext = s;
  ciphertextlen = n;

  rc = agent_card_pkdecrypt (ctrl, hexgrip,
                             ciphertext, ciphertextlen,
                             &plaintext, &plaintextlen, r_padding);
  if (!rc)
    {
      *r_buf = plaintext;
      *r_len = plaintextlen;
    }
  return rc;
}

gpg_error_t
agent_card_ecc_kem (ctrl_t ctrl, const unsigned char *ecc_ct,
                    size_t ecc_point_len, unsigned char *ecc_ecdh)
{
  gpg_error_t err = 0;
  unsigned char *ecdh = NULL;
  size_t len;
  int rc;
  char hexgrip[KEYGRIP_LEN*2+1];

  bin2hex (ctrl->keygrip, KEYGRIP_LEN, hexgrip);
  rc = agent_card_pkdecrypt (ctrl, hexgrip,
                             ecc_ct, ecc_point_len, &ecdh, &len, NULL);
  if (rc)
    return rc;

  if (len == ecc_point_len)
    memcpy (ecc_ecdh, ecdh, len);
  else if (len && (len - 1) * 2 == ecc_point_len - 1
           && (ecdh[0] == 0x41 || (ecdh[0] & ~1) == 0x02))
    {
      /* It's x-coordinate-only (compressed) point representation.  */
      memcpy (ecc_ecdh, ecdh, len);
      memset (ecc_ecdh + len, 0, ecc_point_len - len);
    }
  else if (len == ecc_point_len + 1 && ecdh[0] == 0x40) /* The prefix */
    memcpy (ecc_ecdh, ecdh + 1, len - 1);
  else
    {
      if (opt.verbose)
        log_info ("%s: ECC result length invalid (%zu != %zu)\n",
                  __func__, len, ecc_point_len);
      return gpg_error (GPG_ERR_INV_DATA);
    }

  xfree (ecdh);
  return err;
}


gpg_error_t
divert_writekey (ctrl_t ctrl, int force, const char *serialno,
                 const char *keyref, const char *keydata, size_t keydatalen)
{
  return agent_card_writekey (ctrl, force, serialno, keyref,
                              keydata, keydatalen);
}

int
divert_generic_cmd (ctrl_t ctrl, const char *cmdline, void *assuan_context)
{
  return agent_card_scd (ctrl, cmdline, assuan_context);
}
