/* tpm2.c - Supporting TPM routines for the IBM TSS
 * Copyright (C) 2021 James Bottomley <James.Bottomley@HansenPartnership.com>
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "tpm2.h"

#include "../common/i18n.h"
#include "../common/sexp-parse.h"

int
tpm2_start (TSS_CONTEXT **tssc)
{
  return TSS_start(tssc);
}

void
tpm2_end (TSS_CONTEXT *tssc)
{
  TSS_Delete (tssc);
}

static TPM_HANDLE
tpm2_get_parent (TSS_CONTEXT *tssc, TPM_HANDLE p)
{
  TPM_RC rc;
  TPM2B_SENSITIVE_CREATE inSensitive;
  TPM2B_PUBLIC inPublic;
  TPM_HANDLE objectHandle;

  p = tpm2_handle_int(tssc, p);
  if (tpm2_handle_mso(tssc, p, TPM_HT_PERSISTENT))
    return p;			/* should only be permanent */

  /*  assume no hierarchy auth */
  VAL_2B (inSensitive.sensitive.userAuth, size) = 0;
  /* no sensitive date for storage keys */
  VAL_2B (inSensitive.sensitive.data, size) = 0;

  /* public parameters for a P-256 EC key  */
  inPublic.publicArea.type = TPM_ALG_ECC;
  inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
  VAL (inPublic.publicArea.objectAttributes) =
    TPMA_OBJECT_NODA |
    TPMA_OBJECT_SENSITIVEDATAORIGIN |
    TPMA_OBJECT_USERWITHAUTH |
    TPMA_OBJECT_DECRYPT |
    TPMA_OBJECT_RESTRICTED |
    TPMA_OBJECT_FIXEDPARENT |
    TPMA_OBJECT_FIXEDTPM;

  inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
  inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
  inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
  inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
  inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
  inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

  VAL_2B (inPublic.publicArea.unique.ecc.x, size) = 0;
  VAL_2B (inPublic.publicArea.unique.ecc.y, size) = 0;
  VAL_2B (inPublic.publicArea.authPolicy, size) = 0;

  rc = tpm2_CreatePrimary (tssc, p, &inSensitive, &inPublic, &objectHandle);
  if (rc)
    {
      tpm2_error (rc, "TSS_CreatePrimary");
      return 0;
    }
  return objectHandle;
}

void
tpm2_flush_handle (TSS_CONTEXT *tssc, TPM_HANDLE h)
{
  /* only flush volatile handles */
  if (tpm2_handle_mso(tssc, h, TPM_HT_PERSISTENT))
    return;

  tpm2_FlushContext(tssc, h);
}

static int
tpm2_get_hmac_handle (TSS_CONTEXT *tssc, TPM_HANDLE *handle,
		      TPM_HANDLE salt_key)
{
  TPM_RC rc;
  TPMT_SYM_DEF symmetric;

  symmetric.algorithm = TPM_ALG_AES;
  symmetric.keyBits.aes = 128;
  symmetric.mode.aes = TPM_ALG_CFB;

  rc = tpm2_StartAuthSession(tssc, salt_key, TPM_RH_NULL, TPM_SE_HMAC,
			     &symmetric, TPM_ALG_SHA256, handle, NULL);
  if (rc)
    {
      tpm2_error (rc, "TPM2_StartAuthSession");
      return GPG_ERR_CARD;
    }

  return 0;
}

static int
tpm2_pre_auth (ctrl_t ctrl, TSS_CONTEXT *tssc,
	       gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
				     char **retstr),
	       TPM_HANDLE *ah, char **auth)
{
  TPM_RC rc;
  int len;

  rc = pin_cb (ctrl, _("TPM Key Passphrase"), auth);
  if (rc)
    return rc;

  len = strlen(*auth);
  /*
   * TPMs can't accept a longer passphrase than the name algorithm.
   * We hard code the name algorithm to SHA256 so the max passphrase
   * length is 32
   */
  if (len > 32)
    {
      log_error ("Truncating Passphrase to TPM allowed 32\n");
      (*auth)[32] = '\0';
    }

  rc = tpm2_get_hmac_handle (tssc, ah, TPM_RH_NULL);

  return rc;
}

static int
tpm2_post_auth (TSS_CONTEXT *tssc, TPM_RC rc, TPM_HANDLE ah,
		char **auth, const char *cmd_str)
{
  gcry_free (*auth);
  *auth = NULL;
  if (rc)
    {
      tpm2_error (rc, cmd_str);
      tpm2_flush_handle (tssc, ah);
      switch (rc & 0xFF)
	{
	case TPM_RC_BAD_AUTH:
	case TPM_RC_AUTH_FAIL:
	  return GPG_ERR_BAD_PASSPHRASE;
	default:
	  return GPG_ERR_CARD;
	}
    }
  return 0;
}

static unsigned char *
make_tpm2_shadow_info (uint32_t parent, const char *pub, int pub_len,
                       const char *priv, int priv_len, size_t *len)
{
  gcry_sexp_t s_exp;
  char *info;

  gcry_sexp_build (&s_exp, NULL, "(%u%b%b)", parent, pub_len, pub,
		   priv_len, priv);

  *len = gcry_sexp_sprint (s_exp, GCRYSEXP_FMT_CANON, NULL, 0);
  info = xtrymalloc (*len);
  if (!info)
	  goto out;
  gcry_sexp_sprint (s_exp, GCRYSEXP_FMT_CANON, info, *len);

 out:
  gcry_sexp_release (s_exp);
  return (unsigned char *)info;
}

static gpg_error_t
parse_tpm2_shadow_info (const unsigned char *shadow_info,
                        uint32_t *parent,
                        const char **pub, int *pub_len,
                        const char **priv, int *priv_len)
{
  const unsigned char *s;
  size_t n;
  int i;

  s = shadow_info;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  *parent = 0;
  for (i = 0; i < n; i++)
    {
      *parent *= 10;
      *parent += atoi_1(s+i);
    }

  s += n;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  *pub_len = n;
  *pub = s;

  s += n;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  *priv_len = n;
  *priv = s;

  return 0;
}

int
tpm2_load_key (TSS_CONTEXT *tssc, const unsigned char *shadow_info,
	       TPM_HANDLE *key, TPMI_ALG_PUBLIC *type)
{
  uint32_t parent;
  TPM_HANDLE parentHandle;
  PRIVATE_2B inPrivate;
  TPM2B_PUBLIC inPublic;
  const char *pub, *priv;
  int ret, pub_len, priv_len;
  TPM_RC rc;
  BYTE *buf;
  uint32_t size;

  ret = parse_tpm2_shadow_info (shadow_info, &parent, &pub, &pub_len,
                                &priv, &priv_len);
  if (ret)
    return ret;

  parentHandle = tpm2_get_parent (tssc, parent);

  buf = (BYTE *)priv;
  size = priv_len;
  TPM2B_PRIVATE_Unmarshal ((TPM2B_PRIVATE *)&inPrivate, &buf, &size);

  buf = (BYTE *)pub;
  size = pub_len;
  TPM2B_PUBLIC_Unmarshal (&inPublic, &buf, &size, FALSE);

  *type = inPublic.publicArea.type;

  rc = tpm2_Load (tssc, parentHandle, &inPrivate, &inPublic, key,
		  TPM_RS_PW, NULL);

  tpm2_flush_handle (tssc, parentHandle);

  if (rc != TPM_RC_SUCCESS)
    {
      tpm2_error (rc, "TPM2_Load");
      return GPG_ERR_CARD;
    }

  return 0;
}

int
tpm2_sign (ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
	   gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
				 char **retstr),
	   TPMI_ALG_PUBLIC type,
	   const unsigned char *digest, size_t digestlen,
	   unsigned char **r_sig, size_t *r_siglen)
{
  int ret;
  DIGEST_2B digest2b;
  TPMT_SIG_SCHEME inScheme;
  TPMT_SIGNATURE signature;
  TPM_HANDLE ah;
  char *auth;

  /* The TPM insists on knowing the digest type, so
   * calculate that from the size */
  switch (digestlen)
    {
    case 20:
      inScheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
      break;
    case 32:
      inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
      break;
    case 48:
      inScheme.details.rsassa.hashAlg = TPM_ALG_SHA384;
      break;
#ifdef TPM_ALG_SHA512
    case 64:
      inScheme.details.rsassa.hashAlg = TPM_ALG_SHA512;
      break;
#endif
    default:
      log_error ("Unknown signature digest length, cannot deduce hash type for TPM\n");
      return GPG_ERR_NO_SIGNATURE_SCHEME;
    }
  digest2b.size = digestlen;
  memcpy (digest2b.buffer, digest, digestlen);

  if (type == TPM_ALG_RSA)
    inScheme.scheme = TPM_ALG_RSASSA;
  else if (type == TPM_ALG_ECC)
    inScheme.scheme = TPM_ALG_ECDSA;
  else
    return GPG_ERR_PUBKEY_ALGO;

  ret = tpm2_pre_auth (ctrl, tssc, pin_cb, &ah, &auth);
  if (ret)
    return ret;
  ret = tpm2_Sign (tssc, key, &digest2b, &inScheme, &signature, ah, auth);
  ret = tpm2_post_auth (tssc, ret, ah, &auth, "TPM2_Sign");
  if (ret)
    return ret;

  if (type == TPM_ALG_RSA)
    *r_siglen = VAL_2B (signature.signature.rsassa.sig, size);
  else if (type == TPM_ALG_ECC)
    *r_siglen = VAL_2B (signature.signature.ecdsa.signatureR, size)
      + VAL_2B (signature.signature.ecdsa.signatureS, size);

  *r_sig = xtrymalloc (*r_siglen);
  if (!r_sig)
    return GPG_ERR_ENOMEM;

  if (type == TPM_ALG_RSA)
    {
      memcpy (*r_sig, VAL_2B (signature.signature.rsassa.sig, buffer),
	      *r_siglen);
    }
  else if (type == TPM_ALG_ECC)
    {
      memcpy (*r_sig, VAL_2B (signature.signature.ecdsa.signatureR, buffer),
	      VAL_2B (signature.signature.ecdsa.signatureR, size));
      memcpy (*r_sig + VAL_2B (signature.signature.ecdsa.signatureR, size),
	      VAL_2B (signature.signature.ecdsa.signatureS, buffer),
	      VAL_2B (signature.signature.ecdsa.signatureS, size));
    }

  return 0;
}

static int
sexp_to_tpm2_sensitive_ecc (TPMT_SENSITIVE *s, gcry_sexp_t key)
{
  gcry_mpi_t d;
  gcry_sexp_t l;
  int rc = -1;
  size_t len;

  s->sensitiveType = TPM_ALG_ECC;
  VAL_2B (s->seedValue, size) = 0;

  l = gcry_sexp_find_token (key, "d", 0);
  if (!l)
    return rc;
  d = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof (VAL_2B (s->sensitive.ecc, buffer));
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, VAL_2B (s->sensitive.ecc, buffer),
		       len, &len, d);
  VAL_2B (s->sensitive.ecc, size) = len;
  gcry_mpi_release (d);

  return rc;
}

/* try to match the libgcrypt curve names to known TPM parameters.
 *
 * As of 2018 the TCG defined curves are only NIST
 * (192,224,256,384,521) Barreto-Naehring (256,638) and the Chinese
 * SM2 (256), which means only the NIST ones overlap with libgcrypt */
static struct {
  const char *name;
  TPMI_ECC_CURVE c;
} tpm2_curves[] = {
  { "NIST P-192", TPM_ECC_NIST_P192 },
  { "prime192v1", TPM_ECC_NIST_P192 },
  { "secp192r1", TPM_ECC_NIST_P192 },
  { "nistp192", TPM_ECC_NIST_P192 },
  { "NIST P-224", TPM_ECC_NIST_P224 },
  { "secp224r1", TPM_ECC_NIST_P224 },
  { "nistp224", TPM_ECC_NIST_P224 },
  { "NIST P-256", TPM_ECC_NIST_P256 },
  { "prime256v1", TPM_ECC_NIST_P256 },
  { "secp256r1", TPM_ECC_NIST_P256 },
  { "nistp256", TPM_ECC_NIST_P256 },
  { "NIST P-384", TPM_ECC_NIST_P384 },
  { "secp384r1", TPM_ECC_NIST_P384 },
  { "nistp384", TPM_ECC_NIST_P384 },
  { "NIST P-521", TPM_ECC_NIST_P521 },
  { "secp521r1", TPM_ECC_NIST_P521 },
  { "nistp521", TPM_ECC_NIST_P521 },
};

static int
tpm2_ecc_curve (const char *curve_name, TPMI_ECC_CURVE *c)
{
  int i;

  for (i = 0; i < DIM (tpm2_curves); i++)
    if (strcmp (tpm2_curves[i].name, curve_name) == 0)
      break;
  if (i == DIM (tpm2_curves))
    {
      log_error ("curve %s does not match any available TPM curves\n", curve_name);
      return GPG_ERR_UNKNOWN_CURVE;
    }

  *c = tpm2_curves[i].c;

  return 0;
}

static int
sexp_to_tpm2_public_ecc (TPMT_PUBLIC *p, gcry_sexp_t key)
{
  const char *q;
  gcry_sexp_t l;
  int rc = GPG_ERR_BAD_PUBKEY;
  size_t len;
  TPMI_ECC_CURVE curve;
  char *curve_name;

  l = gcry_sexp_find_token (key, "curve", 0);
  if (!l)
    return rc;
  curve_name = gcry_sexp_nth_string (l, 1);
  if (!curve_name)
    goto out;
  rc = tpm2_ecc_curve (curve_name, &curve);
  gcry_free (curve_name);
  if (rc)
    goto out;
  gcry_sexp_release (l);

  l = gcry_sexp_find_token (key, "q", 0);
  if (!l)
    return rc;
  q = gcry_sexp_nth_data (l, 1, &len);
  /* This is a point representation, the first byte tells you what
   * type.  The only format we understand is uncompressed (0x04)
   * which has layout 0x04 | x | y */
  if (q[0] != 0x04)
    {
      log_error ("Point format for q is not uncompressed\n");
      goto out;
    }
  q++;
  len--;
  /* now should have to equal sized big endian point numbers */
  if ((len & 0x01) == 1)
    {
      log_error ("Point format for q has incorrect length\n");
      goto out;
    }

  len >>= 1;

  p->type = TPM_ALG_ECC;
  p->nameAlg = TPM_ALG_SHA256;
  VAL (p->objectAttributes) = TPMA_OBJECT_NODA |
    TPMA_OBJECT_SIGN |
    TPMA_OBJECT_DECRYPT |
    TPMA_OBJECT_USERWITHAUTH;
  VAL_2B (p->authPolicy, size) = 0;
  p->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
  p->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
  p->parameters.eccDetail.curveID = curve;
  p->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
  memcpy (VAL_2B (p->unique.ecc.x, buffer), q, len);
  VAL_2B (p->unique.ecc.x, size) = len;
  memcpy (VAL_2B (p->unique.ecc.y, buffer), q + len, len);
  VAL_2B (p->unique.ecc.y, size) = len;
 out:
  gcry_sexp_release (l);
  return rc;
}

static int
sexp_to_tpm2_sensitive_rsa (TPMT_SENSITIVE *s, gcry_sexp_t key)
{
  gcry_mpi_t p;
  gcry_sexp_t l;
  int rc = -1;
  size_t len;

  s->sensitiveType = TPM_ALG_RSA;
  VAL_2B (s->seedValue, size) = 0;

  l = gcry_sexp_find_token (key, "p", 0);
  if (!l)
    return rc;
  p = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof (VAL_2B (s->sensitive.rsa, buffer));
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, VAL_2B (s->sensitive.rsa, buffer),
		       len, &len, p);
  VAL_2B (s->sensitive.rsa, size) = len;
  gcry_mpi_release (p);

  return rc;
}

static int
sexp_to_tpm2_public_rsa (TPMT_PUBLIC *p, gcry_sexp_t key)
{
  gcry_mpi_t n, e;
  gcry_sexp_t l;
  int rc = -1, i;
  size_t len;
  /* longer than an int */
  unsigned char ebuf[5];
  uint32_t exp = 0;

  p->type = TPM_ALG_RSA;
  p->nameAlg = TPM_ALG_SHA256;
  VAL (p->objectAttributes) = TPMA_OBJECT_NODA |
    TPMA_OBJECT_DECRYPT |
    TPMA_OBJECT_SIGN |
    TPMA_OBJECT_USERWITHAUTH;
  VAL_2B (p->authPolicy, size) = 0;
  p->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
  p->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;

  l = gcry_sexp_find_token (key, "n", 0);
  if (!l)
    return rc;
  n = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof (VAL_2B (p->unique.rsa, buffer));
  p->parameters.rsaDetail.keyBits = gcry_mpi_get_nbits (n);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, VAL_2B (p->unique.rsa, buffer),
		       len, &len, n);
  VAL_2B (p->unique.rsa, size) = len;
  gcry_mpi_release (n);
  if (rc)
    return rc;
  rc = -1;
  l = gcry_sexp_find_token (key, "e", 0);
  if (!l)
    return rc;
  e = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof (ebuf);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, ebuf, len, &len, e);
  gcry_mpi_release (e);
  if (rc)
    return rc;
  if (len > 4)
    return -1;

  /* MPI are simply big endian integers, so convert to uint32 */
  for (i = 0; i < len; i++)
    {
      exp <<= 8;
      exp += ebuf[i];
    }
  if (exp == 0x10001)
    p->parameters.rsaDetail.exponent = 0;
  else
    p->parameters.rsaDetail.exponent = exp;
  return 0;
}

static int
sexp_to_tpm2(TPMT_PUBLIC *p, TPMT_SENSITIVE *s, gcry_sexp_t s_skey)
{
  gcry_sexp_t l1, l2;
  int rc = -1;

  /* find the value of (private-key */
  l1 = gcry_sexp_nth (s_skey, 1);
  if (!l1)
    return rc;

  l2 = gcry_sexp_find_token (l1, "rsa", 0);
  if (l2)
    {
      rc = sexp_to_tpm2_public_rsa (p, l2);
      if (!rc)
	rc = sexp_to_tpm2_sensitive_rsa (s, l2);
    }
  else
    {
      l2 = gcry_sexp_find_token (l1, "ecc", 0);
      if (!l2)
	goto out;
      rc = sexp_to_tpm2_public_ecc (p, l2);
      if (!rc)
	rc = sexp_to_tpm2_sensitive_ecc (s, l2);
    }

  gcry_sexp_release (l2);

 out:
  gcry_sexp_release (l1);
  return rc;
}

/* copied from TPM implementation code */
static TPM_RC
tpm2_ObjectPublic_GetName (NAME_2B *name,
			   TPMT_PUBLIC *tpmtPublic)
{
  TPM_RC rc = 0;
  uint16_t written = 0;
  TPMT_HA digest;
  uint32_t sizeInBytes;
  uint8_t buffer[MAX_RESPONSE_SIZE];

  /* marshal the TPMT_PUBLIC */
  if (rc == 0)
    {
      INT32 size = MAX_RESPONSE_SIZE;
      uint8_t *buffer1 = buffer;
      rc = TSS_TPMT_PUBLIC_Marshal (tpmtPublic, &written, &buffer1, &size);
    }
  /* hash the public area */
  if (rc == 0)
    {
      sizeInBytes = TSS_GetDigestSize (tpmtPublic->nameAlg);
      digest.hashAlg = tpmtPublic->nameAlg;       /* Name digest algorithm */
      /* generate the TPMT_HA */
      rc = TSS_Hash_Generate (&digest, written, buffer, 0, NULL);
    }
  if (rc == 0)
    {
      TPMI_ALG_HASH nameAlgNbo;

      /* copy the digest */
      memcpy (name->name + sizeof (TPMI_ALG_HASH),
	      (uint8_t *)&digest.digest, sizeInBytes);
      /* copy the hash algorithm */
      nameAlgNbo = htons (tpmtPublic->nameAlg);
      memcpy (name->name, (uint8_t *)&nameAlgNbo, sizeof (TPMI_ALG_HASH));
      /* set the size */
      name->size = sizeInBytes + sizeof (TPMI_ALG_HASH);
    }
  return rc;
}

/*
 * Cut down version of Part 4 Supporting Routines 7.6.3.10
 *
 * Hard coded to symmetrically encrypt with aes128 as the inner
 * wrapper and no outer wrapper but with a prototype that allows
 * drop in replacement with a tss equivalent
 */
TPM_RC tpm2_SensitiveToDuplicate (TPMT_SENSITIVE *s,
				  NAME_2B *name,
				  TPM_ALG_ID nalg,
				  TPMT_SYM_DEF_OBJECT *symdef,
				  DATA_2B *innerkey,
				  PRIVATE_2B *p)
{
  BYTE *buf = p->buffer;

  p->size = 0;
  memset (p, 0, sizeof (*p));

  /* hard code AES CFB */
  if (symdef->algorithm == TPM_ALG_AES
      && symdef->mode.aes == TPM_ALG_CFB)
    {
      TPMT_HA hash;
      const int hlen = TSS_GetDigestSize (nalg);
      TPM2B *digest = (TPM2B *)buf;
      TPM2B *s2b;
      int32_t size;
      unsigned char null_iv[AES_128_BLOCK_SIZE_BYTES];
      UINT16 bsize, written = 0;
      gcry_cipher_hd_t hd;

      /* WARNING: don't use the static null_iv trick here:
       * the AES routines alter the passed in iv */
      memset (null_iv, 0, sizeof (null_iv));

      /* reserve space for hash before the encrypted sensitive */
      bsize = sizeof (digest->size) + hlen;
      buf += bsize;
      p->size += bsize;
      s2b = (TPM2B *)buf;

      /* marshal the digest size */
      buf = (BYTE *)&digest->size;
      bsize = hlen;
      size = 2;
      TSS_UINT16_Marshal (&bsize, &written, &buf, &size);

      /* marshal the unencrypted sensitive in place */
      size = sizeof (*s);
      bsize = 0;
      buf = s2b->buffer;
      TSS_TPMT_SENSITIVE_Marshal (s, &bsize, &buf, &size);
      buf = (BYTE *)&s2b->size;
      size = 2;
      TSS_UINT16_Marshal (&bsize, &written, &buf, &size);

      bsize = bsize + sizeof (s2b->size);
      p->size += bsize;

      /* compute hash of unencrypted marshalled sensitive and
       * write to the digest buffer */
      hash.hashAlg = nalg;
      TSS_Hash_Generate (&hash, bsize, s2b,
			 name->size, name->name,
			 0, NULL);
      memcpy (digest->buffer, &hash.digest, hlen);
      gcry_cipher_open (&hd, GCRY_CIPHER_AES128,
			GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
      gcry_cipher_setiv (hd, null_iv, sizeof (null_iv));
      gcry_cipher_setkey (hd, innerkey->buffer, innerkey->size);
      /* encrypt the hash and sensitive in-place */
      gcry_cipher_encrypt (hd, p->buffer, p->size, NULL, 0);
      gcry_cipher_close (hd);

    }
  else if (symdef->algorithm == TPM_ALG_NULL)
    {
      /* Code is for debugging only, should never be used in production */
      TPM2B *s2b = (TPM2B *)buf;
      int32_t size = sizeof (*s);
      UINT16 bsize = 0, written = 0;

      log_error ("Secret key sent to TPM unencrypted\n");
      buf = s2b->buffer;

      /* marshal the unencrypted sensitive in place */
      TSS_TPMT_SENSITIVE_Marshal (s, &bsize, &buf, &size);
      buf = (BYTE *)&s2b->size;
      size = 2;
      TSS_UINT16_Marshal (&bsize, &written, &buf, &size);

      p->size += bsize + sizeof (s2b->size);
    }
  else
    {
      log_error ("Unknown symmetric algorithm\n");
      return TPM_RC_SYMMETRIC;
    }

  return TPM_RC_SUCCESS;
}

int
tpm2_import_key (ctrl_t ctrl, TSS_CONTEXT *tssc,
		 gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
				       char **retstr),
		 unsigned char **shadow_info, size_t *shadow_len,
		 gcry_sexp_t s_skey, unsigned long parent)
{
  TPM_HANDLE parentHandle;
  DATA_2B encryptionKey;
  TPM2B_PUBLIC objectPublic;
  PRIVATE_2B duplicate;
  ENCRYPTED_SECRET_2B inSymSeed;
  TPMT_SYM_DEF_OBJECT symmetricAlg;
  PRIVATE_2B outPrivate;
  NAME_2B name;
  const int aes_key_bits = 128;
  const int aes_key_bytes = aes_key_bits/8;

  TPMT_SENSITIVE s;
  TPM_HANDLE ah;
  TPM_RC rc;

  uint32_t size;
  uint16_t len;
  BYTE *buffer;
  int ret;
  char *passphrase;

  char pub[sizeof (TPM2B_PUBLIC)];
  int pub_len;
  char priv[sizeof (TPM2B_PRIVATE)];
  int priv_len;

  if (parent == 0)
    parent = EXT_TPM_RH_OWNER;

  ret = sexp_to_tpm2 (&objectPublic.publicArea, &s, s_skey);
  if (ret)
    {
      log_error ("Failed to parse Key s-expression: key corrupt?\n");
      return ret;
    }

  /* add an authorization password to the key which the TPM will check */

  ret = pin_cb (ctrl,  _("Please enter the TPM Authorization passphrase for the key."), &passphrase);
  if (ret)
    return ret;
  len = strlen(passphrase);
  if (len > TSS_GetDigestSize(objectPublic.publicArea.nameAlg))
    {
      len = TSS_GetDigestSize(objectPublic.publicArea.nameAlg);
      log_error ("Truncating Passphrase to TPM allowed %d\n", len);
    }
  VAL_2B (s.authValue, size) = len;
  memcpy (VAL_2B (s.authValue, buffer), passphrase, len);

  /* We're responsible for securing the data in transmission to the
   * TPM here.  The TPM provides parameter encryption via a session,
   * but only for the first parameter.  For TPM2_Import, the first
   * parameter is a symmetric key used to encrypt the sensitive data,
   * so we must populate this key with random value and encrypt the
   * sensitive data with it */
  parentHandle = tpm2_get_parent (tssc, parent);
  tpm2_ObjectPublic_GetName (&name, &objectPublic.publicArea);
  gcry_randomize (encryptionKey.buffer,
                 aes_key_bytes, GCRY_STRONG_RANDOM);
  encryptionKey.size = aes_key_bytes;

  /* set random symSeed */
  inSymSeed.size = 0;
  symmetricAlg.algorithm = TPM_ALG_AES;
  symmetricAlg.keyBits.aes = aes_key_bits;
  symmetricAlg.mode.aes = TPM_ALG_CFB;

  tpm2_SensitiveToDuplicate (&s, &name, objectPublic.publicArea.nameAlg,
			     &symmetricAlg, &encryptionKey, &duplicate);

  /* use salted parameter encryption to hide the key.  First we read
   * the public parameters of the parent key and use them to agree an
   * encryption for the first parameter */
  rc = tpm2_get_hmac_handle (tssc, &ah, parentHandle);
  if (rc)
    {
      tpm2_flush_handle (tssc, parentHandle);
      return GPG_ERR_CARD;
    }

  rc = tpm2_Import (tssc, parentHandle, &encryptionKey, &objectPublic,
		    &duplicate, &inSymSeed, &symmetricAlg, &outPrivate,
		    ah, NULL);
  tpm2_flush_handle (tssc, parentHandle);
  if (rc)
    {
      tpm2_error (rc, "TPM2_Import");
      /* failure means auth handle is not flushed */
      tpm2_flush_handle (tssc, ah);

      if ((rc & 0xbf) == TPM_RC_VALUE)
	{
	  log_error ("TPM cannot import RSA key: wrong size");
	  return GPG_ERR_UNSUPPORTED_ALGORITHM;
	}
      else if ((rc & 0xbf) == TPM_RC_CURVE)
	{
	  log_error ("TPM cannot import requested curve");
	  return GPG_ERR_UNKNOWN_CURVE;
	}
      return GPG_ERR_CARD;
    }

  size = sizeof (pub);
  buffer = pub;
  len = 0;
  TSS_TPM2B_PUBLIC_Marshal (&objectPublic,
                            &len, &buffer, &size);
  pub_len = len;

  size = sizeof (priv);
  buffer = priv;
  len = 0;
  TSS_TPM2B_PRIVATE_Marshal ((TPM2B_PRIVATE *)&outPrivate,
			     &len, &buffer, &size);
  priv_len = len;

  *shadow_info = make_tpm2_shadow_info (parent, pub, pub_len,
					priv, priv_len, shadow_len);
  return rc;
}

int
tpm2_ecc_decrypt (ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		  gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
					char **retstr),
		  const char *ciphertext, int ciphertext_len,
		  char **decrypt, size_t *decrypt_len)
{
  TPM2B_ECC_POINT inPoint;
  TPM2B_ECC_POINT outPoint;
  TPM_HANDLE ah;
  char *auth;
  size_t len;
  int ret;

  /* This isn't really a decryption per se.  The ciphertext actually
   * contains an EC Point which we must multiply by the private key number.
   *
   * The reason is to generate a diffe helman agreement on a shared
   * point.  This shared point is then used to generate the per
   * session encryption key.
   */
  if (ciphertext[0] != 0x04)
    {
      log_error ("Decryption Shared Point format is not uncompressed\n");
      return GPG_ERR_ENCODING_PROBLEM;
    }
  if ((ciphertext_len & 0x01) != 1)
    {
      log_error ("Decryption Shared Point has incorrect length\n");
      return GPG_ERR_ENCODING_PROBLEM;
    }
  len = ciphertext_len >> 1;

  memcpy (VAL_2B (inPoint.point.x, buffer), ciphertext + 1, len);
  VAL_2B (inPoint.point.x, size) = len;
  memcpy (VAL_2B (inPoint.point.y, buffer), ciphertext + 1 + len, len);
  VAL_2B (inPoint.point.y, size) = len;

  ret = tpm2_pre_auth (ctrl, tssc, pin_cb, &ah, &auth);
  if (ret)
    return ret;
  ret = tpm2_ECDH_ZGen (tssc, key, &inPoint, &outPoint, ah, auth);
  ret = tpm2_post_auth (tssc, ret, ah, &auth, "TPM2_ECDH_ZGen");
  if (ret)
    return ret;

  *decrypt_len = VAL_2B (outPoint.point.x, size) +
	  VAL_2B (outPoint.point.y, size) + 1;
  *decrypt = xtrymalloc (*decrypt_len);
  (*decrypt)[0] = 0x04;
  memcpy (*decrypt + 1, VAL_2B (outPoint.point.x, buffer),
	  VAL_2B (outPoint.point.x, size));
  memcpy (*decrypt + 1 + VAL_2B (outPoint.point.x, size),
	  VAL_2B (outPoint.point.y, buffer),
	  VAL_2B (outPoint.point.y, size));

  return 0;
}

int
tpm2_rsa_decrypt (ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		  gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
					char **retstr),
		  const char *ciphertext, int ciphertext_len,
		  char **decrypt, size_t *decrypt_len)
{
  int ret;
  PUBLIC_KEY_RSA_2B cipherText;
  TPMT_RSA_DECRYPT inScheme;
  PUBLIC_KEY_RSA_2B message;
  TPM_HANDLE ah;
  char *auth;

  inScheme.scheme = TPM_ALG_RSAES;
  /*
   * apparent gcrypt error: occasionally rsa ciphertext will
   * be one byte too long and have a leading zero
   */
  if ((ciphertext_len & 1) == 1 && ciphertext[0] == 0)
    {
      log_info ("Fixing Wrong Ciphertext size %d\n", ciphertext_len);
      ciphertext_len--;
      ciphertext++;
    }
  cipherText.size = ciphertext_len;
  memcpy (cipherText.buffer, ciphertext, ciphertext_len);

  ret = tpm2_pre_auth (ctrl, tssc, pin_cb, &ah, &auth);
  if (ret)
    return ret;
  ret = tpm2_RSA_Decrypt (tssc, key, &cipherText, &inScheme, &message,
			  ah, auth, TPMA_SESSION_ENCRYPT);
  ret = tpm2_post_auth (tssc, ret, ah, &auth, "TPM2_RSA_Decrypt");
  if (ret)
    return ret;

  *decrypt_len = message.size;
  *decrypt = xtrymalloc (message.size);
  memcpy (*decrypt, message.buffer, message.size);

  return 0;
}
