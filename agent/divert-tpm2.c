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

#include "tpm2.h"

int
divert_tpm2_pksign (ctrl_t ctrl, const char *desc_text,
                    const unsigned char *digest, size_t digestlen, int algo,
                    const unsigned char *shadow_info, unsigned char **r_sig,
                    size_t *r_siglen)
{
  TSS_CONTEXT *tssc;
  TPM_HANDLE key;
  TPMI_ALG_PUBLIC type;
  int ret;

  ret = tpm2_start(&tssc);
  if (ret)
    return ret;
  ret = tpm2_load_key(tssc, shadow_info, &key, &type);
  if (ret)
    goto out;
  ret = tpm2_sign(ctrl, tssc, key, type, digest, digestlen, r_sig, r_siglen);

  tpm2_flush_handle(tssc, key);

 out:
  tpm2_end(tssc);
  return ret;
}

static unsigned char *
make_tpm2_shadow_info (uint32_t parent, const char *pub, int pub_len,
                       const char *priv, int priv_len)
{
  gcry_sexp_t s_exp;
  size_t len;
  char *info;

  gcry_sexp_build(&s_exp, NULL, "(%u%b%b)", parent, pub_len, pub, priv_len, priv);

  len = gcry_sexp_sprint(s_exp, GCRYSEXP_FMT_CANON, NULL, 0);
  info = xtrymalloc(len);
  gcry_sexp_sprint(s_exp, GCRYSEXP_FMT_CANON, info, len);

  gcry_sexp_release(s_exp);

  return (unsigned char *)info;
}

static gpg_error_t
agent_write_tpm2_shadow_key (ctrl_t ctrl, const unsigned char *grip,
                             int parent, char *pub,  int pub_len,
                             char *priv, int priv_len)
{
  gpg_error_t err;
  unsigned char *shadow_info;
  unsigned char *shdkey;
  unsigned char *pkbuf;
  size_t len;
  gcry_sexp_t s_pkey;

  err = agent_public_key_from_file (ctrl, grip, &s_pkey);
  len = gcry_sexp_sprint(s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);
  pkbuf = xtrymalloc (len);
  gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, pkbuf, len);
  gcry_sexp_release (s_pkey);

  shadow_info = make_tpm2_shadow_info (parent, pub, pub_len, priv, priv_len);
  if (!shadow_info) {
    xfree (pkbuf);
    return gpg_error_from_syserror ();
  }

  err = agent_shadow_key_type (pkbuf, shadow_info, "tpm2-v1", &shdkey);
  xfree (shadow_info);
  xfree (pkbuf);
  if (err)
    {
      log_error ("shadowing the key failed: %s\n", gpg_strerror (err));
      return err;
    }

  len = gcry_sexp_canon_len (shdkey, 0, NULL, NULL);
  err = agent_write_private_key (grip, shdkey, len, 1 /*force*/);
  xfree (shdkey);
  if (err)
    log_error ("error writing key: %s\n", gpg_strerror (err));

  return err;
}

int
divert_tpm2_writekey (ctrl_t ctrl, const unsigned char *grip,
                      gcry_sexp_t s_skey)
{
  TSS_CONTEXT *tssc;
  int ret, pub_len, priv_len;
  /* priv is always shielded so no special handling required */
  char pub[sizeof(TPM2B_PUBLIC)], priv[sizeof(TPM2B_PRIVATE)];

  ret = tpm2_start(&tssc);
  if (ret)
    return ret;
  ret = tpm2_import_key (ctrl, tssc, pub, &pub_len, priv, &priv_len, s_skey);
  if (ret)
    goto out;
  ret = agent_write_tpm2_shadow_key (ctrl, grip, TPM2_PARENT, pub, pub_len,
                                     priv, priv_len);
 out:
  tpm2_end(tssc);
  return ret;
}

int
divert_tpm2_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                       const unsigned char *cipher,
                       const unsigned char *shadow_info,
                       char **r_buf, size_t *r_len, int *r_padding)
{
  TSS_CONTEXT *tssc;
  TPM_HANDLE key;
  TPMI_ALG_PUBLIC type;
  int ret;
  const unsigned char *s;
  size_t n;

  *r_padding = -1;

  (void)desc_text;

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
  if (smatch (&s, n, "rsa"))
    {
      *r_padding = 0;
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
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  /* know we have RSA to decrypt at s,n */

  ret = tpm2_start(&tssc);
  if (ret)
    return ret;
  ret = tpm2_load_key(tssc, shadow_info, &key, &type);
  if (ret)
    goto out;

  if (type == TPM_ALG_RSA)
    ret = tpm2_rsa_decrypt(ctrl, tssc, key, s, n, r_buf, r_len);
  else if (type == TPM_ALG_ECC)
    ret = tpm2_ecc_decrypt(ctrl, tssc, key, s, n, r_buf, r_len);

  tpm2_flush_handle(tssc, key);

 out:
  tpm2_end(tssc);
  return ret;

}
