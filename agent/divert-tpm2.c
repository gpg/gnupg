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

int
divert_tpm2_pksign (ctrl_t ctrl,
                    const unsigned char *digest, size_t digestlen, int algo,
                    const unsigned char *shadow_info, unsigned char **r_sig,
                    size_t *r_siglen)
{
  (void)algo;
  return agent_tpm2d_pksign(ctrl, digest, digestlen,
			    shadow_info, r_sig, r_siglen);
}


static gpg_error_t
agent_write_tpm2_shadow_key (ctrl_t ctrl, const unsigned char *grip,
			     unsigned char *shadow_info,
			     gcry_sexp_t s_key)
{
  gpg_error_t err, err1;
  unsigned char *shdkey;
  unsigned char *pkbuf;
  size_t len;
  gcry_sexp_t s_pkey;

  err = agent_public_key_from_file (ctrl, grip, &s_pkey);
  len = gcry_sexp_sprint(s_pkey, GCRYSEXP_FMT_CANON, NULL, 0);
  pkbuf = xtrymalloc (len);
  gcry_sexp_sprint (s_pkey, GCRYSEXP_FMT_CANON, pkbuf, len);
  gcry_sexp_release (s_pkey);

  err = agent_shadow_key_type (pkbuf, shadow_info, "tpm2-v1", &shdkey);
  xfree (pkbuf);
  if (err)
    {
      log_error ("shadowing the tpm key failed: %s\n", gpg_strerror (err));
      return err;
    }

  err = agent_delete_key (ctrl, NULL, grip, 1, 0);
  if (err)
    {
      log_error ("failed to delete unshadowed key: %s\n", gpg_strerror (err));
      return err;
    }

  len = gcry_sexp_canon_len (shdkey, 0, NULL, NULL);
  err = agent_write_private_key (ctrl, grip, shdkey, len, 1 /*force*/,
                                 NULL, NULL, NULL, 0);
  xfree (shdkey);
  if (err)
    {
      log_error ("error writing tpm key: %s\n", gpg_strerror (err));

      len = gcry_sexp_sprint(s_key, GCRYSEXP_FMT_CANON, NULL, 0);
      pkbuf = xtrymalloc(len);
      if (!pkbuf)
	return GPG_ERR_ENOMEM;

      gcry_sexp_sprint(s_key, GCRYSEXP_FMT_CANON, pkbuf, len);
      err1 = agent_write_private_key (ctrl, grip, pkbuf, len, 1 /*force*/,
				      NULL, NULL, NULL, 0);
      xfree(pkbuf);
      if (err1)
	  log_error ("error trying to restore private key: %s\n",
		     gpg_strerror (err1));
    }

  return err;
}

int
divert_tpm2_writekey (ctrl_t ctrl, const unsigned char *grip,
                      gcry_sexp_t s_skey)
{
  int ret;
  /* shadow_info is always shielded so no special handling required */
  unsigned char *shadow_info;

  ret = agent_tpm2d_writekey(ctrl, &shadow_info, s_skey);
  if (!ret) {
    ret = agent_write_tpm2_shadow_key (ctrl, grip, shadow_info, s_skey);
    xfree (shadow_info);
  }
  return ret;
}

int
divert_tpm2_pkdecrypt (ctrl_t ctrl,
                       const unsigned char *cipher,
                       const unsigned char *shadow_info,
                       char **r_buf, size_t *r_len, int *r_padding)
{
  const unsigned char *s;
  size_t n;

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

  return agent_tpm2d_pkdecrypt (ctrl, s, n, shadow_info, r_buf, r_len);
}
