/* pkdecrypt.c - public key decryption (well, actually using a secret key)
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"


/* DECRYPT the stuff in ciphertext which is expected to be a S-Exp.
   Try to get the key from CTRL and write the decoded stuff back to
   OUTFP.   The padding information is stored at R_PADDING with -1
   for not known.  */
gpg_error_t
agent_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                 const unsigned char *ciphertext, size_t ciphertextlen,
                 membuf_t *outbuf, int *r_padding)
{
  gcry_sexp_t s_skey = NULL, s_cipher = NULL, s_plain = NULL;
  unsigned char *shadow_info = NULL;
  gpg_error_t err = 0;
  int no_shadow_info = 0;
  char *buf = NULL;
  size_t len;

  *r_padding = -1;

  if (!ctrl->have_keygrip)
    {
      log_error ("speculative decryption not yet supported\n");
      err = gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }

  err = gcry_sexp_sscan (&s_cipher, NULL, (char*)ciphertext, ciphertextlen);
  if (err)
    {
      log_error ("failed to convert ciphertext: %s\n", gpg_strerror (err));
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      log_printhex (ctrl->keygrip, 20, "keygrip:");
      log_printhex (ciphertext, ciphertextlen, "cipher: ");
    }
  err = agent_key_from_file (ctrl, NULL, desc_text,
                             NULL, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey, NULL, NULL);
  if (gpg_err_code (err) == GPG_ERR_NO_SECKEY)
    no_shadow_info = 1;
  else if (err)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  if (shadow_info || no_shadow_info)
    { /* divert operation to the smartcard */

      if (!gcry_sexp_canon_len (ciphertext, ciphertextlen, NULL, NULL))
        {
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto leave;
        }

      if (s_skey && agent_is_tpm2_key (s_skey))
	err = divert_tpm2_pkdecrypt (ctrl, ciphertext, shadow_info,
                                     &buf, &len, r_padding);
      else
        err = divert_pkdecrypt (ctrl, ctrl->keygrip, ciphertext,
                                &buf, &len, r_padding);
      if (err)
        {
          /* We restore the original error (ie. no seckey) is no card
           * has been found and we have no shadow key.  This avoids a
           * surprising "card removed" error code.  */
          if ((gpg_err_code (err) == GPG_ERR_CARD_REMOVED
               || gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
              && no_shadow_info)
            err = gpg_error (GPG_ERR_NO_SECKEY);
          else
            log_error ("smartcard decryption failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      put_membuf_printf (outbuf, "(5:value%u:", (unsigned int)len);
      put_membuf (outbuf, buf, len);
      put_membuf (outbuf, ")", 2);
    }
  else
    { /* No smartcard, but a private key */
/*       if (DBG_CRYPTO ) */
/*         { */
/*           log_debug ("skey: "); */
/*           gcry_sexp_dump (s_skey); */
/*         } */

      err = gcry_pk_decrypt (&s_plain, s_cipher, s_skey);
      if (err)
        {
          log_error ("decryption failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (DBG_CRYPTO)
        {
          log_debug ("plain: ");
          gcry_sexp_dump (s_plain);
        }
      len = gcry_sexp_sprint (s_plain, GCRYSEXP_FMT_CANON, NULL, 0);
      log_assert (len);
      buf = xmalloc (len);
      len = gcry_sexp_sprint (s_plain, GCRYSEXP_FMT_CANON, buf, len);
      log_assert (len);
      if (*buf == '(')
        put_membuf (outbuf, buf, len);
      else
        {
          /* Old style libgcrypt: This is only an S-expression
             part. Turn it into a complete S-expression. */
          put_membuf (outbuf, "(5:value", 8);
          put_membuf (outbuf, buf, len);
          put_membuf (outbuf, ")", 2);
        }
    }


 leave:
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_plain);
  gcry_sexp_release (s_cipher);
  xfree (buf);
  xfree (shadow_info);
  return err;
}
