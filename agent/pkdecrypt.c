/* pkdecrypt.c - public key decryption (well, acually using a secret key)
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"


/* DECRYPT the stuff in ciphertext which is expected to be a S-Exp.
   Try to get the key from CTRL and write the decoded stuff back to
   OUTFP. */
int
agent_pkdecrypt (CTRL ctrl, const char *ciphertext, size_t ciphertextlen,
                 FILE *outfp) 
{
  GCRY_SEXP s_skey = NULL, s_cipher = NULL, s_plain = NULL;
  int rc;
  char *buf = NULL;
  size_t len;

  if (!ctrl->have_keygrip)
    {
      log_error ("speculative decryption not yet supported\n");
      rc = seterr (No_Secret_Key);
      goto leave;
    }

  rc = gcry_sexp_sscan (&s_cipher, NULL, ciphertext, ciphertextlen);
  if (rc)
    {
      log_error ("failed to convert ciphertext: %s\n", gcry_strerror (rc));
      rc = seterr (Invalid_Data);
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      log_printhex ("keygrip:", ctrl->keygrip, 20);
      log_printhex ("cipher: ", ciphertext, ciphertextlen);
    }
  s_skey = agent_key_from_file (ctrl->keygrip);
  if (!s_skey)
    {
      log_error ("failed to read the secret key\n");
      rc = seterr (No_Secret_Key);
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      log_debug ("skey: ");
      gcry_sexp_dump (s_skey);
    }

  rc = gcry_pk_decrypt (&s_plain, s_cipher, s_skey);
  if (rc)
    {
      log_error ("decryption failed: %s\n", gcry_strerror (rc));
      rc = map_gcry_err (rc);
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      log_debug ("plain: ");
      gcry_sexp_dump (s_plain);
    }
  len = gcry_sexp_sprint (s_plain, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xmalloc (len);
  len = gcry_sexp_sprint (s_plain, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  /* FIXME: we must make sure that no buffering takes place or we are
     in full control of the buffer memory (easy to do) - should go
     into assuan. */
  fwrite (buf, 1, len, outfp);

 leave:
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_plain);
  gcry_sexp_release (s_cipher);
  xfree (buf);
  return rc;
}


