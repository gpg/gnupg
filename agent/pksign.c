/* pksign.c - public key signing (well, acually using a secret key)
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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


static int
do_encode_md (const byte * md, size_t mdlen, int algo, gcry_sexp_t * r_hash)
{
  gcry_sexp_t hash;
  const char * s;
  char * p, tmp[16];
  int i, rc;

#warning I do do like that stuff - libgcrypt provides easier interfaces. -wk
  /* FIXME: Either use the build function or create canonical encoded
     S-expressions. */

  p = xmalloc (64 + 2 * mdlen);
  s = gcry_md_algo_name (algo);
  if (s && strlen (s) < 16)
    {
      for (i=0; i < strlen (s); i++)
        tmp[i] = tolower (s[i]);
      tmp[i] = '\0';   
    }
  sprintf (p, "(data\n (flags pkcs1)\n (hash %s #", tmp);
  for (i=0; i < mdlen; i++)
    {
      sprintf (tmp, "%02x", (byte)md[i]);
      strcat (p, tmp);   
    }
  strcat (p, "#))\n");
  rc = gcry_sexp_sscan (&hash, NULL, p, strlen (p));
  xfree (p);
  *r_hash = hash;
  return rc;   
}


/* SIGN whatever information we have accumulated in CTRL and write it
   back to OUTFP. */
int
agent_pksign (CTRL ctrl, FILE *outfp, int ignore_cache) 
{
  gcry_sexp_t s_skey = NULL, s_hash = NULL, s_sig = NULL;
  unsigned char *shadow_info = NULL;
  int rc;
  char *buf = NULL;
  size_t len;

  if (!ctrl->have_keygrip)
    return gpg_error (GPG_ERR_NO_SECKEY);

  s_skey = agent_key_from_file (ctrl,
                                ctrl->keygrip, &shadow_info, ignore_cache);
  if (!s_skey && !shadow_info)
    {
      log_error ("failed to read the secret key\n");
      rc = gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }

  if (!s_skey)
    { /* divert operation to the smartcard */
      unsigned char *sigbuf;

      rc = divert_pksign (ctrl, 
                          ctrl->digest.value, 
                          ctrl->digest.valuelen,
                          ctrl->digest.algo,
                          shadow_info, &sigbuf);
      if (rc)
        {
          log_error ("smartcard signing failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      len = gcry_sexp_canon_len (sigbuf, 0, NULL, NULL);
      assert (len);
      buf = sigbuf;
    }
  else
    { /* no smartcard, but a private key */

      /* put the hash into a sexp */
      rc = do_encode_md (ctrl->digest.value,
                         ctrl->digest.valuelen,
                         ctrl->digest.algo,
                         &s_hash);
      if (rc)
        goto leave;

      if (DBG_CRYPTO)
        {
          log_debug ("skey: ");
          gcry_sexp_dump (s_skey);
        }

      /* sign */
      rc = gcry_pk_sign (&s_sig, s_hash, s_skey);
      if (rc)
        {
          log_error ("signing failed: %s\n", gpg_strerror (rc));
          rc = map_gcry_err (rc);
          goto leave;
        }

      if (DBG_CRYPTO)
        {
          log_debug ("result: ");
          gcry_sexp_dump (s_sig);
        }

      len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
      assert (len);
      buf = xmalloc (len);
      len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, buf, len);
      assert (len);
    }

  /* FIXME: we must make sure that no buffering takes place or we are
     in full control of the buffer memory (easy to do) - should go
     into assuan. */
  fwrite (buf, 1, len, outfp);

 leave:
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_sig);
  xfree (buf);
  xfree (shadow_info);
  return rc;
}


