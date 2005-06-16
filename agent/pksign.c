/* pksign.c - public key signing (well, actually using a secret key)
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
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
do_encode_md (const byte * md, size_t mdlen, int algo, gcry_sexp_t * r_hash,
	      int raw_value)
{
  gcry_sexp_t hash;
  int rc;

  if (! raw_value)
    {
      const char *s;
      char tmp[16+1];
      int i;
      
      s = gcry_md_algo_name (algo);
      if (s && strlen (s) < 16)
	{
	  for (i=0; i < strlen (s); i++)
	    tmp[i] = tolower (s[i]);
	  tmp[i] = '\0';   
	}

      rc = gcry_sexp_build (&hash, NULL,
			    "(data (flags pkcs1) (hash %s %b))",
			    tmp, mdlen, md);
    }
  else
    {
      gcry_mpi_t mpi;
      
      rc = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, md, mdlen, NULL);
      if (! rc)
	{
	  rc = gcry_sexp_build (&hash, NULL,
				"(data (flags raw) (value %m))",
				mpi);
	  gcry_mpi_release (mpi);
	}
	  
    }
  
  *r_hash = hash;
  return rc;   
}


/* SIGN whatever information we have accumulated in CTRL and return
   the signature S-Expression. */
int
agent_pksign_do (ctrl_t ctrl, const char *desc_text,
		 gcry_sexp_t *signature_sexp, cache_mode_t cache_mode)
{
  gcry_sexp_t s_skey = NULL, s_sig = NULL;
  unsigned char *shadow_info = NULL;
  unsigned int rc = 0;		/* FIXME: gpg-error? */

  if (! ctrl->have_keygrip)
    return gpg_error (GPG_ERR_NO_SECKEY);

  rc = agent_key_from_file (ctrl, desc_text, ctrl->keygrip,
                            &shadow_info, cache_mode, &s_skey);
  if (rc)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  if (!s_skey)
    {
      /* Divert operation to the smartcard */

      unsigned char *buf = NULL;
      size_t len = 0;

      rc = divert_pksign (ctrl, 
                          ctrl->digest.value, 
                          ctrl->digest.valuelen,
                          ctrl->digest.algo,
                          shadow_info, &buf);
      if (rc)
        {
          log_error ("smartcard signing failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      len = gcry_sexp_canon_len (buf, 0, NULL, NULL);
      assert (len);

      rc = gcry_sexp_sscan (&s_sig, NULL, (char*)buf, len);
      xfree (buf);
      if (rc)
	{
	  log_error ("failed to convert sigbuf returned by divert_pksign "
		     "into S-Exp: %s", gpg_strerror (rc));
	  goto leave;
	}
    }
  else
    {
      /* No smartcard, but a private key */

      gcry_sexp_t s_hash = NULL;

      /* put the hash into a sexp */
      rc = do_encode_md (ctrl->digest.value,
                         ctrl->digest.valuelen,
                         ctrl->digest.algo,
                         &s_hash,
			 ctrl->digest.raw_value);
      if (rc)
        goto leave;

      if (DBG_CRYPTO)
        {
          log_debug ("skey: ");
          gcry_sexp_dump (s_skey);
        }

      /* sign */
      rc = gcry_pk_sign (&s_sig, s_hash, s_skey);
      gcry_sexp_release (s_hash);
      if (rc)
        {
          log_error ("signing failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (DBG_CRYPTO)
        {
          log_debug ("result: ");
          gcry_sexp_dump (s_sig);
        }
    }

 leave:

  *signature_sexp = s_sig;

  gcry_sexp_release (s_skey);
  xfree (shadow_info);

  return rc;
}

/* SIGN whatever information we have accumulated in CTRL and write it
   back to OUTFP. */
int
agent_pksign (ctrl_t ctrl, const char *desc_text,
              membuf_t *outbuf, cache_mode_t cache_mode) 
{
  gcry_sexp_t s_sig = NULL;
  char *buf = NULL;
  size_t len = 0;
  int rc = 0;

  rc = agent_pksign_do (ctrl, desc_text, &s_sig, cache_mode);
  if (rc)
    goto leave;

  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xmalloc (len);
  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  put_membuf (outbuf, buf, len);

 leave:
  gcry_sexp_release (s_sig);
  xfree (buf);

  return rc;
}
