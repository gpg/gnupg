/* pksign.c - public key signing (well, acually using a secret key)
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


static int
do_encode_md (const unsigned char *digest, size_t digestlen, int algo,
              unsigned int nbits, GCRY_MPI *r_val)
{
  int nframe = (nbits+7) / 8;
  byte *frame;
  int i, n;
  byte asn[100];
  size_t asnlen;

  asnlen = DIM(asn);
  if (gcry_md_algo_info (algo, GCRYCTL_GET_ASNOID, asn, &asnlen))
    {
      log_error ("no object identifier for algo %d\n", algo);
      return GNUPG_Internal_Error;
    }

  if (digestlen + asnlen + 4  > nframe )
    {
      log_error ("can't encode a %d bit MD into a %d bits frame\n",
                 (int)(digestlen*8), (int)nbits);
      return GNUPG_Internal_Error;
    }
  
  /* We encode the MD in this way:
   *
   *	   0  1 PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
   *
   * PAD consists of FF bytes.
   */
  frame = xtrymalloc (nframe);
  if (!frame)
    return GNUPG_Out_Of_Core;
  n = 0;
  frame[n++] = 0;
  frame[n++] = 1; /* block type */
  i = nframe - digestlen - asnlen -3 ;
  assert ( i > 1 );
  memset ( frame+n, 0xff, i ); n += i;
  frame[n++] = 0;
  memcpy ( frame+n, asn, asnlen ); n += asnlen;
  memcpy ( frame+n, digest, digestlen ); n += digestlen;
  assert ( n == nframe );
  if (DBG_CRYPTO)
    log_printhex ("encoded hash:", frame, nframe);
      
  gcry_mpi_scan (r_val, GCRYMPI_FMT_USG, frame, &nframe);
  xfree (frame);
  return 0;
}


/* SIGN whatever information we have accumulated in CTRL and write it
   back to OUTFP. */
int
agent_pksign (CTRL ctrl, FILE *outfp) 
{
  GCRY_SEXP s_skey = NULL, s_hash = NULL, s_sig = NULL;
  GCRY_MPI frame = NULL;
  unsigned char *shadow_info = NULL;
  int rc;
  char *buf = NULL;
  size_t len;

  if (!ctrl->have_keygrip)
    return seterr (No_Secret_Key);

  s_skey = agent_key_from_file (ctrl->keygrip, &shadow_info);
  if (!s_skey && !shadow_info)
    {
      log_error ("failed to read the secret key\n");
      rc = seterr (No_Secret_Key);
      goto leave;
    }

  if (!s_skey)
    { /* divert operation to the smartcard */
      unsigned char *sigbuf;

      rc = divert_pksign (ctrl->digest.value, 
                          ctrl->digest.valuelen,
                          ctrl->digest.algo,
                          shadow_info, &sigbuf);
      if (rc)
        {
          log_error ("smartcard signing failed: %s\n", gnupg_strerror (rc));
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
                         gcry_pk_get_nbits (s_skey),
                         &frame);
      if (rc)
        goto leave;
      if ( gcry_sexp_build (&s_hash, NULL, "%m", frame) )
        BUG ();

      if (DBG_CRYPTO)
        {
          log_debug ("skey: ");
          gcry_sexp_dump (s_skey);
        }

      /* sign */
      rc = gcry_pk_sign (&s_sig, s_hash, s_skey);
      if (rc)
        {
          log_error ("signing failed: %s\n", gcry_strerror (rc));
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
  gcry_mpi_release (frame);
  xfree (buf);
  xfree (shadow_info);
  return rc;
}


