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
      log_error ("No object identifier for algo %d\n", algo);
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
   *	   0  A PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
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
    {
      int j;
      log_debug ("encoded hash:");
      for (j=0; j < nframe; j++)
        log_printf (" %02X", frame[j]);
      log_printf ("\n");
    }
      
  gcry_mpi_scan (r_val, GCRYMPI_FMT_USG, frame, &nframe);
  xfree (frame);
  return 0;
}


static GCRY_SEXP
key_from_file (const unsigned char *grip)
{
  int i, rc;
  char *fname;
  FILE *fp;
  struct stat st;
  char *buf;
  size_t buflen, erroff;
  GCRY_SEXP s_skey;
  char hexgrip[41];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  hexgrip[40] = 0;

  fname = make_filename (opt.homedir, "private-keys-v1.d", hexgrip, NULL );
  fp = fopen (fname, "rb");
  if (!fp)
    {
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return NULL;
    }
  
  if (fstat (fileno(fp), &st))
    {
      log_error ("can't stat `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      log_error ("error reading `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      xfree (buf);
      return NULL;
    }

  rc = gcry_sexp_sscan (&s_skey, &erroff, buf, buflen);
  xfree (fname);
  fclose (fp);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gcry_strerror (rc));
      return NULL;
    }

  return s_skey;
}



/* SIGN whatever information we have accumulated in CTRL and write it
   back to OUTFP. */
int
agent_pksign (CTRL ctrl, FILE *outfp) 
{
  GCRY_SEXP s_skey, s_hash, s_sig;
  GCRY_MPI frame;
  int rc;
  char *buf;
  size_t len;

  s_skey = key_from_file (ctrl->keygrip);
  if (!s_skey)
    {
      log_error ("failed to read the secret key\n");
      return seterr (No_Secret_Key);
    }

  /* put the hash into a sexp */
  rc = do_encode_md (ctrl->digest.value,
                     ctrl->digest.valuelen,
                     ctrl->digest.algo,
                     gcry_pk_get_nbits (s_skey),
                     &frame);
  if (rc)
    {
      /* fixme: clean up some things */
      return rc;
    }
  if ( gcry_sexp_build (&s_hash, NULL, "%m", frame) )
    BUG ();


  /* sign */
  rc = gcry_pk_sign (&s_sig, s_hash, s_skey);
  if (rc)
    {
      log_error ("signing failed: %s\n", gcry_strerror (rc));
      return map_gcry_err (rc);
    }

  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xmalloc (len);
  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  /* FIXME: we must make sure that no buffering takes place or we are
     in full control of the buffer memory (easy to do) - should go
     into assuan. */
  fwrite (buf, 1, strlen(buf), outfp);
  return 0;
}


