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


/* SIGN whatever information we have accumulated in CTRL and write it
   back to OUTFP. */
int
agent_pksign (CTRL ctrl, FILE *outfp) 
{
  /* our sample key */
  const char n[] = "#8732A669BB7C5057AD070EFA54E035C86DF474F7A7EBE2435"
    "3DADEB86FFE74C32AEEF9E5C6BD7584CB572520167B3E8C89A1FA75C74FF9E938"
    "2710F3B270B638EB96E7486491D81C53CA8A50B4E840B1C7458A4A1E52EC18D681"
    "8A2805C9165827F77EF90D55014E4B2AF9386AE8F6462F46A547CB593ABD509311"
    "4D3D16375F#";
  const char e[] = "#11#";
  const char d[] = "#07F3EBABDDDA22D7FB1E8869140D30571586D9B4370DE02213F"
    "DD0DDAC3C24FC6BEFF0950BB0CAAD755F7AA788DA12BCF90987341AC8781CC7115"
    "B59A115B05D9D99B3D7AF77854DC2EE6A36154512CC0EAD832601038A88E837112"
    "AB2A39FD9FBE05E30D6FFA6F43D71C59F423CA43BC91C254A8C89673AB61F326B0"
    "762FBC9#";
  const char p[] = "#B2ABAD4328E66303E206C53CFBED17F18F712B1C47C966EE13DD"
    "AA9AD3616A610ADF513F8376FA48BAE12FED64CECC1E73091A77B45119AF0FC1286A"
    "85BD9BBD#";
  const char q[] = "#C1B648B294BB9AEE7FEEB77C4F64E9333E4EA9A7C54D521356FB"
    "BBB7558A0E7D6331EC7B42E3F0CD7BBBA9B7A013422F615F10DCC1E8462828BF8FC7"
    "39C5E34B#";
  const char  u[] = "#A9B5EFF9C80A4A356B9A95EB63E381B262071E5CE9C1F32FF03"
    "83AD8289BED8BC690555E54411FA2FDB9B49638A21B2046C325F5633B4B1ECABEBFD"
    "1B3519072#";

  GCRY_SEXP s_skey, s_hash, s_sig;
  GCRY_MPI frame;
  int rc;
  char *buf;
  size_t len;

  /* create a secret key as an sexp */
  log_debug ("Using HARDWIRED secret key\n");
  asprintf (&buf, "(private-key(oid.1.2.840.113549.1.1.1"
           "(n %s)(e %s)(d %s)(p %s)(q %s)(u %s)))",
           n, e, d, p, q, u);
  /* asprintf does not use our allocation fucntions, so we can't
     use our free */
  rc = gcry_sexp_sscan (&s_skey, NULL, buf, strlen(buf));
  free (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp: %s\n", gcry_strerror (rc));
      return map_gcry_err (rc);
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

  fwrite (buf, 1, strlen(buf), outfp);
  return 0;
}


