/* seskey.c -  make session keys etc.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2006, 2009, 2010 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "options.h"
#include "main.h"
#include "../common/i18n.h"


/* Generate a new session key in *DEK that is appropriate for the
 * algorithm DEK->ALGO (i.e., ensure that the key is not weak).
 *
 * This function overwrites DEK->KEYLEN, DEK->KEY.  The rest of the
 * fields are left as is.  */
void
make_session_key( DEK *dek )
{
    gcry_cipher_hd_t chd;
    int i, rc;

    dek->keylen = openpgp_cipher_get_algo_keylen (dek->algo);

    if (openpgp_cipher_open (&chd, dek->algo, GCRY_CIPHER_MODE_CFB,
			     (GCRY_CIPHER_SECURE
			      | (dek->algo >= 100 ?
				 0 : GCRY_CIPHER_ENABLE_SYNC))) )
      BUG();
    gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM );
    for (i=0; i < 16; i++ )
      {
	rc = gcry_cipher_setkey (chd, dek->key, dek->keylen);
	if (!rc)
          {
	    gcry_cipher_close (chd);
	    return;
          }
        if (gpg_err_code (rc) != GPG_ERR_WEAK_KEY)
          BUG();
	log_info(_("weak key created - retrying\n") );
	/* Renew the session key until we get a non-weak key. */
	gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM);
      }
    log_fatal (_("cannot avoid weak key for symmetric cipher; "
                 "tried %d times!\n"), i);
}


/* Encode the session key stored in DEK as an MPI in preparation to
 * encrypt it with the public key algorithm OPENPGP_PK_ALGO with a key
 * whose length (the size of the public key) is NBITS.
 *
 * On success, returns an MPI, which the caller must free using
 * gcry_mpi_release().  */
gcry_mpi_t
encode_session_key (int openpgp_pk_algo, DEK *dek, unsigned int nbits)
{
  size_t nframe = (nbits+7) / 8;
  byte *p;
  byte *frame;
  int i,n;
  u16 csum;
  gcry_mpi_t a;

  if (DBG_CRYPTO)
    log_debug ("encode_session_key: encoding %d byte DEK", dek->keylen);

  csum = 0;
  for (p = dek->key, i=0; i < dek->keylen; i++)
    csum += *p++;

  /* Shortcut for ECDH.  It's padding is minimal to simply make the
     output be a multiple of 8 bytes.  */
  if (openpgp_pk_algo == PUBKEY_ALGO_ECDH)
    {
      /* Pad to 8 byte granulatiry; the padding byte is the number of
       * padded bytes.
       *
       * A  DEK(k bytes)  CSUM(2 bytes) 0x 0x 0x 0x ... 0x
       *                                +---- x times ---+
       */
      nframe = (( 1 + dek->keylen + 2 /* The value so far is always odd. */
                  + 7 ) & (~7));

      /* alg+key+csum fit and the size is congruent to 8.  */
      log_assert (!(nframe%8) && nframe > 1 + dek->keylen + 2 );

      frame = xmalloc_secure (nframe);
      n = 0;
      frame[n++] = dek->algo;
      memcpy (frame+n, dek->key, dek->keylen);
      n += dek->keylen;
      frame[n++] = csum >> 8;
      frame[n++] = csum;
      i = nframe - n;         /* Number of padded bytes.  */
      memset (frame+n, i, i); /* Use it as the value of each padded byte.  */
      log_assert (n+i == nframe);

      if (DBG_CRYPTO)
        log_debug ("encode_session_key: "
                   "[%d] %02x  %02x %02x ...  %02x %02x %02x\n",
                   (int) nframe, frame[0], frame[1], frame[2],
                   frame[nframe-3], frame[nframe-2], frame[nframe-1]);

      if (gcry_mpi_scan (&a, GCRYMPI_FMT_USG, frame, nframe, &nframe))
        BUG();
      xfree(frame);
      return a;
    }

  /* The current limitation is that we can only use a session key
   * whose length is a multiple of BITS_PER_MPI_LIMB
   * I think we can live with that.
   */
  if (dek->keylen + 7 > nframe || !nframe)
    log_bug ("can't encode a %d bit key in a %d bits frame\n",
             dek->keylen*8, nbits );

  /* We encode the session key according to PKCS#1 v1.5 (see section
   * 13.1.1 of RFC 4880):
   *
   *	   0  2  RND(i bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
   *
   * (But how can we store the leading 0 - the external representaion
   *  of MPIs doesn't allow leading zeroes =:-)
   *
   * RND are (at least 1) non-zero random bytes.
   * A   is the cipher algorithm
   * DEK is the encryption key (session key) length k depends on the
   *	   cipher algorithm (20 is used with blowfish160).
   * CSUM is the 16 bit checksum over the DEK
   */

  frame = xmalloc_secure( nframe );
  n = 0;
  frame[n++] = 0;
  frame[n++] = 2;
  /* The number of random bytes are the number of otherwise unused
     bytes.  See diagram above.  */
  i = nframe - 6 - dek->keylen;
  log_assert( i > 0 );
  p = gcry_random_bytes_secure (i, GCRY_STRONG_RANDOM);
  /* Replace zero bytes by new values.  */
  for (;;)
    {
      int j, k;
      byte *pp;

      /* Count the zero bytes. */
      for (j=k=0; j < i; j++ )
        if (!p[j])
          k++;
      if (!k)
        break; /* Okay: no zero bytes. */
      k += k/128 + 3; /* Better get some more. */
      pp = gcry_random_bytes_secure (k, GCRY_STRONG_RANDOM);
      for (j=0; j < i && k ;)
        {
          if (!p[j])
            p[j] = pp[--k];
          if (p[j])
            j++;
        }
      xfree (pp);
    }
  memcpy (frame+n, p, i);
  xfree (p);
  n += i;
  frame[n++] = 0;
  frame[n++] = dek->algo;
  memcpy (frame+n, dek->key, dek->keylen );
  n += dek->keylen;
  frame[n++] = csum >>8;
  frame[n++] = csum;
  log_assert (n == nframe);
  if (gcry_mpi_scan( &a, GCRYMPI_FMT_USG, frame, n, &nframe))
    BUG();
  xfree (frame);
  return a;
}


static gcry_mpi_t
do_encode_md( gcry_md_hd_t md, int algo, size_t len, unsigned nbits,
	      const byte *asn, size_t asnlen )
{
    size_t nframe = (nbits+7) / 8;
    byte *frame;
    int i,n;
    gcry_mpi_t a;

    if (len + asnlen + 4  > nframe)
      {
        log_error ("can't encode a %d bit MD into a %d bits frame, algo=%d\n",
                   (int)(len*8), (int)nbits, algo);
        return NULL;
      }

    /* We encode the MD in this way:
     *
     *	   0  1 PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
     *
     * PAD consists of FF bytes.
     */
    frame = gcry_md_is_secure (md)? xmalloc_secure (nframe) : xmalloc (nframe);
    n = 0;
    frame[n++] = 0;
    frame[n++] = 1; /* block type */
    i = nframe - len - asnlen -3 ;
    log_assert( i > 1 );
    memset( frame+n, 0xff, i ); n += i;
    frame[n++] = 0;
    memcpy( frame+n, asn, asnlen ); n += asnlen;
    memcpy( frame+n, gcry_md_read (md, algo), len ); n += len;
    log_assert( n == nframe );

    if (gcry_mpi_scan( &a, GCRYMPI_FMT_USG, frame, n, &nframe ))
	BUG();
    xfree(frame);

    /* Note that PGP before version 2.3 encoded the MD as:
     *
     *   0   1   MD(16 bytes)   0   PAD(n bytes)   1
     *
     * The MD is always 16 bytes here because it's always MD5.  We do
     * not support pre-v2.3 signatures, but I'm including this comment
     * so the information is easily found in the future.
     */

    return a;
}


/****************
 * Encode a message digest into an MPI.
 * If it's for a DSA signature, make sure that the hash is large
 * enough to fill up q.  If the hash is too big, take the leftmost
 * bits.
 */
gcry_mpi_t
encode_md_value (PKT_public_key *pk, gcry_md_hd_t md, int hash_algo)
{
  gcry_mpi_t frame;
  size_t mdlen;

  log_assert (hash_algo);
  log_assert (pk);

  if (pk->pubkey_algo == PUBKEY_ALGO_EDDSA)
    {
      /* EdDSA signs data of arbitrary length.  Thus no special
         treatment is required.  */
      frame = gcry_mpi_set_opaque_copy (NULL, gcry_md_read (md, hash_algo),
                                        8*gcry_md_get_algo_dlen (hash_algo));
    }
  else if (pk->pubkey_algo == PUBKEY_ALGO_DSA
           || pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
    {
      /* It's a DSA signature, so find out the size of q.  */

      size_t qbits = gcry_mpi_get_nbits (pk->pkey[1]);

      /* pkey[1] is Q for ECDSA, which is an uncompressed point,
         i.e.  04 <x> <y>  */
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
        qbits = ecdsa_qbits_from_Q (qbits);

      /* Make sure it is a multiple of 8 bits. */
      if ((qbits%8))
	{
	  log_error(_("DSA requires the hash length to be a"
		      " multiple of 8 bits\n"));
	  return NULL;
	}

      /* Don't allow any q smaller than 160 bits.  This might need a
	 revisit as the DSA2 design firms up, but for now, we don't
	 want someone to issue signatures from a key with a 16-bit q
	 or something like that, which would look correct but allow
	 trivial forgeries.  Yes, I know this rules out using MD5 with
	 DSA. ;) */
      if (qbits < 160)
	{
	  log_error (_("%s key %s uses an unsafe (%zu bit) hash\n"),
                     openpgp_pk_algo_name (pk->pubkey_algo),
                     keystr_from_pk (pk), qbits);
	  return NULL;
	}


      /* ECDSA 521 is special has it is larger than the largest hash
         we have (SHA-512).  Thus we change the size for further
         processing to 512.  */
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA && qbits > 512)
        qbits = 512;

      /* Check if we're too short.  Too long is safe as we'll
	 automatically left-truncate.  */
      mdlen = gcry_md_get_algo_dlen (hash_algo);
      if (mdlen < qbits/8)
	{
	  log_error (_("%s key %s requires a %zu bit or larger hash "
                       "(hash is %s)\n"),
                     openpgp_pk_algo_name (pk->pubkey_algo),
                     keystr_from_pk (pk), qbits,
                     gcry_md_algo_name (hash_algo));
	  return NULL;
	}

     /* Note that we do the truncation by passing QBITS/8 as length to
        mpi_scan.  */
      if (gcry_mpi_scan (&frame, GCRYMPI_FMT_USG,
                         gcry_md_read (md, hash_algo), qbits/8, NULL))
        BUG();
    }
  else
    {
      gpg_error_t rc;
      byte *asn;
      size_t asnlen;

      rc = gcry_md_algo_info (hash_algo, GCRYCTL_GET_ASNOID, NULL, &asnlen);
      if (rc)
        log_fatal ("can't get OID of digest algorithm %d: %s\n",
                   hash_algo, gpg_strerror (rc));
      asn = xtrymalloc (asnlen);
      if (!asn)
        return NULL;
      if ( gcry_md_algo_info (hash_algo, GCRYCTL_GET_ASNOID, asn, &asnlen) )
        BUG();
      frame = do_encode_md (md, hash_algo, gcry_md_get_algo_dlen (hash_algo),
                            gcry_mpi_get_nbits (pk->pkey[0]), asn, asnlen);
      xfree (asn);
    }

  return frame;
}
