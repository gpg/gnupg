/* seskey.c -  make sesssion keys etc.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2006, 2009 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "cipher.h"
#include "main.h"
#include "i18n.h"


/****************
 * Make a session key and put it into DEK
 */
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


/****************
 * Encode the session key. NBITS is the number of bits which should be used
 * for packing the session key.
 * returns: A mpi with the session key (caller must free)
 */
gcry_mpi_t
encode_session_key (DEK *dek, unsigned int nbits)
{
    size_t nframe = (nbits+7) / 8;
    byte *p;
    byte *frame;
    int i,n;
    u16 csum;
    gcry_mpi_t a;

    /* The current limitation is that we can only use a session key
     * whose length is a multiple of BITS_PER_MPI_LIMB
     * I think we can live with that.
     */
    if( dek->keylen + 7 > nframe || !nframe )
	log_bug("can't encode a %d bit key in a %d bits frame\n",
		    dek->keylen*8, nbits );

    /* We encode the session key in this way:
     *
     *	   0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
     *
     * (But how can we store the leading 0 - the external representaion
     *	of MPIs doesn't allow leading zeroes =:-)
     *
     * RND are non-zero random bytes.
     * A   is the cipher algorithm
     * DEK is the encryption key (session key) length k depends on the
     *	   cipher algorithm (20 is used with blowfish160).
     * CSUM is the 16 bit checksum over the DEK
     */
    csum = 0;
    for( p = dek->key, i=0; i < dek->keylen; i++ )
	csum += *p++;

    frame = xmalloc_secure( nframe );
    n = 0;
    frame[n++] = 0;
    frame[n++] = 2;
    i = nframe - 6 - dek->keylen;
    assert( i > 0 );
    p = gcry_random_bytes_secure (i, GCRY_STRONG_RANDOM);
    /* Replace zero bytes by new values. */
    for(;;) {
	int j, k;
	byte *pp;

	/* count the zero bytes */
	for(j=k=0; j < i; j++ )
	    if( !p[j] )
		k++;
	if( !k )
	    break; /* okay: no zero bytes */
	k += k/128 + 3; /* better get some more */
	pp = gcry_random_bytes_secure (k, GCRY_STRONG_RANDOM);
	for(j=0; j < i && k ;) {
	    if( !p[j] )
		p[j] = pp[--k];
            if (p[j])
              j++;
        }
	xfree(pp);
    }
    memcpy( frame+n, p, i );
    xfree(p);
    n += i;
    frame[n++] = 0;
    frame[n++] = dek->algo;
    memcpy( frame+n, dek->key, dek->keylen ); n += dek->keylen;
    frame[n++] = csum >>8;
    frame[n++] = csum;
    assert( n == nframe );
    if (gcry_mpi_scan( &a, GCRYMPI_FMT_USG, frame, n, &nframe))
      BUG();
    xfree(frame);
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

    if( len + asnlen + 4  > nframe )
	log_bug("can't encode a %d bit MD into a %d bits frame\n",
		    (int)(len*8), (int)nbits);

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
    assert( i > 1 );
    memset( frame+n, 0xff, i ); n += i;
    frame[n++] = 0;
    memcpy( frame+n, asn, asnlen ); n += asnlen;
    memcpy( frame+n, gcry_md_read (md, algo), len ); n += len;
    assert( n == nframe );

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
encode_md_value (PKT_public_key *pk, PKT_secret_key *sk,
		 gcry_md_hd_t md, int hash_algo)
{
  gcry_mpi_t frame;

  assert(hash_algo);
  assert(pk || sk);

  if((pk?pk->pubkey_algo:sk->pubkey_algo) == GCRY_PK_DSA)
    {
      /* It's a DSA signature, so find out the size of q. */

      size_t qbytes = gcry_mpi_get_nbits (pk?pk->pkey[1]:sk->skey[1]);

      /* Make sure it is a multiple of 8 bits. */

      if(qbytes%8)
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
      if (qbytes < 160)
	{
	  log_error (_("DSA key %s uses an unsafe (%u bit) hash\n"),
                     pk?keystr_from_pk(pk):keystr_from_sk(sk),
                     (unsigned int)qbytes);
	  return NULL;
	}

      qbytes/=8;

      /* Check if we're too short.  Too long is safe as we'll
	 automatically left-truncate. */
      if (gcry_md_get_algo_dlen (hash_algo) < qbytes)
	{
	  log_error (_("DSA key %s requires a %u bit or larger hash\n"),
                     pk?keystr_from_pk(pk):keystr_from_sk(sk),
                     (unsigned int)(qbytes*8));
	  return NULL;
	}

      if (gcry_mpi_scan (&frame, GCRYMPI_FMT_USG,
                         gcry_md_read (md, hash_algo), qbytes, &qbytes))
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
      asn = xmalloc (asnlen);
      if ( gcry_md_algo_info (hash_algo, GCRYCTL_GET_ASNOID, asn, &asnlen) )
        BUG();
      frame = do_encode_md (md, hash_algo, gcry_md_get_algo_dlen (hash_algo),
                            gcry_mpi_get_nbits (pk?pk->pkey[0]:sk->skey[0]),
                            asn, asnlen);
      xfree (asn);
    }

  return frame;
}
