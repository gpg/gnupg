/* seskey.c -  make sesssion keys etc.
 * Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "cipher.h"
#include "mpi.h"
#include "main.h"
#include "i18n.h"
#include "options.h"

/****************
 * Make a session key and put it into DEK
 */
void
make_session_key( DEK *dek )
{
  gcry_cipher_hd_t chd;
  int i, rc;

  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);

  if (gcry_cipher_open (&chd, dek->algo, GCRY_CIPHER_MODE_CFB,
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
      log_info (_("weak key created - retrying\n") );
      /* Renew the session key until we get a non-weak key. */
      gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM );
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
    int nframe = (nbits+7) / 8;
    byte *p;
    byte *frame;
    int i,n;
    u16 csum;
    gcry_mpi_t a;

    /* the current limitation is that we can only use a session key
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

    frame = gcry_xmalloc_secure ( nframe );
    n = 0;
    frame[n++] = 0;
    frame[n++] = 2;
    i = nframe - 6 - dek->keylen;
    assert( i > 0 );
    p = gcry_random_bytes_secure (i, GCRY_STRONG_RANDOM);
    /* replace zero bytes by new values */
    for(;;) {
	int j, k;
	byte *pp;

	/* count the zero bytes */
	for(j=k=0; j < i; j++ )
	    if( !p[j] )
		k++;
	if( !k )
	    break; /* okay: no zero bytes */
	k += k/128; /* better get some more */
	pp = gcry_random_bytes_secure( k, GCRY_STRONG_RANDOM);
	for(j=0; j < i && k ; j++ )
	    if( !p[j] )
		p[j] = pp[--k];
	xfree (pp);
    }
    memcpy( frame+n, p, i );
    xfree (p);
    n += i;
    frame[n++] = 0;
    frame[n++] = dek->algo;
    memcpy( frame+n, dek->key, dek->keylen ); n += dek->keylen;
    frame[n++] = csum >>8;
    frame[n++] = csum;
    assert (n == nframe);

    if (DBG_CIPHER)
      log_printhex ("encoded session key:", frame, nframe );

    if (gcry_mpi_scan( &a, GCRYMPI_FMT_USG, frame, &nframe))
      BUG();
    xfree (frame);
    return a;
}


static gcry_mpi_t
do_encode_md( gcry_md_hd_t md, int algo, size_t len, unsigned nbits,
	      const byte *asn, size_t asnlen, int v3compathack )
{
    int nframe = (nbits+7) / 8;
    byte *frame;
    int i,n;
    gcry_mpi_t a;

    if( len + asnlen + 4  > nframe )
	log_bug("can't encode a %d bit MD into a %d bits frame\n",
		    (int)(len*8), (int)nbits);

    /* We encode the MD in this way:
     *
     *	   0  A PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
     *
     * PAD consists of FF bytes.
     */
    frame = gcry_md_is_secure (md)? xmalloc_secure (nframe): xmalloc (nframe);
    n = 0;
    frame[n++] = 0;
    frame[n++] = v3compathack? algo : 1; /* block type */
    i = nframe - len - asnlen -3 ;
    assert( i > 1 );
    memset( frame+n, 0xff, i ); n += i;
    frame[n++] = 0;
    memcpy( frame+n, asn, asnlen ); n += asnlen;
    memcpy( frame+n, gcry_md_read (md, algo), len ); n += len;
    assert( n == nframe );
    if (gcry_mpi_scan( &a, GCRYMPI_FMT_USG, frame, &nframe ))
	BUG();
    xfree (frame);
    return a;
}


/****************
 * Encode a message digest into an MPI.
 * v3compathack is used to work around a bug in old GnuPG versions
 * which did put the algo identifier inseatd of the block type 1 into
 * the encoded value.  Setting this flag forces the old behaviour.
 */
gcry_mpi_t
encode_md_value (int pubkey_algo, gcry_md_hd_t md, int hash_algo,
		 unsigned int nbits, int v3compathack )
{
  int algo = hash_algo? hash_algo : gcry_md_get_algo (md);
  gcry_mpi_t frame;
  
  if (pubkey_algo == GCRY_PK_DSA) 
    {
      size_t n = gcry_md_get_algo_dlen(hash_algo);
      if (n != 20)
        {
          log_error (_("DSA requires the use of a 160 bit hash algorithm\n"));
          return NULL;
        }
      if (gcry_mpi_scan( &frame, GCRYMPI_FMT_USG,
                         gcry_md_read (md, hash_algo), &n ) )
        BUG();
    }
  else
    {
      gpg_error_t rc;
      byte *asn;
      size_t asnlen;
      
      rc = gcry_md_algo_info( algo, GCRYCTL_GET_ASNOID, NULL, &asnlen);
      if (rc)
        log_fatal("can't get OID of algo %d: %s\n",
                  algo, gpg_strerror (rc));
      asn = xmalloc (asnlen);
      if( gcry_md_algo_info( algo, GCRYCTL_GET_ASNOID, asn, &asnlen ) )
        BUG();
      frame = do_encode_md( md, algo, gcry_md_get_algo_dlen( algo ),
                            nbits, asn, asnlen, v3compathack );
      xfree (asn);
    }
  return frame;
}






