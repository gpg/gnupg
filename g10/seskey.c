/* seskey.c -  make sesssion keys etc.
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "cipher.h"
#include "mpi.h"
#include "main.h"
#include "i18n.h"


/****************
 * Make a session key and put it into DEK
 */
void
make_session_key( DEK *dek )
{
    CIPHER_HANDLE chd;
    int i, rc;

    dek->keylen = cipher_get_keylen( dek->algo ) / 8;

    chd = cipher_open( dek->algo, CIPHER_MODE_AUTO_CFB, 1 );
    randomize_buffer( dek->key, dek->keylen, 1 );
    for(i=0; i < 16; i++ ) {
	rc = cipher_setkey( chd, dek->key, dek->keylen );
	if( !rc ) {
	    cipher_close( chd );
	    return;
	}
	log_info(_("weak key created - retrying\n") );
	/* Renew the session key until we get a non-weak key. */
	randomize_buffer( dek->key, dek->keylen, 1 );
    }
    log_fatal(_(
	    "cannot avoid weak key for symmetric cipher; tried %d times!\n"),
		  i);
}


/****************
 * Encode the session key. NBITS is the number of bits which should be used
 * for packing the session key.
 * returns: A mpi with the session key (caller must free)
 */
MPI
encode_session_key( DEK *dek, unsigned nbits )
{
    int nframe = (nbits+7) / 8;
    byte *p;
    byte *frame;
    int i,n;
    u16 csum;
    MPI a;

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

    frame = m_alloc_secure( nframe );
    n = 0;
    frame[n++] = 0;
    frame[n++] = 2;
    i = nframe - 6 - dek->keylen;
    assert( i > 0 );
    p = get_random_bits( i*8, 1, 1 );
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
	k += k/128 + 3; /* better get some more */
	pp = get_random_bits( k*8, 1, 1);
	for(j=0; j < i && k ;) {
	    if( !p[j] )
		p[j] = pp[--k];
            if (p[j])
              j++;
        }
	m_free(pp);
    }
    memcpy( frame+n, p, i );
    m_free(p);
    n += i;
    frame[n++] = 0;
    frame[n++] = dek->algo;
    memcpy( frame+n, dek->key, dek->keylen ); n += dek->keylen;
    frame[n++] = csum >>8;
    frame[n++] = csum;
    assert( n == nframe );
    a = mpi_alloc_secure( (nframe+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
    mpi_set_buffer( a, frame, nframe, 0 );
    m_free(frame);
    return a;
}


static MPI
do_encode_md( MD_HANDLE md, int algo, size_t len, unsigned nbits,
	      const byte *asn, size_t asnlen )
{
    int nframe = (nbits+7) / 8;
    byte *frame;
    int i,n;
    MPI a;

    if( len + asnlen + 4  > nframe )
	log_bug("can't encode a %d bit MD into a %d bits frame\n",
		    (int)(len*8), (int)nbits);

    /* We encode the MD in this way:
     *
     *	   0  1 PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
     *
     * PAD consists of FF bytes.
     */
    frame = md_is_secure(md)? m_alloc_secure( nframe ) : m_alloc( nframe );
    n = 0;
    frame[n++] = 0;
    frame[n++] = 1; /* block type */
    i = nframe - len - asnlen -3 ;
    assert( i > 1 );
    memset( frame+n, 0xff, i ); n += i;
    frame[n++] = 0;
    memcpy( frame+n, asn, asnlen ); n += asnlen;
    memcpy( frame+n, md_read(md, algo), len ); n += len;
    assert( n == nframe );
    a = md_is_secure(md)?
	 mpi_alloc_secure( (nframe+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB )
	 : mpi_alloc( (nframe+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
    mpi_set_buffer( a, frame, nframe, 0 );
    m_free(frame);

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
 * v3compathack is used to work around a bug in old GnuPG versions
 * which did put the algo identifier inseatd of the block type 1 into
 * the encoded value.  Setting this flag forces the old behaviour.
 */
MPI
encode_md_value( int pubkey_algo, MD_HANDLE md,
		 int hash_algo, unsigned nbits )
{
    int algo = hash_algo? hash_algo : md_get_algo(md);
    const byte *asn;
    size_t asnlen, mdlen;
    MPI frame;

    if( pubkey_algo == PUBKEY_ALGO_DSA ) {
        mdlen = md_digest_length (hash_algo);
        if (mdlen != 20) {
            log_error (_("DSA requires the use of a 160 bit hash algorithm\n"));
            return NULL;
        }

	frame = md_is_secure(md)? mpi_alloc_secure((md_digest_length(hash_algo)
				 +BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB )
				: mpi_alloc((md_digest_length(hash_algo)
				 +BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB );
	mpi_set_buffer( frame, md_read(md, hash_algo),
			       md_digest_length(hash_algo), 0 );
    }
    else {
       asn = md_asn_oid( algo, &asnlen, &mdlen );
       frame = do_encode_md( md, algo, mdlen, nbits, asn, asnlen );
    }
    return frame;
}
