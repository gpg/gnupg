/* kbxblob.c - KBX Blob handling
 *	Copyright (C) 2000 Free Software Foundation, Inc.
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
 *
 ***********************************************
 * adler_cksum() is based on the zlib code with these conditions:
 *
 *	Copyright (C) 1995-1998 Mark Adler
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */


/* The keybox data formats

The KeyBox uses an augmented OpenPGP key format.  This makes random
access to a keyblock easier and also gives the opportunity to store
additional information (e.g. the fingerprint) along with the key.
All integers are stored in network byte order, offsets are counted from
the beginning of the Blob.

The first record of a plain KBX file has a special format:

 u32  length of the first record
 u32  magic 'KBXf'
 byte version number (1)
 b[3] reserved
 byte marginals  used for validity calculation of this file
 byte completes  ditto.
 byte cert_depth ditto.

The standard KBX Blob looks like this:

 u32  length of this blob (including these 4 bytes)
 byte version number (1)
 byte reserved
 u16  Blob flags
	bit 0 = contains secret key material

 u32  offset to the OpenPGP keyblock
 u32  length of the keyblock
 u16  number of keys (at least 1!)
 u16  size of additional key information
 n times:
   b20	The keys fingerprint
	(fingerprints are always 20 bytes, MD5 left padded with zeroes)
   u32	offset to the n-th key's keyID (a keyID is always 8 byte)
   u16	special key flags
	 bit 0 =
   u16	reserved
 u16  number of user IDs
 u16  size of additional user ID information
 n times:
   u32	offset to the n-th user ID
   u32	length of this user ID.
   u16	special user ID flags.
	 bit 0 =
   byte validity
   byte reserved
 u16  number of signatures
 u16  size of signature information (4)
   u32	expiration time of signature with some special values:
	0x00000000 = not checked
	0x00000001 = missing key
	0x00000002 = bad signature
	0x10000000 = valid and expires at some date in 1978.
	0xffffffff = valid and does not expire
 u8	assigned ownertrust
 u8	all_validity
 u16	reserved
 u32	recheck_after
 u32	size of reserved space (not including this field)
      reserved space

    Here we might want to put other data

    Here comes the keyblock

    maybe we put a sigture here later.

 u32	adler checksum
 *
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <gcrypt.h>

#include "kbx.h"

/* special values of the signature status */
#define SF_NONE(a)  ( !(a) )
#define SF_NOKEY(a) ((a) & (1<<0))
#define SF_BAD(a)   ((a) & (1<<1))
#define SF_VALID(a) ((a) & (1<<29))

#if MAX_FINGERPRINT_LEN < 20
  #error fingerprints are 20 bytes
#endif

struct kbxblob_key {
    char   fpr[20];
    u32    off_kid;
    ulong  off_kid_addr; /* where it is stored in the datablock */
    u16    flags;
};
struct kbxblob_uid {
    u32    off;
    ulong  off_addr; /* where it is stored in the datablock */
    u32    len;
    u16    flags;
    byte   validity
};

struct keyid_list {
    struct keyid_list *next;
    int seqno;
    char kid[8];
}

struct kbxblob {
    int nkeys;
    struct kbxblob_key *keys;
    int nuids;
    struct kbxblob_uid *uids;
    int nsigs;
    u32  *sigs;

    struct keyid_list *temp_kids;
} *KBXBLOB;


static u32
adler_cksum ( const byte *buf, size_t len )
{
    unsigned long s1 = 1;
    unsigned long s2 = 0;

  #define X_BASE 65521L /* largest prime smaller than 65536 */
  #define X_NMAX 5552	/* largest n such that			 */
			    /* 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */
  #define X_DO1(buf,i)	{s1 += buf[i]; s2 += s1;}
  #define X_DO2(buf,i)	X_DO1(buf,i); X_DO1(buf,i+1);
  #define X_DO4(buf,i)	X_DO2(buf,i); X_DO2(buf,i+2);
  #define X_DO8(buf,i)	X_DO4(buf,i); X_DO4(buf,i+4);
  #define X_DO16(buf)	X_DO8(buf,0); X_DO8(buf,8);
    while ( len  ) {
	int k = len < NMAX ? len : NMAX;
	len -= k;
	while ( k >= 16 ) {
	    DO16(buf);
	    buf += 16;
	    k -= 16;
	}
	if ( k ) {
	      do {
		s1 += *buf++;
		s2 += s1;
	    } while ( --k );
	}
	s1 %= BASE;
	s2 %= BASE;
    }
  #undef X_BASE
  #undef X_NMAX
  #undef X_DO1
  #undef X_DO2
  #undef X_DO4
  #undef X_DO8
  #undef X_DO16
    return ( s2 << 16 ) | s1;
}


/* Note: this functions are only used for temportay iobufs and therefore
 * they can't fail */
static void
put8 ( IOBUF out, byte a )
{
    iobuf_put ( out, a )
}

static void
put16 ( IOBUF out, u16 a )
{
    iobuf_put ( out, a>>8 );
    iobuf_put ( out, a )
}

static void
put32 ( IOBUF out, u32 a )
{
    iobuf_put (out, a>> 24);
    iobuf_put (out, a>> 16);
    iobuf_put (out, a>> 8);
    iobuf_put (out, a) )
}

static void
putn ( IOBUF out, const byte *p, size_t n )
{
    for ( ; n; p++, n-- ) {
	iobuf_put ( out, *p );
    }
}

/****************
 * special version of put 32, which is used to fixup a value at file offset OFF
 */
static void
put32at ( IOBUF out, u32 a, size_t pos )
{
    size_t n;
    byte *p,

    iobuf_flush_temp ( out );
    p = iobuf_get_temp_buffer( out );
    n = iobuf_get_temp_length( out );
    assert( n >= pos+4 );
    p[0] = a >> 24 ;
    p[1] = a >> 16 ;
    p[2] = a >>  8 ;
    p[3] = a	   ;
}


/****************
 * We must store the keyid at some place becuase we can't calculate the
 * offset yet.	This is only used for v3 keyIDs.  Function returns an index
 * value for later fixupd; this must be a non-zero value
 */
static int
temp_store_kid ( KBXBLOB blob, PKT_public_key *pk )
{
    struct keyid_list *k, *r;

    k = gcry_xmalloc ( sizeof *k );
    k->kid = pk->keyid;
    k->seqno = 0;
    k->next = blob->temp_kids;
    blob->temp_kids = k;
    for ( r=k; r; r = r->next ) {
	k->seqno++
    }

    return k->seqno;
}

static void
put_stored_kid( IOBUF a, KBXBLOB blob, int seqno )
{
    struct keyid_list *r;

    for ( r = blob->temp_kids; r; r = r->next ) {
	if( r->seqno == seqno ) {
	    putn ( a, r->kid, 8 );
	    return;
	}
    }
    BUG();
}

static int
release_kid_list ( struct keyid_list *kl )
{
    struct keyid_list *r, *r2;

    for ( r = blob->temp_kids; r; r = r2 ) {
	r2 = r->next;
	gcry_free( r );
    }
}


static int
create_key_part( KBXBLOB blob, KBNODE keyblock )
{
    KBNODE node;
    byte fpr[MAX_FINGERPRINT_LEN];
    size_t fprlen;
    int n;

    for ( n=0, node = keyblock; node; node = node->next ) {
	if ( node->pkt->pkttype == PKT_PUBLIC_KEY:
	     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;

	    fingerprint_from_pk( pk, blob->keys[n].fpr, &fprlen );
	    if ( fprlen != 20 ) { /*v3 fpr - shift right and fill with zeroes*/
		assert( fprlen == 16 );
		memmove( blob->keys[n]+4, blob->keys[n].fpr, 16);
		memset( blob->keys[n].fpr, 0, 4 );
		blob->keys[n].off_kid = temp_store_kid( blob, pk );
	    }
	    else {
		blob->keys[n].off_kid = 0; /* will be fixed up later */
	    }
	    blob->keys[n].flags = 0;
	    n++;
	}
	else if ( node->pkt->pkttype == PKT_SECRET_KEY
		  || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    BUG(); /* not yet implemented */
	}
    }
    assert( n == blob->nkeys );
    return 0;
}

static int
create_uid_part( KBXBLOB blob, KBNODE keyblock )
{
    KBNODE node;
    int n;

    for ( n=0, node = keyblock; node; node = node->next ) {
	if ( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *u = node->pkt->pkt.user_id;

	    blob->uids[n].off	= 0;  /* must calculate this later */
	    blob->uids[n].len	= u->len;
	    blob->uids[n].flags = 0;
	    blob->uids[n].validity = 0;
	    n++;
	}
    }
    assert( n == blob->nuids );
    return 0;
}

static int
create_sig_part( KBXBLOB blob, KBNODE keyblock )
{
    KBNODE node;
    int n;

    for ( n=0, node = keyblock; node; node = node->next ) {
	if ( node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    blob->sigs[n] = 0;	/* FIXME: check the signature here */
	    n++;
	}
    }
    assert( n == blob->nsigs );
    return 0;
}


static int
create_blob_header( IOBUF a, KBXBLOB blob )
{
    int i;

    put32 ( a, 0 ); /* blob length, needs fixup */
    put8 ( a, 1 );  /* version number */
    put8 ( a, 0 );  /* reserved */
    put16 ( a, 0 ); /* blob flags */

    put32 ( a, 0 ); /* offset to the keyblock, needs fixup */
    put32 ( a, 0 ); /* length of the keyblock, needs fixup */

    put16 ( a, blob->nkeys );
    put16 ( a, 20 + 8 + 2 + 2 );  /* size of key info */
    for ( i=0; i < blob->nkeys; i++ ) {
	putn ( a, blob->keys[i].fpr, 20 );
	blob->keys[i].off_kid_addr = iobuf_tell ( out );
	put32 ( a, 0 ); /* offset to keyid, fixed up later */
	put16 ( a, blob->keys[i].flags );
	put16 ( a, 0 ); /* reserved */
    }

    put16 ( a, blob->nuids );
    put16 ( a, 4 + 4 + 2 + 1 + 1 );  /* size of uid info */
    for ( i=0; i < blob->nuids; i++ ) {
	blob->uids[i].off_addr = iobuf_tell ( out );
	put32 ( a, 0 ); /* offset to userid, fixed up later */
	put32 ( a, blob->uids[i].len );
	put16 ( a, blob->uids[i].flags );
	put8  ( a, 0 ); /* validity */
	put8  ( a, 0 ); /* reserved */
    }

    put16 ( a, blob->nsigs );
    put16 ( a, 4 );  /* size of sig info */
    for ( i=0; i < blob->nsigs; i++ ) {
	put32 ( a, blob->sigs[i] );
    }

    put8 ( a, 0 );  /* assigned ownertrust */
    put8 ( a, 0 );  /* validity of all user IDs */
    put16 ( a, 0 );  /* reserved */
    put32 ( a, 0 );  /* time of next recheck */
    put32 ( a, 0 );  /* size of reserved space */
	/* reserved space (which is currently 0) */

    /* We need to store the keyids for all v3 keys because those key IDs are
     * not part of the fingerprint.  While we are doing that, we fixup all
     * the keyID offsets */
    for ( i=0; i < blob->nkeys; i++ ) {
	if ( blob->keys[i].off_kid ) { /* this is a v3 one */
	    put32at ( a, iobuf_tell(), blob->keys[i].off_kid_addr );
	    put_stored_kid ( a, blob, blob->keys[i].off_kid );
	}
	else { /* the better v4 key IDs - just store an offset 8 bytes back */
	    put32at ( a, blob->keys[i].off_kid_addr-8,
				    blob->keys[i].off_kid_addr );
	}
    }


    return 0;
}

static int
create_blob_keyblock( IOBUF a, KBXBLOB blob, KBNODE keyblock )
{
    KBNODE node;
    int rc;

    for ( node = keyblock; node; node = node->next ) {
	/* we must get some offset into thge keyblock and do some
	 * fixups */
	rc = build_packet ( fp, node->pkt );
	if ( rc ) {
	    log_error("build_packet(%d) for kbxblob failed: %s\n",
			node->pkt->pkttype, gpg_errstr(rc) );
	    return GPGERR_WRITE_FILE;
	}
    }
    return 0;
}

static int
create_blob_trailer( IOBUF a, KBXBLOB blob )
{
    return 0;
}

static int
create_blob_finish( IOBUF a, KBXBLOB blob )
{


    /* fixup the length */
    /* optionally we could sign the whole stuff at this point */
    /* write the checksum */
    return 0;
}


int
kbx_create_blob ( KBXBLOB *retkbx, KBNODE keyblock )
{
    int rc = 0;
    KBNODE node;
    struct kbxblob *blob;
    int nkey, nuid, nsig;
    IOBUF a = NULL;

    *retkbx = NULL;
    blob = gcry_calloc (1, sizeof *blob );
    if( !blob )
	return GCRYERR_NO_MEM;

    /* fixme: Do some sanity checks on the keyblock */

    /* count userids and keys so that we can allocate the arrays */
    for ( node = keyblock; node; node = node->next ) {
	switch ( node->pkt->pkttype ) {
	  case PKT_PUBLIC_KEY:
	  case PKT_SECRET_KEY:
	  case PKT_PUBLIC_SUBKEY:
	  case PKT_SECRET_SUBKEY: blob->nkeys++; break;
	  case PKT_USER_ID:  blob->nuids++; break;
	  case PKT_SIGNATURE: blob->nsigs++, break;
	}
    }
    blob->nkeys = gcry_calloc ( blob->nkeys, sizeof ( blob->keys ) );
    blob->nuids = gcry_calloc ( blob->nuids, sizeof ( blob->uids ) );
    blob->nsigs = gcry_calloc ( blob->nsigs, sizeof ( blob->sigs ) );
    if ( !blob->nkeys || !blob->nuids || !blob->nsigs ) {
	rc = GCRYERR_NO_MEM;
	goto leave;
    }

    rc = create_key_part ( blob, keyblock ),
    if( rc )
	goto leave;
    rc = create_uid_part ( blob, keyblock ),
    if( rc )
	goto leave;
    rc = create_sig_part ( blob, keyblock ),
    if( rc )
	goto leave;

    a = iobuf_temp();
    rc = create_blob_header ( a, blob );
    if( rc )
	goto leave;
    rc = create_blob_keyblock ( a, blob, keyblock );
    if( rc )
	goto leave;
    rc = create_blob_trailer ( a, blob );
    if( rc )
	goto leave;
    rc = create_blob_finish ( a, blob );
    if( rc )
	goto leave;

    /* now we take the iobuf and copy it to the output */

    *retkbx = blob;

  failure:
    if( a )
	iobuf_cancel( a );
    release_kid_list( blob->temp_kids );
    if ( rc ) {
	gcry_free( blob->nkeys );
	gcry_free( blob->nuids );
	gcry_free( blob->nsigs );
	gcry_free( blob );
    }
    return rc;
}


