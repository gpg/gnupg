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
 */


/* The keybox data formats

The KeyBox uses an augmented OpenPGP key format.  This makes random
access to a keyblock easier and also gives the opportunity to store
additional information (e.g. the fingerprint) along with the key.
All integers are stored in network byte order, offsets are counted from
the beginning of the Blob.

The first record of a plain KBX file has a special format:

 u32  length of the first record
 byte Blob type (1)
 byte version number (1)
 byte reserved
 byte reserved
 u32  magic 'KBXf'
 byte marginals  used for validity calculation of this file
 byte completes  ditto.
 byte cert_depth ditto.

The standard KBX Blob looks like this:

 u32  length of this blob (including these 4 bytes)
 byte Blob type (2)
 byte version number of this blob type (1)
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
 u32	Newest timestamp in the keyblock (useful for KS syncronsiation?)
 u32	Blob created at
 u32	size of reserved space (not including this field)
      reserved space

    Here we might want to put other data

    Here comes the keyblock

    maybe we put a signature here later.

 b16	MD5 checksum  (useful for KS syncronisation)
 *
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <gcrypt.h>

#include "iobuf.h"
#include "util.h"
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
    ulong  off_kid_addr;
    u16    flags;
};
struct kbxblob_uid {
    ulong  off_addr;
    u32    len;
    u16    flags;
    byte   validity;
};

struct keyid_list {
    struct keyid_list *next;
    int seqno;
    byte kid[8];
};

struct fixup_list {
    struct fixup_list *next;
    u32 off;
    u32 val;
};


struct kbxblob {
    byte *blob;
    size_t bloblen;

    /* stuff used only by kbx_create_blob */
    int nkeys;
    struct kbxblob_key *keys;
    int nuids;
    struct kbxblob_uid *uids;
    int nsigs;
    u32  *sigs;
    struct fixup_list *fixups;

    struct keyid_list *temp_kids;
    IOBUF buf;	/* the KBX is temporarly stored here */
};

void kbx_release_blob ( KBXBLOB blob );

/* Note: this functions are only used for temportay iobufs and therefore
 * they can't fail */
static void
put8 ( IOBUF out, byte a )
{
    iobuf_put ( out, a );
}

static void
put16 ( IOBUF out, u16 a )
{
    iobuf_put ( out, a>>8 );
    iobuf_put ( out, a );
}

static void
put32 ( IOBUF out, u32 a )
{
    iobuf_put (out, a>> 24);
    iobuf_put (out, a>> 16);
    iobuf_put (out, a>> 8);
    iobuf_put (out, a );
}

static void
putn ( IOBUF out, const byte *p, size_t n )
{
    for ( ; n; p++, n-- ) {
	iobuf_put ( out, *p );
    }
}


/****************
 * We must store the keyid at some place because we can't calculate the
 * offset yet.	This is only used for v3 keyIDs.  Function returns an index
 * value for later fixupd; this must be a non-zero value
 */
static int
temp_store_kid ( KBXBLOB blob, PKT_public_key *pk )
{
    struct keyid_list *k, *r;

    k = gcry_xmalloc ( sizeof *k );
    k->kid[0] = pk->keyid[0] >> 24 ;
    k->kid[1] = pk->keyid[0] >> 16 ;
    k->kid[2] = pk->keyid[0] >>  8 ;
    k->kid[3] = pk->keyid[0]	   ;
    k->kid[4] = pk->keyid[0] >> 24 ;
    k->kid[5] = pk->keyid[0] >> 16 ;
    k->kid[6] = pk->keyid[0] >>  8 ;
    k->kid[7] = pk->keyid[0]	   ;
    k->seqno = 0;
    k->next = blob->temp_kids;
    blob->temp_kids = k;
    for ( r=k; r; r = r->next ) {
	k->seqno++;
    }

    return k->seqno;
}

static void
put_stored_kid( KBXBLOB blob, int seqno )
{
    struct keyid_list *r;

    for ( r = blob->temp_kids; r; r = r->next ) {
	if( r->seqno == seqno ) {
	    putn ( blob->buf, r->kid, 8 );
	    return;
	}
    }
    BUG();
}

static void
release_kid_list ( struct keyid_list *kl )
{
    struct keyid_list *r, *r2;

    for ( r = kl; r; r = r2 ) {
	r2 = r->next;
	gcry_free( r );
    }
}


static int
create_key_part( KBXBLOB blob, KBNODE keyblock )
{
    KBNODE node;
    size_t fprlen;
    int n;

    for ( n=0, node = keyblock; node; node = node->next ) {
	if ( node->pkt->pkttype == PKT_PUBLIC_KEY
	     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    char tmp[20];

	    fingerprint_from_pk( pk, tmp , &fprlen );
	    memcpy(blob->keys[n].fpr,tmp,20);
	    if ( fprlen != 20 ) { /*v3 fpr - shift right and fill with zeroes*/
		assert( fprlen == 16 );
		memmove( blob->keys[n].fpr+4, blob->keys[n].fpr, 16);
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
create_blob_header( KBXBLOB blob )
{
    IOBUF a = blob->buf;
    int i;

    put32 ( a, 0 ); /* blob length, needs fixup */
    put8 ( a, 2 );  /* blob type */
    put8 ( a, 1 );  /* blob type version */
    put16 ( a, 0 ); /* blob flags */

    put32 ( a, 0 ); /* offset to the keyblock, needs fixup */
    put32 ( a, 0 ); /* length of the keyblock, needs fixup */

    put16 ( a, blob->nkeys );
    put16 ( a, 20 + 4 + 2 + 2 );  /* size of key info */
    for ( i=0; i < blob->nkeys; i++ ) {
	putn ( a, blob->keys[i].fpr, 20 );
	blob->keys[i].off_kid_addr = iobuf_get_temp_length (a);
	put32 ( a, 0 ); /* offset to keyid, fixed up later */
	put16 ( a, blob->keys[i].flags );
	put16 ( a, 0 ); /* reserved */
    }

    put16 ( a, blob->nuids );
    put16 ( a, 4 + 4 + 2 + 1 + 1 );  /* size of uid info */
    for ( i=0; i < blob->nuids; i++ ) {
	blob->uids[i].off_addr = iobuf_get_temp_length ( a );
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
    put32 ( a, 0 );  /* newest timestamp (none) */
    put32 ( a, make_timestamp() );  /* creation time */
    put32 ( a, 0 );  /* size of reserved space */
	/* reserved space (which is currently of size 0) */

    /* We need to store the keyids for all v3 keys because those key IDs are
     * not part of the fingerprint.  While we are doing that, we fixup all
     * the keyID offsets */
    for ( i=0; i < blob->nkeys; i++ ) {
	struct fixup_list *fl = gcry_xcalloc(1, sizeof *fl );
	fl->off = blob->keys[i].off_kid_addr;
	fl->next = blob->fixups;
	blob->fixups = fl;

	if ( blob->keys[i].off_kid ) { /* this is a v3 one */
	    fl->val = iobuf_get_temp_length (a);
	    put_stored_kid ( blob, blob->keys[i].off_kid );
	}
	else { /* the better v4 key IDs - just store an offset 8 bytes back */
	    fl->val = blob->keys[i].off_kid_addr-8;
	}
    }


    return 0;
}

static int
create_blob_keyblock( KBXBLOB blob, KBNODE keyblock )
{
    IOBUF a = blob->buf;
    KBNODE node;
    int rc;
    int n;
    u32 kbstart = iobuf_get_temp_length ( a );

    {
	    struct fixup_list *fl = gcry_xcalloc(1, sizeof *fl );
	    fl->off = 8;
	    fl->val = kbstart;
	    fl->next = blob->fixups;
	    blob->fixups = fl;
    }
    for ( n = 0, node = keyblock; node; node = node->next ) {
	rc = build_packet ( a, node->pkt );
	if ( rc ) {
	    gpg_log_error("build_packet(%d) for kbxblob failed: %s\n",
			node->pkt->pkttype, gpg_errstr(rc) );
	    return GPGERR_WRITE_FILE;
	}
	if ( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *u = node->pkt->pkt.user_id;
	    /* build_packet has set the offset of the name into u ;
	     * now we can do the fixup */
	    struct fixup_list *fl = gcry_xcalloc(1, sizeof *fl );
	    fl->off = blob->uids[n].off_addr;
	    fl->val = u->stored_at;
	    fl->next = blob->fixups;
	    blob->fixups = fl;
	    n++;
	}
    }
    assert( n == blob->nuids );
    {
	    struct fixup_list *fl = gcry_xcalloc(1, sizeof *fl );
	    fl->off = 12;
	    fl->val = iobuf_get_temp_length (a) - kbstart;
	    fl->next = blob->fixups;
	    blob->fixups = fl;
    }
    return 0;
}

static int
create_blob_trailer( KBXBLOB blob )
{
    IOBUF a = blob->buf;
    return 0;
}

static int
create_blob_finish( KBXBLOB blob )
{
    IOBUF a = blob->buf;
    byte *p;
    char *pp;
    int i;
    size_t n;

    /* write a placeholder for the checksum */
    for ( i = 0; i < 16; i++ )
	put32( a, 0 );
    /* get the memory area */
    iobuf_flush_temp ( a );
    p = iobuf_get_temp_buffer ( a );
    n = iobuf_get_temp_length ( a );
    assert( n >= 20 );

    /* fixup the length */
    {
	struct fixup_list *fl = gcry_xcalloc(1, sizeof *fl );
	fl->off = 0;
	fl->val = n;
	fl->next = blob->fixups;
	blob->fixups = fl;
    }
    /* do the fixups */
    {
	struct fixup_list *fl;
	for ( fl = blob->fixups; fl; fl = fl->next ) {
	    assert( fl->off+4 <= n );
	    p[fl->off+0] = fl->val >> 24 ;
	    p[fl->off+1] = fl->val >> 16 ;
	    p[fl->off+2] = fl->val >>  8 ;
	    p[fl->off+3] = fl->val	 ;
	}

    }

    /* calculate and store the MD5 checksum */
    gcry_md_hash_buffer( GCRY_MD_MD5, p + n - 16, p, n - 16 );

    pp = gcry_malloc ( n );
    if ( !pp )
	return GCRYERR_NO_MEM;
    memcpy ( pp , p, n );
    blob->blob = pp;
    blob->bloblen = n;

    return 0;
}


int
kbx_create_blob ( KBXBLOB *r_blob,  KBNODE keyblock )
{
    int rc = 0;
    KBNODE node;
    KBXBLOB blob;

    *r_blob = NULL;
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
	  case PKT_SIGNATURE: blob->nsigs++; break;
	  default: break;
	}
    }
    blob->keys = gcry_calloc ( blob->nkeys, sizeof ( *blob->keys ) );
    blob->uids = gcry_calloc ( blob->nuids, sizeof ( *blob->uids ) );
    blob->sigs = gcry_calloc ( blob->nsigs, sizeof ( *blob->sigs ) );
    if ( !blob->keys || !blob->uids || !blob->sigs ) {
	rc = GCRYERR_NO_MEM;
	goto leave;
    }

    rc = create_key_part ( blob, keyblock );
    if( rc )
	goto leave;
    rc = create_uid_part ( blob, keyblock );
    if( rc )
	goto leave;
    rc = create_sig_part ( blob, keyblock );
    if( rc )
	goto leave;

    blob->buf = iobuf_temp();
    rc = create_blob_header ( blob );
    if( rc )
	goto leave;
    rc = create_blob_keyblock ( blob, keyblock );
    if( rc )
	goto leave;
    rc = create_blob_trailer ( blob );
    if( rc )
	goto leave;
    rc = create_blob_finish ( blob );
    if( rc )
	goto leave;


  leave:
    release_kid_list( blob->temp_kids );
    blob->temp_kids = NULL;
    if ( rc ) {
	kbx_release_blob ( blob );
	*r_blob = NULL;
    }
    else  {
	*r_blob = blob;
    }
    return rc;
}

int
kbx_new_blob ( KBXBLOB *r_blob,  char *image, size_t imagelen )
{
    KBXBLOB blob;

    *r_blob = NULL;
    blob = gcry_calloc (1, sizeof *blob );
    if( !blob )
	return GCRYERR_NO_MEM;
    blob->blob = image;
    blob->bloblen = imagelen;
    *r_blob = blob;
    return 0;
}



const char *
kbx_get_blob_image ( KBXBLOB blob, size_t *n )
{
    *n = blob->bloblen;
    return blob->blob;
}

void
kbx_release_blob ( KBXBLOB blob )
{
    if( !blob )
	return;
    if( blob->buf )
	iobuf_cancel( blob->buf );
    gcry_free( blob->keys );
    gcry_free( blob->uids );
    gcry_free( blob->sigs );

    gcry_free ( blob->blob );

    gcry_free( blob );
}

static ulong
get32( const byte *buffer )
{
    ulong a;
    a =  *buffer << 24;
    a |= buffer[1] << 16;
    a |= buffer[2] << 8;
    a |= buffer[3];
    return a;
}

static ulong
get16( const byte *buffer )
{
    ulong a;
    a =  *buffer << 8;
    a |= buffer[1];
    return a;
}


int
kbx_dump_blob ( FILE *fp, KBXBLOB blob	)
{
    const byte *buffer = blob->blob;
    size_t length = blob->bloblen;
    ulong n, nkeys, keyinfolen;
    ulong nuids, uidinfolen;
    ulong nsigs, siginfolen;
    ulong keyblock_off, keyblock_len;
    const byte *p;

    if( length < 40 )  {
	fprintf( fp, "blob too short\n");
	return -1;
    }
    n = get32( buffer );
    if( n > length ) {
	fprintf( fp, "blob larger than length - output truncated\n");
    }
    else
	length = n;  /* ignore the rest */
    fprintf( fp, "Length: %lu\n", n );
    fprintf( fp, "Type:   %d\n", buffer[4] );
    fprintf( fp, "Version: %d\n", buffer[5] );
    if( buffer[4] != 2 ) {
	fprintf( fp, "can't dump this blob type\n" );
	return 0;
    }

    n = get16( buffer + 6 );
    fprintf( fp, "Blob-Flags: %04lX\n", n );
    keyblock_off = get32( buffer + 8 );
    keyblock_len = get32( buffer + 12 );
    fprintf( fp, "Keyblock-Offset: %lu\n", keyblock_off );
    fprintf( fp, "Keyblock-Length: %lu\n", keyblock_len );

    nkeys = get16( buffer + 16 );
    fprintf( fp, "Key-Count: %lu\n", nkeys );
    keyinfolen = get16( buffer + 18 );
    fprintf( fp, "Key-Info-Length: %lu\n", keyinfolen );
    /* fixme: check bounds */
    p = buffer + 20;
    for(n=0; n < nkeys; n++, p += keyinfolen ) {
	int i;
	ulong kidoff, kflags;

	fprintf( fp, "Key-%lu-Fpr: ", n );
	for(i=0; i < 20; i++ )
	    fprintf( fp, "%02X", p[i] );
	kidoff = get32( p + 20 );
	fprintf( fp, "\nKey-%lu-Kid-Off: %lu\n", n, kidoff );
	fprintf( fp, "Key-%lu-Kid: ", n );
	/* fixme: check bounds */
	for(i=0; i < 8; i++ )
	    fprintf( fp, "%02X", buffer[kidoff+i] );
	kflags = get16( p + 24 );
	fprintf( fp, "\nKey-%lu-Flags: %04lX\n", n, kflags );
    }


    nuids = get16( p );
    fprintf( fp, "Uid-Count: %lu\n", nuids );
    uidinfolen = get16( p + 2 );
    fprintf( fp, "Uid-Info-Length: %lu\n", uidinfolen );
    /* fixme: check bounds */
    p += 4;
    for(n=0; n < nuids; n++, p += uidinfolen ) {
	ulong uidoff, uidlen, uflags;

	uidoff = get32( p );
	uidlen = get32( p+4 );
	fprintf( fp, "Uid-%lu-Off: %lu\n", n, uidoff );
	fprintf( fp, "Uid-%lu-Len: %lu\n", n, uidlen );
	fprintf( fp, "Uid-%lu: \"", n );
	print_string( fp, buffer+uidoff, uidlen, '\"' );
	fputs("\"\n", fp );
	uflags = get16( p + 8 );
	fprintf( fp, "Uid-%lu-Flags: %04lX\n", n, uflags );
	fprintf( fp, "Uid-%lu-Validity: %d\n", n, p[10] );
    }

    nsigs = get16( p );
    fprintf( fp, "Sig-Count: %lu\n", nsigs );
    siginfolen = get16( p + 2 );
    fprintf( fp, "Sig-Info-Length: %lu\n", siginfolen );
    /* fixme: check bounds  */
    p += 4;
    for(n=0; n < nsigs; n++, p += siginfolen ) {
	ulong sflags;

	sflags = get32( p );
	fprintf( fp, "Sig-%lu-Expire: ", n );
	if( !sflags )
	    fputs( "[not checked]", fp );
	else if( sflags == 1 )
	    fputs( "[missing key]", fp );
	else if( sflags == 2 )
	    fputs( "[bad signature]", fp );
	else if( sflags < 0x10000000 )
	    fprintf( fp, "[bad flag %0lx]", sflags );
	else if( sflags == 0xffffffff )
	    fputs( "0", fp );
	else
	    fputs( strtimestamp( sflags ), fp );
	putc('\n', fp );
    }

    fprintf( fp, "Ownertrust: %d\n", p[0] );
    fprintf( fp, "All-Validity: %d\n", p[1] );
    p += 4;
    n = get32( p ); p += 4;
    fprintf( fp, "Recheck-After: %s\n", n? strtimestamp(n) : "0" );
    n = get32( p ); p += 4;
    fprintf( fp, "Latest-Timestamp: %s\n", strtimestamp(n) );
    n = get32( p ); p += 4;
    fprintf( fp, "Created-At: %s\n", strtimestamp(n) );
    n = get32( p ); p += 4;
    fprintf( fp, "Reserved-Space: %lu\n", n );


    /* check that the keyblock is at the correct offset and other bounds */


    fprintf( fp, "Blob-Checksum: [MD5-hash]\n" );
    return 0;
}

/****************
 * Check whether the given fingerprint (20 bytes) is in the
 * given keyblob.  fpr is always 20 bytes.
 * Return: 0 = found
 *	   -1 = not found
	  other = error  (fixme: do not always reurn gpgerr_general)
 */
int
kbx_blob_has_fpr ( KBXBLOB blob, const byte *fpr )
{
    ulong n, nkeys, keyinfolen;
    const byte *p, *pend;
    byte *buffer = blob->blob;
    size_t buflen = blob->bloblen;

    if ( buflen < 40 )
	return GPGERR_GENERAL; /* blob too short */
    n = get32( buffer );
    if ( n > buflen )
	return GPGERR_GENERAL; /* blob larger than announced length */
    buflen = n;  /* ignore trailing stuff */
    pend = buffer + n - 1;

    if ( buffer[4] != 2 )
	return GPGERR_GENERAL; /* invalid blob type */
    if ( buffer[5] != 1 )
	return GPGERR_GENERAL; /* invalid blob format version */

    nkeys = get16( buffer + 16 );
    keyinfolen = get16( buffer + 18 );
    p = buffer + 20;
    for(n=0; n < nkeys; n++, p += keyinfolen ) {
	if ( p+20 > pend )
	    return GPGERR_GENERAL; /* blob shorter than required */
	if (!memcmp ( p, fpr, 20 ) )
	    return 0; /* found */
    }
    return -1;
}

/****************
 * Check whether the given keyID (20 bytes) is in the
 * given keyblob.
 * Return: 0 = found
 *	   -1 = not found
	  other = error  (fixme: do not always return gpgerr_general)
 */
int
kbx_blob_has_kid ( KBXBLOB blob, const byte *keyidbuf, size_t keyidlen )
{
    ulong n, nkeys, keyinfolen, off;
    const byte *p, *pend;
    byte *buffer = blob->blob;
    size_t buflen = blob->bloblen;

    if ( buflen < 40 )
	return GPGERR_GENERAL; /* blob too short */
    n = get32( buffer );
    if ( n > buflen )
	return GPGERR_GENERAL; /* blob larger than announced length */
    buflen = n;  /* ignore trailing stuff */
    pend = buffer + n - 1;

    if ( buffer[4] != 2 )
	return GPGERR_GENERAL; /* invalid blob type */
    if ( buffer[5] != 1 )
	return GPGERR_GENERAL; /* invalid blob format version */

    nkeys = get16( buffer + 16 );
    keyinfolen = get16( buffer + 18 );
    p = buffer + 20;
    for(n=0; n < nkeys; n++, p += keyinfolen ) {
	if ( p+24 > pend )
	    return GPGERR_GENERAL; /* blob shorter than required */
	off = get32 ( p + 20 );
	if (keyidlen < 8 ) /* actually keyidlen may either be 4 or 8 */
	    off +=4;
	if ( off+keyidlen > buflen )
	    return GPGERR_GENERAL; /* offset out of bounds */
	if ( !memcmp ( buffer+off, keyidbuf, keyidlen ) )
	    return 0; /* found */
    }
    return -1;
}



int
kbx_blob_has_uid ( KBXBLOB blob,
		   int (*cmp)(const byte *, size_t, void *), void *opaque )
{
    ulong n, nuids, uidinfolen, off, len;
    const byte *p, *pend;
    byte *buffer = blob->blob;
    size_t buflen = blob->bloblen;

    if ( buflen < 40 )
	return GPGERR_GENERAL; /* blob too short */
    n = get32( buffer );
    if ( n > buflen )
	return GPGERR_GENERAL; /* blob larger than announced length */
    buflen = n;  /* ignore trailing stuff */
    pend = buffer + n - 1;

    if ( buffer[4] != 2 )
	return GPGERR_GENERAL; /* invalid blob type */
    if ( buffer[5] != 1 )
	return GPGERR_GENERAL; /* invalid blob format version */

    p = buffer + 20 + get16( buffer + 16 ) * get16( buffer + 18 );
    if ( p+4 > pend )
	return GPGERR_GENERAL; /* blob shorter than required */

    nuids = get16( p ); p+= 2;
    uidinfolen = get16( p ); p+=2;
    for(n=0; n < nuids; n++, p += uidinfolen ) {
	if ( p+8 > pend )
	    return GPGERR_GENERAL; /* blob shorter than required */
	off = get32 ( p );
	len = get32 ( p + 4 );
	if ( off+len > buflen )
	    return GPGERR_GENERAL; /* offset out of bounds */
	if ( (*cmp) ( buffer+off, len, opaque ) )
	    return 0; /* found */
    }

    return -1;
}


