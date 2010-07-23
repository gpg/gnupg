/* keybox-blob.c - KBX Blob handling
 * Copyright (C) 2000, 2001, 2002, 2003, 2008 Free Software Foundation, Inc.
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


/* The keybox data formats

The KeyBox uses an augmented OpenPGP/X.509 key format.  This makes
random access to a keyblock/certificate easier and also gives the
opportunity to store additional information (e.g. the fingerprint)
along with the key.  All integers are stored in network byte order,
offsets are counted from the beginning of the Blob.

The first record of a plain KBX file has a special format:

 u32  length of the first record
 byte Blob type (1)
 byte version number (1)
 byte reserved
 byte reserved
 u32  magic 'KBXf'
 u32  reserved
 u32  file_created_at
 u32  last_maintenance_run
 u32  reserved
 u32  reserved

The OpenPGP and X.509 blob are very similiar, things which are
X.509 specific are noted like [X.509: xxx]

 u32  length of this blob (including these 4 bytes)
 byte Blob type (2) [X509: 3]
 byte version number of this blob type (1)
 u16  Blob flags
	bit 0 = contains secret key material
        bit 1 = ephemeral blob (e.g. used while quering external resources)

 u32  offset to the OpenPGP keyblock or X509 DER encoded certificate
 u32  and its length
 u16  number of keys (at least 1!) [X509: always 1]
 u16  size of additional key information
 n times:
   b20	The keys fingerprint
	(fingerprints are always 20 bytes, MD5 left padded with zeroes)
   u32	offset to the n-th key's keyID (a keyID is always 8 byte)
        or 0 if not known which is the case only for X509.
   u16	special key flags
	 bit 0 = qualified signature (not yet implemented}
   u16	reserved
 u16  size of serialnumber(may be zero) 
   n  u16 (see above) bytes of serial number
 u16  number of user IDs
 u16  size of additional user ID information
 n times:
   u32	offset to the n-th user ID
   u32	length of this user ID.
   u16	special user ID flags.
	 bit 0 =
   byte validity
   byte reserved
   [For X509, the first user ID is the Issuer, the second the Subject
   and the others are subjectAltNames]
 u16  number of signatures
 u16  size of signature information (4)
   u32	expiration time of signature with some special values:
	0x00000000 = not checked
	0x00000001 = missing key
	0x00000002 = bad signature
	0x10000000 = valid and expires at some date in 1978.
	0xffffffff = valid and does not expire
 u8	assigned ownertrust [X509: not used]
 u8	all_validity 
           OpenPGP:  see ../g10/trustdb/TRUST_* [not yet used]
           X509: Bit 4 set := key has been revoked.  Note that this value
                              matches TRUST_FLAG_REVOKED
 u16	reserved
 u32	recheck_after
 u32	Newest timestamp in the keyblock (useful for KS syncronsiation?)
 u32	Blob created at
 u32	size of reserved space (not including this field)
      reserved space

    Here we might want to put other data

    Here comes the keyblock

    maybe we put a signature here later.

 b16	MD5 checksum  (useful for KS syncronisation), we might also want to use
    a mac here.
 b4    reserved

*/


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include "keybox-defs.h"
#include <gcrypt.h>

#ifdef KEYBOX_WITH_OPENPGP
/* include stuff to parse the packets */
#endif
#ifdef KEYBOX_WITH_X509
#include <ksba.h>
#endif



/* special values of the signature status */
#define SF_NONE(a)  ( !(a) )
#define SF_NOKEY(a) ((a) & (1<<0))
#define SF_BAD(a)   ((a) & (1<<1))
#define SF_VALID(a) ((a) & (1<<29))


struct membuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};


/*  #if MAX_FINGERPRINT_LEN < 20 */
/*    #error fingerprints are 20 bytes */
/*  #endif */

struct keyboxblob_key {
  char   fpr[20];
  u32    off_kid;
  ulong  off_kid_addr;
  u16    flags;
};
struct keyboxblob_uid {
  ulong  off_addr;
  char   *name;     /* used only with x509 */
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


struct keyboxblob {
  byte *blob;
  size_t bloblen;
  off_t fileoffset;
  
  /* stuff used only by keybox_create_blob */
  unsigned char *serialbuf;
  const unsigned char *serial;
  size_t seriallen;
  int nkeys;
  struct keyboxblob_key *keys;
  int nuids;
  struct keyboxblob_uid *uids;
  int nsigs;
  u32  *sigs;
  struct fixup_list *fixups;
  int fixup_out_of_core;
  
  struct keyid_list *temp_kids;
  struct membuf bufbuf; /* temporary store for the blob */
  struct membuf *buf; 
};



/* A simple implemention of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  */

static void
init_membuf (struct membuf *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = xtrymalloc (initiallen);
  if (!mb->buf)
      mb->out_of_core = 1;
}

static void
put_membuf (struct membuf *mb, const void *buf, size_t len)
{
  if (mb->out_of_core)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;
      
      mb->size += len + 1024;
      p = xtryrealloc (mb->buf, mb->size);
      if (!p)
        {
          mb->out_of_core = 1;
          return;
        }
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}

static void *
get_membuf (struct membuf *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      xfree (mb->buf);
      mb->buf = NULL;
      return NULL;
    }

  p = mb->buf;
  *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = 1; /* don't allow a reuse */
  return p;
}


static void
put8 (struct membuf *mb, byte a )
{
  put_membuf (mb, &a, 1);
}

static void
put16 (struct membuf *mb, u16 a )
{
  unsigned char tmp[2];
  tmp[0] = a>>8;
  tmp[1] = a;
  put_membuf (mb, tmp, 2);
}

static void
put32 (struct membuf *mb, u32 a )
{
  unsigned char tmp[4];
  tmp[0] = a>>24;
  tmp[1] = a>>16;
  tmp[2] = a>>8;
  tmp[3] = a;
  put_membuf (mb, tmp, 4);
}


/* Store a value in the fixup list */
static void
add_fixup (KEYBOXBLOB blob, u32 off, u32 val)
{
  struct fixup_list *fl;
  
  if (blob->fixup_out_of_core)
    return;

  fl = xtrycalloc(1, sizeof *fl);
  if (!fl)
    blob->fixup_out_of_core = 1;
  else 
    {
      fl->off = off;
      fl->val = val;
      fl->next = blob->fixups;
      blob->fixups = fl;
    }
}


/*
 Some wrappers
*/

static u32
make_timestamp (void)
{
  return time(NULL);
}



#ifdef KEYBOX_WITH_OPENPGP
/*
  OpenPGP specific stuff 
*/


/*
  We must store the keyid at some place because we can't calculate the
  offset yet. This is only used for v3 keyIDs.  Function returns an
  index value for later fixup or -1 for out of core. The value must be
  a non-zero value */
static int
pgp_temp_store_kid (KEYBOXBLOB blob, PKT_public_key *pk)
{
  struct keyid_list *k, *r;
  
  k = xtrymalloc (sizeof *k); 
  if (!k)
    return -1;
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
  for (r=k; r; r = r->next) 
    k->seqno++;
  
  return k->seqno;
}

static int
pgp_create_key_part (KEYBOXBLOB blob, KBNODE keyblock)
{
  KBNODE node;
  size_t fprlen;
  int n;

  for (n=0, node = keyblock; node; node = node->next)
    {
      if ( node->pkt->pkttype == PKT_PUBLIC_KEY
           || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) 
        {
          PKT_public_key *pk = node->pkt->pkt.public_key;
          char tmp[20];

          fingerprint_from_pk (pk, tmp , &fprlen);
          memcpy (blob->keys[n].fpr, tmp, 20);
          if ( fprlen != 20 ) /*v3 fpr - shift right and fill with zeroes*/
            {
              assert (fprlen == 16);
              memmove (blob->keys[n].fpr+4, blob->keys[n].fpr, 16);
              memset (blob->keys[n].fpr, 0, 4);
              blob->keys[n].off_kid = pgp_temp_store_kid (blob, pk);
	    }
          else
            {
              blob->keys[n].off_kid = 0; /* will be fixed up later */
	    }
          blob->keys[n].flags = 0;
          n++;
	}
      else if ( node->pkt->pkttype == PKT_SECRET_KEY
		  || node->pkt->pkttype == PKT_SECRET_SUBKEY ) 
        {
          never_reached (); /* actually not yet implemented */
	}
    }
  assert (n == blob->nkeys);
  return 0;
}

static int
pgp_create_uid_part (KEYBOXBLOB blob, KBNODE keyblock)
{
  KBNODE node;
  int n;

  for (n=0, node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          PKT_user_id *u = node->pkt->pkt.user_id;
          
          blob->uids[n].len = u->len;
          blob->uids[n].flags = 0;
          blob->uids[n].validity = 0;
          n++;
	}
    }
  assert (n == blob->nuids);
  return 0;
}

static int
pgp_create_sig_part (KEYBOXBLOB blob, KBNODE keyblock)
{
  KBNODE node;
  int n;
  
  for (n=0, node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_SIGNATURE)
        {
          PKT_signature *sig = node->pkt->pkt.signature;
          
          blob->sigs[n] = 0;	/* FIXME: check the signature here */
          n++;
	}
    }
  assert( n == blob->nsigs );
  return 0;
}

static int
pgp_create_blob_keyblock (KEYBOXBLOB blob, KBNODE keyblock)
{
  struct membuf *a = blob->buf;
  KBNODE node;
  int rc;
  int n;
  u32 kbstart = a->len;

  add_fixup (blob, kbstart);

  for (n = 0, node = keyblock; node; node = node->next)
    {
      rc = build_packet ( a, node->pkt );
      if ( rc ) {
        gpg_log_error ("build_packet(%d) for keyboxblob failed: %s\n",
                      node->pkt->pkttype, gpg_errstr(rc) );
        return GPGERR_WRITE_FILE;
      }
      if ( node->pkt->pkttype == PKT_USER_ID ) 
        {
          PKT_user_id *u = node->pkt->pkt.user_id;
          /* build_packet has set the offset of the name into u ;
           * now we can do the fixup */
          add_fixup (blob, blob->uids[n].off_addr, u->stored_at);
          n++;
	}
    }
  assert (n == blob->nuids);

  add_fixup (blob, a->len - kbstart);
  return 0;
}
 
#endif /*KEYBOX_WITH_OPENPGP*/


#ifdef KEYBOX_WITH_X509
/* 
   X.509 specific stuff
 */

/* Write the raw certificate out */
static int
x509_create_blob_cert (KEYBOXBLOB blob, ksba_cert_t cert)
{
  struct membuf *a = blob->buf;
  const unsigned char *image;
  size_t length;
  u32 kbstart = a->len;

  /* Store our offset for later fixup */
  add_fixup (blob, 8, kbstart);

  image = ksba_cert_get_image (cert, &length);
  if (!image)
    return gpg_error (GPG_ERR_GENERAL);
  put_membuf (a, image, length);

  add_fixup (blob, 12, a->len - kbstart);
  return 0;
}
 
#endif /*KEYBOX_WITH_X509*/

/* Write a stored keyID out to the buffer */
static void
write_stored_kid (KEYBOXBLOB blob, int seqno)
{
  struct keyid_list *r;
  
  for ( r = blob->temp_kids; r; r = r->next ) 
    {
      if (r->seqno == seqno )
        {
          put_membuf (blob->buf, r->kid, 8);
          return;
	}
    }
  never_reached ();
}

/* Release a list of key IDs */
static void
release_kid_list (struct keyid_list *kl)
{
  struct keyid_list *r, *r2;
  
  for ( r = kl; r; r = r2 ) 
    {
      r2 = r->next;
      xfree (r);
    }
}



static int
create_blob_header (KEYBOXBLOB blob, int blobtype, int as_ephemeral)
{
  struct membuf *a = blob->buf;
  int i;

  put32 ( a, 0 ); /* blob length, needs fixup */
  put8 ( a, blobtype);  
  put8 ( a, 1 );  /* blob type version */
  put16 ( a, as_ephemeral? 2:0 ); /* blob flags */

  put32 ( a, 0 ); /* offset to the raw data, needs fixup */
  put32 ( a, 0 ); /* length of the raw data, needs fixup */

  put16 ( a, blob->nkeys );
  put16 ( a, 20 + 4 + 2 + 2 );  /* size of key info */
  for ( i=0; i < blob->nkeys; i++ )
    {
      put_membuf (a, blob->keys[i].fpr, 20);
      blob->keys[i].off_kid_addr = a->len;
      put32 ( a, 0 ); /* offset to keyid, fixed up later */
      put16 ( a, blob->keys[i].flags );
      put16 ( a, 0 ); /* reserved */
    }

  put16 (a, blob->seriallen); /*fixme: check that it fits into 16 bits*/
  if (blob->serial)
    put_membuf (a, blob->serial, blob->seriallen);

  put16 ( a, blob->nuids );
  put16 ( a, 4 + 4 + 2 + 1 + 1 );  /* size of uid info */
  for (i=0; i < blob->nuids; i++)
    {
      blob->uids[i].off_addr = a->len;
      put32 ( a, 0 ); /* offset to userid, fixed up later */
      put32 ( a, blob->uids[i].len );
      put16 ( a, blob->uids[i].flags );
      put8  ( a, 0 ); /* validity */
      put8  ( a, 0 ); /* reserved */
    }

  put16 ( a, blob->nsigs );
  put16 ( a, 4 );  /* size of sig info */
  for (i=0; i < blob->nsigs; i++)
    {
      put32 ( a, blob->sigs[i]);
    }

  put8 ( a, 0 );  /* assigned ownertrust */
  put8 ( a, 0 );  /* validity of all user IDs */
  put16 ( a, 0 );  /* reserved */
  put32 ( a, 0 );  /* time of next recheck */
  put32 ( a, 0 );  /* newest timestamp (none) */
  put32 ( a, make_timestamp() );  /* creation time */
  put32 ( a, 0 );  /* size of reserved space */
  /* reserved space (which is currently of size 0) */

  /* space where we write keyIDs and and other stuff so that the
     pointers can actually point to somewhere */
  if (blobtype == BLOBTYPE_PGP)
    {
      /* We need to store the keyids for all pgp v3 keys because those key
         IDs are not part of the fingerprint.  While we are doing that, we
         fixup all the keyID offsets */
      for (i=0; i < blob->nkeys; i++ )
        {
          if (blob->keys[i].off_kid) 
            { /* this is a v3 one */
              add_fixup (blob, blob->keys[i].off_kid_addr, a->len);
              write_stored_kid (blob, blob->keys[i].off_kid);
            }
          else
            { /* the better v4 key IDs - just store an offset 8 bytes back */
              add_fixup (blob, blob->keys[i].off_kid_addr,
                         blob->keys[i].off_kid_addr - 8); 
            }
        }
    }
  
  if (blobtype == BLOBTYPE_X509)
    {
      /* We don't want to point to ASN.1 encoded UserIDs (DNs) but to
         the utf-8 string represenation of them */
      for (i=0; i < blob->nuids; i++ )
        {
          if (blob->uids[i].name) 
            { /* this is a v3 one */
              add_fixup (blob, blob->uids[i].off_addr, a->len);
              put_membuf (blob->buf, blob->uids[i].name, blob->uids[i].len);
            }
        }
    }

    return 0;
}



static int
create_blob_trailer (KEYBOXBLOB blob)
{
  (void)blob;
  return 0;
}


static int
create_blob_finish (KEYBOXBLOB blob)
{
  struct membuf *a = blob->buf;
  unsigned char *p;
  unsigned char *pp;
  int i;
  size_t n;

  /* write a placeholder for the checksum */
  for (i = 0; i < 16; i++ )
    put32 (a, 0);  /* Hmmm: why put32() ?? */
  
  /* get the memory area */
  n = 0; /* (Just to avoid compiler warning.) */
  p = get_membuf (a, &n);
  if (!p)
    return gpg_error (GPG_ERR_ENOMEM);
  assert (n >= 20);

  /* fixup the length */
  add_fixup (blob, 0, n);

  /* do the fixups */
  if (blob->fixup_out_of_core)
    return gpg_error (GPG_ERR_ENOMEM);

  {
    struct fixup_list *fl;
    for (fl = blob->fixups; fl; fl = fl->next)
      {
        assert (fl->off+4 <= n);
        p[fl->off+0] = fl->val >> 24;
        p[fl->off+1] = fl->val >> 16;
        p[fl->off+2] = fl->val >>  8;
        p[fl->off+3] = fl->val;
      }
  }

  /* calculate and store the MD5 checksum */
  gcry_md_hash_buffer (GCRY_MD_MD5, p + n - 16, p, n - 16);

  pp = xtrymalloc (n);
  if ( !pp )
    return gpg_error_from_syserror ();
  memcpy (pp , p, n);
  blob->blob = pp;
  blob->bloblen = n;
  
  return 0;
}


#ifdef KEYBOX_WITH_OPENPGP

int
_keybox_create_pgp_blob (KEYBOXBLOB *r_blob, KBNODE keyblock, int as_ephemeral)
{
  int rc = 0;
  KBNODE node;
  KEYBOXBLOB blob;

  *r_blob = NULL;
  blob = xtrycalloc (1, sizeof *blob);
  if (!blob)
    return gpg_error_from_syserror ();

  /* fixme: Do some sanity checks on the keyblock */

  /* count userids and keys so that we can allocate the arrays */
  for (node = keyblock; node; node = node->next) 
    {
      switch (node->pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_SECRET_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_SUBKEY: blob->nkeys++; break;
        case PKT_USER_ID:  blob->nuids++; break;
        case PKT_SIGNATURE: blob->nsigs++; break;
        default: break;
	}
    }

  blob->keys = xtrycalloc (blob->nkeys, sizeof *blob->keys );
  blob->uids = xtrycalloc (blob->nuids, sizeof *blob->uids );
  blob->sigs = xtrycalloc (blob->nsigs, sizeof *blob->sigs );
  if (!blob->keys || !blob->uids || !blob->sigs)
    {
      rc = gpg_error (GPG_ERR_ENOMEM);
      goto leave;
    }

  rc = pgp_create_key_part ( blob, keyblock );
  if (rc)
    goto leave;
  rc = pgp_create_uid_part ( blob, keyblock );
  if (rc)
    goto leave;
  rc = pgp_create_sig_part ( blob, keyblock );
  if (rc)
    goto leave;
  
  init_membuf (&blob->bufbuf, 1024);
  blob->buf = &blob->bufbuf;
  rc = create_blob_header (blob, BLOBTYPE_OPENPGP, as_ephemeral);
  if (rc)
    goto leave;
  rc = pgp_create_blob_keyblock (blob, keyblock);
  if (rc)
    goto leave;
  rc = create_blob_trailer (blob);
  if (rc)
    goto leave;
  rc = create_blob_finish ( blob );
  if (rc)
    goto leave;

  
 leave:
  release_kid_list (blob->temp_kids);
  blob->temp_kids = NULL;
  if (rc)
    {
      keybox_release_blob (blob);
      *r_blob = NULL;
    }
  else
    {
      *r_blob = blob;
    }
  return rc;
}
#endif /*KEYBOX_WITH_OPENPGP*/

#ifdef KEYBOX_WITH_X509

/* Return an allocated string with the email address extracted from a
   DN.  Note hat we use this code also in ../sm/keylist.c.  */
static char *
x509_email_kludge (const char *name)
{
  const char *p, *string;
  unsigned char *buf;
  int n;

  string = name;
  for (;;)
    {
      p = strstr (string, "1.2.840.113549.1.9.1=#");
      if (!p)
        return NULL;
      if (p == name || (p > string+1 && p[-1] == ',' && p[-2] != '\\'))
        {
          name = p + 22;
          break;
        }
      string = p + 22;
    }


  /* This looks pretty much like an email address in the subject's DN
     we use this to add an additional user ID entry.  This way,
     OpenSSL generated keys get a nicer and usable listing.  */
  for (n=0, p=name; hexdigitp (p) && hexdigitp (p+1); p +=2, n++)
    ;
  if (!n)
    return NULL;
  buf = xtrymalloc (n+3);
  if (!buf)
    return NULL; /* oops, out of core */
  *buf = '<';
  for (n=1, p=name; hexdigitp (p); p +=2, n++)
    buf[n] = xtoi_2 (p);
  buf[n++] = '>';
  buf[n] = 0;
  return (char*)buf;
}



/* Note: We should move calculation of the digest into libksba and
   remove that parameter */
int
_keybox_create_x509_blob (KEYBOXBLOB *r_blob, ksba_cert_t cert,
                          unsigned char *sha1_digest, int as_ephemeral)
{
  int i, rc = 0;
  KEYBOXBLOB blob;
  unsigned char *sn;
  char *p;
  char **names = NULL;
  size_t max_names;

  *r_blob = NULL;
  blob = xtrycalloc (1, sizeof *blob);
  if( !blob )
    return gpg_error_from_syserror ();

  sn = ksba_cert_get_serial (cert);
  if (sn)
    {
      size_t n, len;
      n = gcry_sexp_canon_len (sn, 0, NULL, NULL);
      if (n < 2)
        {
          xfree (sn);
          return gpg_error (GPG_ERR_GENERAL);
        }
      blob->serialbuf = sn;
      sn++; n--; /* skip '(' */
      for (len=0; n && *sn && *sn != ':' && digitp (sn); n--, sn++)
        len = len*10 + atoi_1 (sn);
      if (*sn != ':')
        {
          xfree (blob->serialbuf);
          blob->serialbuf = NULL;
          return gpg_error (GPG_ERR_GENERAL);
        }
      sn++;
      blob->serial = sn;
      blob->seriallen = len;
    }

  blob->nkeys = 1;

  /* create list of names */
  blob->nuids = 0;
  max_names = 100;
  names = xtrymalloc (max_names * sizeof *names);
  if (!names)
    {
      rc = gpg_error_from_syserror ();
      goto leave;
    }
  
  p = ksba_cert_get_issuer (cert, 0);
  if (!p)
    {
      rc =  gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  names[blob->nuids++] = p;
  for (i=0; (p = ksba_cert_get_subject (cert, i)); i++)
    {
      if (blob->nuids >= max_names)
        {
          char **tmp;
          
          max_names += 100;
          tmp = xtryrealloc (names, max_names * sizeof *names);
          if (!tmp)
            {
              rc = gpg_error_from_syserror ();
              goto leave;
            }
          names = tmp;
        }
      names[blob->nuids++] = p;
      if (!i && (p=x509_email_kludge (p)))
        names[blob->nuids++] = p; /* due to !i we don't need to check bounds*/
    }
  
  /* space for signature information */
  blob->nsigs = 1; 

  blob->keys = xtrycalloc (blob->nkeys, sizeof *blob->keys );
  blob->uids = xtrycalloc (blob->nuids, sizeof *blob->uids );
  blob->sigs = xtrycalloc (blob->nsigs, sizeof *blob->sigs );
  if (!blob->keys || !blob->uids || !blob->sigs)
    {
      rc = gpg_error (GPG_ERR_ENOMEM);
      goto leave;
    }

  memcpy (blob->keys[0].fpr, sha1_digest, 20);
  blob->keys[0].off_kid = 0; /* We don't have keyids */
  blob->keys[0].flags = 0;

  /* issuer and subject names */
  for (i=0; i < blob->nuids; i++)
    {
      blob->uids[i].name = names[i];
      blob->uids[i].len = strlen(names[i]);
      names[i] = NULL;
      blob->uids[i].flags = 0;
      blob->uids[i].validity = 0;
    }
  xfree (names);
  names = NULL;

  /* signatures */
  blob->sigs[0] = 0;	/* not yet checked */

  /* Create a temporary buffer for further processing */
  init_membuf (&blob->bufbuf, 1024);
  blob->buf = &blob->bufbuf;
  /* write out what we already have */
  rc = create_blob_header (blob, BLOBTYPE_X509, as_ephemeral);
  if (rc)
    goto leave;
  rc = x509_create_blob_cert (blob, cert);
  if (rc)
    goto leave;
  rc = create_blob_trailer (blob);
  if (rc)
    goto leave;
  rc = create_blob_finish ( blob );
  if (rc)
    goto leave;

  
 leave:
  release_kid_list (blob->temp_kids);
  blob->temp_kids = NULL;
  if (blob && names)
    {
      for (i=0; i < blob->nuids; i++)
        xfree (names[i]); 
    }
  xfree (names);
  if (rc)
    {
      _keybox_release_blob (blob);
      *r_blob = NULL;
    }
  else
    {
      *r_blob = blob;
    }
  return rc;
}
#endif /*KEYBOX_WITH_X509*/



int
_keybox_new_blob (KEYBOXBLOB *r_blob,
                  unsigned char *image, size_t imagelen, off_t off)
{
  KEYBOXBLOB blob;
  
  *r_blob = NULL;
  blob = xtrycalloc (1, sizeof *blob);
  if (!blob)
    return gpg_error_from_syserror ();

  blob->blob = image;
  blob->bloblen = imagelen;
  blob->fileoffset = off;
  *r_blob = blob;
  return 0;
}


void
_keybox_release_blob (KEYBOXBLOB blob)
{
  int i;
  if (!blob)
    return;
  /* hmmm: release membuf here?*/
  xfree (blob->keys );
  xfree (blob->serialbuf);
  for (i=0; i < blob->nuids; i++)
    xfree (blob->uids[i].name);
  xfree (blob->uids );
  xfree (blob->sigs );
  xfree (blob->blob );
  xfree (blob );
}



const unsigned char *
_keybox_get_blob_image ( KEYBOXBLOB blob, size_t *n )
{
  *n = blob->bloblen;
  return blob->blob;
}

off_t
_keybox_get_blob_fileoffset (KEYBOXBLOB blob)
{
  return blob->fileoffset;
}



void
_keybox_update_header_blob (KEYBOXBLOB blob)
{
  if (blob->bloblen >= 32 && blob->blob[4] == BLOBTYPE_HEADER)
    {
      u32 val = make_timestamp ();

      /* Update the last maintenance run times tamp. */
      blob->blob[20]   = (val >> 24);
      blob->blob[20+1] = (val >> 16);
      blob->blob[20+2] = (val >>  8);
      blob->blob[20+3] = (val      );
    }
}
