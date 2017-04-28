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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
* The keybox data format

   The KeyBox uses an augmented OpenPGP/X.509 key format.  This makes
   random access to a keyblock/certificate easier and also gives the
   opportunity to store additional information (e.g. the fingerprint)
   along with the key.  All integers are stored in network byte order,
   offsets are counted from the beginning of the Blob.

** Overview of blob types

   | Byte 4 | Blob type    |
   |--------+--------------|
   |      0 | Empty blob   |
   |      1 | First blob   |
   |      2 | OpenPGP blob |
   |      3 | X.509 blob   |

** The First blob

   The first blob of a plain KBX file has a special format:

   - u32  Length of this blob
   - byte Blob type (1)
   - byte Version number (1)
   - u16  Header flags
          bit 0 - RFU
          bit 1 - Is being or has been used for OpenPGP blobs
   - b4   Magic 'KBXf'
   - u32  RFU
   - u32  file_created_at
   - u32  last_maintenance_run
   - u32  RFU
   - u32  RFU

** The OpenPGP and X.509 blobs

   The OpenPGP and X.509 blobs are very similar, things which are
   X.509 specific are noted like [X.509: xxx]

   - u32  Length of this blob (including these 4 bytes)
   - byte Blob type
           2 = OpenPGP
           3 = X509
   - byte Version number of this blob type
           1 = The only defined value
   - u16  Blob flags
          bit 0 = contains secret key material (not used)
          bit 1 = ephemeral blob (e.g. used while querying external resources)
   - u32  Offset to the OpenPGP keyblock or the X.509 DER encoded
          certificate
   - u32  The length of the keyblock or certificate
   - u16  [NKEYS] Number of keys (at least 1!) [X509: always 1]
   - u16  Size of the key information structure (at least 28).
   - NKEYS times:
      - b20  The fingerprint of the key.
             Fingerprints are always 20 bytes, MD5 left padded with zeroes.
      - u32  Offset to the n-th key's keyID (a keyID is always 8 byte)
             or 0 if not known which is the case only for X.509.
      - u16  Key flags
             bit 0 = qualified signature (not yet implemented}
      - u16  RFU
      - bN   Optional filler up to the specified length of this
             structure.
   - u16  Size of the serial number (may be zero)
      -  bN  The serial number. N as giiven above.
   - u16  Number of user IDs
   - u16  [NUIDS] Size of user ID information structure
   - NUIDS times:

      For X509, the first user ID is the Issuer, the second the
      Subject and the others are subjectAltNames.  For OpenPGP we only
      store the information from UserID packets here.

      - u32  Blob offset to the n-th user ID
      - u32  Length of this user ID.
      - u16  User ID flags.
             (not yet used)
      - byte Validity
      - byte RFU

   - u16  [NSIGS] Number of signatures
   - u16  Size of signature information (4)
   - NSIGS times:
      - u32  Expiration time of signature with some special values.
             Since version 2.1.20 these special valuesare not anymore
             used for OpenPGP:
             - 0x00000000 = not checked
             - 0x00000001 = missing key
             - 0x00000002 = bad signature
             - 0x10000000 = valid and expires at some date in 1978.
             - 0xffffffff = valid and does not expire
   - u8	Assigned ownertrust [X509: not used]
   - u8	All_Validity
        OpenPGP: See ../g10/trustdb/TRUST_* [not yet used]
        X509: Bit 4 set := key has been revoked.
                           Note that this value matches TRUST_FLAG_REVOKED
   - u16  RFU
   - u32  Recheck_after
   - u32  Latest timestamp in the keyblock (useful for KS syncronsiation?)
   - u32  Blob created at
   - u32  [NRES] Size of reserved space (not including this field)
   - bN   Reserved space of size NRES for future use.
   - bN   Arbitrary space for example used to store data which is not
          part of the keyblock or certificate.  For example the v3 key
          IDs go here.
   - bN   Space for the keyblock or certificate.
   - bN   RFU.  This is the remaining space after keyblock and before
          the checksum.  It is not covered by the checksum.
   - b20  SHA-1 checksum (useful for KS syncronisation?)
          Note, that KBX versions before GnuPG 2.1 used an MD5
          checksum.  However it was only created but never checked.
          Thus we do not expect problems if we switch to SHA-1.  If
          the checksum fails and the first 4 bytes are zero, we can
          try again with MD5.  SHA-1 has the advantage that it is
          faster on CPUs with dedicated SHA-1 support.


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

#ifdef KEYBOX_WITH_X509
#include <ksba.h>
#endif


#include "../common/gettime.h"


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
  u32    off;
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



/* A simple implementation of a dynamic buffer.  Use init_membuf() to
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
  if (buf)
    memcpy (mb->buf + mb->len, buf, len);
  else
    memset (mb->buf + mb->len, 0, len);
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
  OpenPGP specific stuff
*/


/* We must store the keyid at some place because we can't calculate
   the offset yet. This is only used for v3 keyIDs.  Function returns
   an index value for later fixup or -1 for out of core.  The value
   must be a non-zero value. */
static int
pgp_temp_store_kid (KEYBOXBLOB blob, struct _keybox_openpgp_key_info *kinfo)
{
  struct keyid_list *k, *r;

  k = xtrymalloc (sizeof *k);
  if (!k)
    return -1;
  memcpy (k->kid, kinfo->keyid, 8);
  k->seqno = 0;
  k->next = blob->temp_kids;
  blob->temp_kids = k;
  for (r=k; r; r = r->next)
    k->seqno++;

  return k->seqno;
}


/* Helper for pgp_create_key_part.  */
static gpg_error_t
pgp_create_key_part_single (KEYBOXBLOB blob, int n,
                            struct _keybox_openpgp_key_info *kinfo)
{
  size_t fprlen;
  int off;

  fprlen = kinfo->fprlen;
  if (fprlen > 20)
    fprlen = 20;
  memcpy (blob->keys[n].fpr, kinfo->fpr, fprlen);
  if (fprlen != 20) /* v3 fpr - shift right and fill with zeroes. */
    {
      memmove (blob->keys[n].fpr + 20 - fprlen, blob->keys[n].fpr, fprlen);
      memset (blob->keys[n].fpr, 0, 20 - fprlen);
      off = pgp_temp_store_kid (blob, kinfo);
      if (off == -1)
        return gpg_error_from_syserror ();
      blob->keys[n].off_kid = off;
    }
  else
    blob->keys[n].off_kid = 0; /* Will be fixed up later */
  blob->keys[n].flags = 0;
  return 0;
}


static gpg_error_t
pgp_create_key_part (KEYBOXBLOB blob, keybox_openpgp_info_t info)
{
  gpg_error_t err;
  int n = 0;
  struct _keybox_openpgp_key_info *kinfo;

  err = pgp_create_key_part_single (blob, n++, &info->primary);
  if (err)
    return err;
  if (info->nsubkeys)
    for (kinfo = &info->subkeys; kinfo; kinfo = kinfo->next)
      if ((err=pgp_create_key_part_single (blob, n++, kinfo)))
        return err;

  assert (n == blob->nkeys);
  return 0;
}


static void
pgp_create_uid_part (KEYBOXBLOB blob, keybox_openpgp_info_t info)
{
  int n = 0;
  struct _keybox_openpgp_uid_info *u;

  if (info->nuids)
    {
      for (u = &info->uids; u; u = u->next)
        {
          blob->uids[n].off = u->off;
          blob->uids[n].len = u->len;
          blob->uids[n].flags = 0;
          blob->uids[n].validity = 0;
          n++;
        }
    }

  assert (n == blob->nuids);
}


static void
pgp_create_sig_part (KEYBOXBLOB blob, u32 *sigstatus)
{
  int n;

  for (n=0; n < blob->nsigs; n++)
    {
      blob->sigs[n] = sigstatus? sigstatus[n+1] : 0;
    }
}


static int
pgp_create_blob_keyblock (KEYBOXBLOB blob,
                          const unsigned char *image, size_t imagelen)
{
  struct membuf *a = blob->buf;
  int n;
  u32 kbstart = a->len;

  add_fixup (blob, 8, kbstart);

  for (n = 0; n < blob->nuids; n++)
    add_fixup (blob, blob->uids[n].off_addr, kbstart + blob->uids[n].off);

  put_membuf (a, image, imagelen);

  add_fixup (blob, 12, a->len - kbstart);
  return 0;
}



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

  /* space where we write keyIDs and other stuff so that the
     pointers can actually point to somewhere */
  if (blobtype == KEYBOX_BLOBTYPE_PGP)
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

  if (blobtype == KEYBOX_BLOBTYPE_X509)
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
  size_t n;

  /* Write a placeholder for the checksum */
  put_membuf (a, NULL, 20);

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
    {
      xfree (p);
      return gpg_error (GPG_ERR_ENOMEM);
    }

  {
    struct fixup_list *fl, *next;
    for (fl = blob->fixups; fl; fl = next)
      {
        assert (fl->off+4 <= n);
        p[fl->off+0] = fl->val >> 24;
        p[fl->off+1] = fl->val >> 16;
        p[fl->off+2] = fl->val >>  8;
        p[fl->off+3] = fl->val;
        next = fl->next;
        xfree (fl);
      }
    blob->fixups = NULL;
  }

  /* Compute and store the SHA-1 checksum. */
  gcry_md_hash_buffer (GCRY_MD_SHA1, p + n - 20, p, n - 20);

  pp = xtrymalloc (n);
  if ( !pp )
    {
      xfree (p);
      return gpg_error_from_syserror ();
    }
  memcpy (pp , p, n);
  xfree (p);
  blob->blob = pp;
  blob->bloblen = n;

  return 0;
}



gpg_error_t
_keybox_create_openpgp_blob (KEYBOXBLOB *r_blob,
                             keybox_openpgp_info_t info,
                             const unsigned char *image,
                             size_t imagelen,
                             int as_ephemeral)
{
  gpg_error_t err;
  KEYBOXBLOB blob;

  *r_blob = NULL;

  blob = xtrycalloc (1, sizeof *blob);
  if (!blob)
    return gpg_error_from_syserror ();

  blob->nkeys = 1 + info->nsubkeys;
  blob->keys = xtrycalloc (blob->nkeys, sizeof *blob->keys );
  if (!blob->keys)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  blob->nuids = info->nuids;
  if (blob->nuids)
    {
      blob->uids = xtrycalloc (blob->nuids, sizeof *blob->uids );
      if (!blob->uids)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  blob->nsigs = info->nsigs;
  if (blob->nsigs)
    {
      blob->sigs = xtrycalloc (blob->nsigs, sizeof *blob->sigs );
      if (!blob->sigs)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  err = pgp_create_key_part (blob, info);
  if (err)
    goto leave;
  pgp_create_uid_part (blob, info);
  pgp_create_sig_part (blob, NULL);

  init_membuf (&blob->bufbuf, 1024);
  blob->buf = &blob->bufbuf;
  err = create_blob_header (blob, KEYBOX_BLOBTYPE_PGP, as_ephemeral);
  if (err)
    goto leave;
  err = pgp_create_blob_keyblock (blob, image, imagelen);
  if (err)
    goto leave;
  err = create_blob_trailer (blob);
  if (err)
    goto leave;
  err = create_blob_finish (blob);
  if (err)
    goto leave;

 leave:
  release_kid_list (blob->temp_kids);
  blob->temp_kids = NULL;
  if (err)
    _keybox_release_blob (blob);
  else
    *r_blob = blob;
  return err;
}


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
  rc = create_blob_header (blob, KEYBOX_BLOBTYPE_X509, as_ephemeral);
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
  if (names)
    {
      for (i=0; i < blob->nuids; i++)
        xfree (names[i]);
      xfree (names);
    }
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
  if (blob->buf)
    {
      size_t len;
      xfree (get_membuf (blob->buf, &len));
    }
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
_keybox_update_header_blob (KEYBOXBLOB blob, int for_openpgp)
{
  if (blob->bloblen >= 32 && blob->blob[4] == KEYBOX_BLOBTYPE_HEADER)
    {
      u32 val = make_timestamp ();

      /* Update the last maintenance run times tamp. */
      blob->blob[20]   = (val >> 24);
      blob->blob[20+1] = (val >> 16);
      blob->blob[20+2] = (val >>  8);
      blob->blob[20+3] = (val      );

      if (for_openpgp)
        blob->blob[7] |= 0x02;  /* OpenPGP data may be available.  */
    }
}
