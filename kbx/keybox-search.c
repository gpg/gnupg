/* keybox-search.c - Search operations
 * Copyright (C) 2001, 2002, 2003, 2004, 2012,
 *               2013 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "keybox-defs.h"
#include <gcrypt.h>
#include "../common/host2net.h"
#include "../common/mbox-util.h"

#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


struct sn_array_s {
    int snlen;
    unsigned char *sn;
};


#define get32(a) buf32_to_ulong ((a))
#define get16(a) buf16_to_ulong ((a))


static inline unsigned int
blob_get_blob_flags (KEYBOXBLOB blob)
{
  const unsigned char *buffer;
  size_t length;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 8)
    return 0; /* oops */

  return get16 (buffer + 6);
}


/* Return the first keyid from the blob.  Returns true if
   available.  */
static int
blob_get_first_keyid (KEYBOXBLOB blob, u32 *kid)
{
  const unsigned char *buffer;
  size_t length, nkeys, keyinfolen;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 48)
    return 0; /* blob too short */

  nkeys = get16 (buffer + 16);
  keyinfolen = get16 (buffer + 18);
  if (!nkeys || keyinfolen < 28)
    return 0; /* invalid blob */

  kid[0] = get32 (buffer + 32);
  kid[1] = get32 (buffer + 36);

  return 1;
}


/* Return information on the flag WHAT within the blob BUFFER,LENGTH.
   Return the offset and the length (in bytes) of the flag in
   FLAGOFF,FLAG_SIZE. */
gpg_err_code_t
_keybox_get_flag_location (const unsigned char *buffer, size_t length,
                           int what, size_t *flag_off, size_t *flag_size)
{
  size_t pos;
  size_t nkeys, keyinfolen;
  size_t nuids, uidinfolen;
  size_t nserial;
  size_t nsigs, siginfolen, siginfooff;

  switch (what)
    {
    case KEYBOX_FLAG_BLOB:
      if (length < 8)
        return GPG_ERR_INV_OBJ;
      *flag_off = 6;
      *flag_size = 2;
      break;

    case KEYBOX_FLAG_OWNERTRUST:
    case KEYBOX_FLAG_VALIDITY:
    case KEYBOX_FLAG_CREATED_AT:
    case KEYBOX_FLAG_SIG_INFO:
      if (length < 20)
        return GPG_ERR_INV_OBJ;
      /* Key info. */
      nkeys = get16 (buffer + 16);
      keyinfolen = get16 (buffer + 18 );
      if (keyinfolen < 28)
        return GPG_ERR_INV_OBJ;
      pos = 20 + keyinfolen*nkeys;
      if (pos+2 > length)
        return GPG_ERR_INV_OBJ; /* Out of bounds. */
      /* Serial number. */
      nserial = get16 (buffer+pos);
      pos += 2 + nserial;
      if (pos+4 > length)
        return GPG_ERR_INV_OBJ; /* Out of bounds. */
      /* User IDs. */
      nuids = get16 (buffer + pos); pos += 2;
      uidinfolen = get16 (buffer + pos); pos += 2;
      if (uidinfolen < 12 )
        return GPG_ERR_INV_OBJ;
      pos += uidinfolen*nuids;
      if (pos+4 > length)
        return GPG_ERR_INV_OBJ ; /* Out of bounds. */
      /* Signature info. */
      siginfooff = pos;
      nsigs = get16 (buffer + pos); pos += 2;
      siginfolen = get16 (buffer + pos); pos += 2;
      if (siginfolen < 4 )
        return GPG_ERR_INV_OBJ;
      pos += siginfolen*nsigs;
      if (pos+1+1+2+4+4+4+4 > length)
        return GPG_ERR_INV_OBJ ; /* Out of bounds. */
      *flag_size = 1;
      *flag_off = pos;
      switch (what)
        {
        case KEYBOX_FLAG_VALIDITY:
          *flag_off += 1;
          break;
        case KEYBOX_FLAG_CREATED_AT:
          *flag_size = 4;
          *flag_off += 1+2+4+4+4;
          break;
        case KEYBOX_FLAG_SIG_INFO:
          *flag_size = siginfolen * nsigs;
          *flag_off = siginfooff;
          break;
        default:
          break;
        }
      break;

    default:
      return GPG_ERR_INV_FLAG;
    }
  return 0;
}



/* Return one of the flags WHAT in VALUE from the blob BUFFER of
   LENGTH bytes.  Return 0 on success or an raw error code. */
static gpg_err_code_t
get_flag_from_image (const unsigned char *buffer, size_t length,
                     int what, unsigned int *value)
{
  gpg_err_code_t ec;
  size_t pos, size;

  *value = 0;
  ec = _keybox_get_flag_location (buffer, length, what, &pos, &size);
  if (!ec)
    switch (size)
      {
      case 1: *value = buffer[pos]; break;
      case 2: *value = get16 (buffer + pos); break;
      case 4: *value = get32 (buffer + pos); break;
      default: ec = GPG_ERR_BUG; break;
      }

  return ec;
}


static int
blob_cmp_sn (KEYBOXBLOB blob, const unsigned char *sn, int snlen)
{
  const unsigned char *buffer;
  size_t length;
  size_t pos, off;
  size_t nkeys, keyinfolen;
  size_t nserial;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* blob too short */

  /*keys*/
  nkeys = get16 (buffer + 16);
  keyinfolen = get16 (buffer + 18 );
  if (keyinfolen < 28)
    return 0; /* invalid blob */
  pos = 20 + keyinfolen*nkeys;
  if (pos+2 > length)
    return 0; /* out of bounds */

  /*serial*/
  nserial = get16 (buffer+pos);
  off = pos + 2;
  if (off+nserial > length)
    return 0; /* out of bounds */

  return nserial == snlen && !memcmp (buffer+off, sn, snlen);
}


/* Returns 0 if not found or the number of the key which was found.
   For X.509 this is always 1, for OpenPGP this is 1 for the primary
   key and 2 and more for the subkeys.  */
static int
blob_cmp_fpr (KEYBOXBLOB blob, const unsigned char *fpr)
{
  const unsigned char *buffer;
  size_t length;
  size_t pos, off;
  size_t nkeys, keyinfolen;
  int idx;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* blob too short */

  /*keys*/
  nkeys = get16 (buffer + 16);
  keyinfolen = get16 (buffer + 18 );
  if (keyinfolen < 28)
    return 0; /* invalid blob */
  pos = 20;
  if (pos + (uint64_t)keyinfolen*nkeys > (uint64_t)length)
    return 0; /* out of bounds */

  for (idx=0; idx < nkeys; idx++)
    {
      off = pos + idx*keyinfolen;
      if (!memcmp (buffer + off, fpr, 20))
        return idx+1; /* found */
    }
  return 0; /* not found */
}

static int
blob_cmp_fpr_part (KEYBOXBLOB blob, const unsigned char *fpr,
                   int fproff, int fprlen)
{
  const unsigned char *buffer;
  size_t length;
  size_t pos, off;
  size_t nkeys, keyinfolen;
  int idx;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* blob too short */

  /*keys*/
  nkeys = get16 (buffer + 16);
  keyinfolen = get16 (buffer + 18 );
  if (keyinfolen < 28)
    return 0; /* invalid blob */
  pos = 20;
  if (pos + (uint64_t)keyinfolen*nkeys > (uint64_t)length)
    return 0; /* out of bounds */

  for (idx=0; idx < nkeys; idx++)
    {
      off = pos + idx*keyinfolen;
      if (!memcmp (buffer + off + fproff, fpr, fprlen))
        return idx+1; /* found */
    }
  return 0; /* not found */
}


static int
blob_cmp_name (KEYBOXBLOB blob, int idx,
               const char *name, size_t namelen, int substr, int x509)
{
  const unsigned char *buffer;
  size_t length;
  size_t pos, off, len;
  size_t nkeys, keyinfolen;
  size_t nuids, uidinfolen;
  size_t nserial;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* blob too short */

  /*keys*/
  nkeys = get16 (buffer + 16);
  keyinfolen = get16 (buffer + 18 );
  if (keyinfolen < 28)
    return 0; /* invalid blob */
  pos = 20 + keyinfolen*nkeys;
  if ((uint64_t)pos+2 > (uint64_t)length)
    return 0; /* out of bounds */

  /*serial*/
  nserial = get16 (buffer+pos);
  pos += 2 + nserial;
  if (pos+4 > length)
    return 0; /* out of bounds */

  /* user ids*/
  nuids = get16 (buffer + pos);  pos += 2;
  uidinfolen = get16 (buffer + pos);  pos += 2;
  if (uidinfolen < 12 /* should add a: || nuidinfolen > MAX_UIDINFOLEN */)
    return 0; /* invalid blob */
  if (pos + uidinfolen*nuids > length)
    return 0; /* out of bounds */

  if (idx < 0)
    { /* Compare all names.  Note that for X.509 we start with index 1
         so to skip the issuer at index 0.  */
      for (idx = !!x509; idx < nuids; idx++)
        {
          size_t mypos = pos;

          mypos += idx*uidinfolen;
          off = get32 (buffer+mypos);
          len = get32 (buffer+mypos+4);
          if ((uint64_t)off+(uint64_t)len > (uint64_t)length)
            return 0; /* error: better stop here out of bounds */
          if (len < 1)
            continue; /* empty name */
          if (substr)
            {
              if (ascii_memcasemem (buffer+off, len, name, namelen))
                return idx+1; /* found */
            }
          else
            {
              if (len == namelen && !memcmp (buffer+off, name, len))
                return idx+1; /* found */
            }
        }
    }
  else
    {
      if (idx > nuids)
        return 0; /* no user ID with that idx */
      pos += idx*uidinfolen;
      off = get32 (buffer+pos);
      len = get32 (buffer+pos+4);
      if (off+len > length)
        return 0; /* out of bounds */
      if (len < 1)
        return 0; /* empty name */

      if (substr)
        {
          if (ascii_memcasemem (buffer+off, len, name, namelen))
            return idx+1; /* found */
        }
      else
        {
          if (len == namelen && !memcmp (buffer+off, name, len))
            return idx+1; /* found */
        }
    }
  return 0; /* not found */
}


/* Compare all email addresses of the subject.  With SUBSTR given as
   True a substring search is done in the mail address.  The X509 flag
   indicated whether the search is done on an X.509 blob.  */
static int
blob_cmp_mail (KEYBOXBLOB blob, const char *name, size_t namelen, int substr,
               int x509)
{
  const unsigned char *buffer;
  size_t length;
  size_t pos, off, len;
  size_t nkeys, keyinfolen;
  size_t nuids, uidinfolen;
  size_t nserial;
  int idx;

  /* fixme: this code is common to blob_cmp_mail */
  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* blob too short */

  /*keys*/
  nkeys = get16 (buffer + 16);
  keyinfolen = get16 (buffer + 18 );
  if (keyinfolen < 28)
    return 0; /* invalid blob */
  pos = 20 + keyinfolen*nkeys;
  if (pos+2 > length)
    return 0; /* out of bounds */

  /*serial*/
  nserial = get16 (buffer+pos);
  pos += 2 + nserial;
  if (pos+4 > length)
    return 0; /* out of bounds */

  /* user ids*/
  nuids = get16 (buffer + pos);  pos += 2;
  uidinfolen = get16 (buffer + pos);  pos += 2;
  if (uidinfolen < 12 /* should add a: || nuidinfolen > MAX_UIDINFOLEN */)
    return 0; /* invalid blob */
  if (pos + uidinfolen*nuids > length)
    return 0; /* out of bounds */

  if (namelen < 1)
    return 0;

  /* Note that for X.509 we start at index 1 because index 0 is used
     for the issuer name.  */
  for (idx=!!x509 ;idx < nuids; idx++)
    {
      size_t mypos = pos;
      size_t mylen;

      mypos += idx*uidinfolen;
      off = get32 (buffer+mypos);
      len = get32 (buffer+mypos+4);
      if ((uint64_t)off+(uint64_t)len > (uint64_t)length)
        return 0; /* error: better stop here - out of bounds */
      if (x509)
        {
          if (len < 2 || buffer[off] != '<')
            continue; /* empty name or trailing 0 not stored */
          len--; /* one back */
          if ( len < 3 || buffer[off+len] != '>')
            continue; /* not a proper email address */
          off++;
          len--;
        }
      else /* OpenPGP.  */
        {
          /* We need to forward to the mailbox part.  */
          mypos = off;
          mylen = len;
          for ( ; len && buffer[off] != '<'; len--, off++)
            ;
          if (len < 2 || buffer[off] != '<')
            {
              /* Mailbox not explicitly given or too short.  Restore
                 OFF and LEN and check whether the entire string
                 resembles a mailbox without the angle brackets.  */
              off = mypos;
              len = mylen;
              if (!is_valid_mailbox_mem (buffer+off, len))
                continue; /* Not a mail address. */
            }
          else /* Seems to be standard user id with mail address.  */
            {
              off++; /* Point to first char of the mail address.  */
              len--;
              /* Search closing '>'.  */
              for (mypos=off; len && buffer[mypos] != '>'; len--, mypos++)
                ;
              if (!len || buffer[mypos] != '>' || off == mypos)
                continue; /* Not a proper mail address.  */
              len = mypos - off;
            }

        }

      if (substr)
        {
          if (ascii_memcasemem (buffer+off, len, name, namelen))
            return idx+1; /* found */
        }
      else
        {
          if (len == namelen && !ascii_memcasecmp (buffer+off, name, len))
            return idx+1; /* found */
        }
    }
  return 0; /* not found */
}


/* Return true if the key in BLOB matches the 20 bytes keygrip GRIP.
 * We don't have the keygrips as meta data, thus we need to parse the
 * certificate. Fixme: We might want to return proper error codes
 * instead of failing a search for invalid certificates etc.  */
static int
blob_openpgp_has_grip (KEYBOXBLOB blob, const unsigned char *grip)
{
  int rc = 0;
  const unsigned char *buffer;
  size_t length;
  size_t cert_off, cert_len;
  struct _keybox_openpgp_info info;
  struct _keybox_openpgp_key_info *k;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* Too short. */
  cert_off = get32 (buffer+8);
  cert_len = get32 (buffer+12);
  if ((uint64_t)cert_off+(uint64_t)cert_len > (uint64_t)length)
    return 0; /* Too short.  */

  if (_keybox_parse_openpgp (buffer + cert_off, cert_len, NULL, &info))
    return 0; /* Parse error.  */

  if (!memcmp (info.primary.grip, grip, 20))
    {
      rc = 1;
      goto leave;
    }

  if (info.nsubkeys)
    {
      k = &info.subkeys;
      do
        {
          if (!memcmp (k->grip, grip, 20))
            {
              rc = 1;
              goto leave;
            }
          k = k->next;
        }
      while (k);
    }

 leave:
  _keybox_destroy_openpgp_info (&info);
  return rc;
}


#ifdef KEYBOX_WITH_X509
/* Return true if the key in BLOB matches the 20 bytes keygrip GRIP.
   We don't have the keygrips as meta data, thus we need to parse the
   certificate. Fixme: We might want to return proper error codes
   instead of failing a search for invalid certificates etc.  */
static int
blob_x509_has_grip (KEYBOXBLOB blob, const unsigned char *grip)
{
  int rc;
  const unsigned char *buffer;
  size_t length;
  size_t cert_off, cert_len;
  ksba_reader_t reader = NULL;
  ksba_cert_t cert = NULL;
  ksba_sexp_t p = NULL;
  gcry_sexp_t s_pkey;
  unsigned char array[20];
  unsigned char *rcp;
  size_t n;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return 0; /* Too short. */
  cert_off = get32 (buffer+8);
  cert_len = get32 (buffer+12);
  if ((uint64_t)cert_off+(uint64_t)cert_len > (uint64_t)length)
    return 0; /* Too short.  */

  rc = ksba_reader_new (&reader);
  if (rc)
    return 0; /* Problem with ksba. */
  rc = ksba_reader_set_mem (reader, buffer+cert_off, cert_len);
  if (rc)
    goto failed;
  rc = ksba_cert_new (&cert);
  if (rc)
    goto failed;
  rc = ksba_cert_read_der (cert, reader);
  if (rc)
    goto failed;
  p = ksba_cert_get_public_key (cert);
  if (!p)
    goto failed;
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    goto failed;
  rc = gcry_sexp_sscan (&s_pkey, NULL, (char*)p, n);
  if (rc)
    {
      gcry_sexp_release (s_pkey);
      goto failed;
    }
  rcp = gcry_pk_get_keygrip (s_pkey, array);
  gcry_sexp_release (s_pkey);
  if (!rcp)
    goto failed; /* Can't calculate keygrip. */

  xfree (p);
  ksba_cert_release (cert);
  ksba_reader_release (reader);
  return !memcmp (array, grip, 20);
 failed:
  xfree (p);
  ksba_cert_release (cert);
  ksba_reader_release (reader);
  return 0;
}
#endif /*KEYBOX_WITH_X509*/



/*
  The has_foo functions are used as helpers for search
*/
static inline int
has_short_kid (KEYBOXBLOB blob, u32 lkid)
{
  unsigned char buf[4];
  buf[0] = lkid >> 24;
  buf[1] = lkid >> 16;
  buf[2] = lkid >> 8;
  buf[3] = lkid;
  return blob_cmp_fpr_part (blob, buf, 16, 4);
}

static inline int
has_long_kid (KEYBOXBLOB blob, u32 mkid, u32 lkid)
{
  unsigned char buf[8];
  buf[0] = mkid >> 24;
  buf[1] = mkid >> 16;
  buf[2] = mkid >> 8;
  buf[3] = mkid;
  buf[4] = lkid >> 24;
  buf[5] = lkid >> 16;
  buf[6] = lkid >> 8;
  buf[7] = lkid;
  return blob_cmp_fpr_part (blob, buf, 12, 8);
}

static inline int
has_fingerprint (KEYBOXBLOB blob, const unsigned char *fpr)
{
  return blob_cmp_fpr (blob, fpr);
}

static inline int
has_keygrip (KEYBOXBLOB blob, const unsigned char *grip)
{
  if (blob_get_type (blob) == KEYBOX_BLOBTYPE_PGP)
    return blob_openpgp_has_grip (blob, grip);
#ifdef KEYBOX_WITH_X509
  if (blob_get_type (blob) == KEYBOX_BLOBTYPE_X509)
    return blob_x509_has_grip (blob, grip);
#endif
  return 0;
}


static inline int
has_issuer (KEYBOXBLOB blob, const char *name)
{
  size_t namelen;

  return_val_if_fail (name, 0);

  if (blob_get_type (blob) != KEYBOX_BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  return blob_cmp_name (blob, 0 /* issuer */, name, namelen, 0, 1);
}

static inline int
has_issuer_sn (KEYBOXBLOB blob, const char *name,
               const unsigned char *sn, int snlen)
{
  size_t namelen;

  return_val_if_fail (name, 0);
  return_val_if_fail (sn, 0);

  if (blob_get_type (blob) != KEYBOX_BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);

  return (blob_cmp_sn (blob, sn, snlen)
          && blob_cmp_name (blob, 0 /* issuer */, name, namelen, 0, 1));
}

static inline int
has_sn (KEYBOXBLOB blob, const unsigned char *sn, int snlen)
{
  return_val_if_fail (sn, 0);

  if (blob_get_type (blob) != KEYBOX_BLOBTYPE_X509)
    return 0;
  return blob_cmp_sn (blob, sn, snlen);
}

static inline int
has_subject (KEYBOXBLOB blob, const char *name)
{
  size_t namelen;

  return_val_if_fail (name, 0);

  if (blob_get_type (blob) != KEYBOX_BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  return blob_cmp_name (blob, 1 /* subject */, name, namelen, 0, 1);
}


static inline int
has_username (KEYBOXBLOB blob, const char *name, int substr)
{
  size_t namelen;
  int btype;

  return_val_if_fail (name, 0);

  btype = blob_get_type (blob);
  if (btype != KEYBOX_BLOBTYPE_PGP && btype != KEYBOX_BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  return blob_cmp_name (blob, -1 /* all subject/user names */, name,
                        namelen, substr, (btype == KEYBOX_BLOBTYPE_X509));
}


static inline int
has_mail (KEYBOXBLOB blob, const char *name, int substr)
{
  size_t namelen;
  int btype;

  return_val_if_fail (name, 0);

  btype = blob_get_type (blob);
  if (btype != KEYBOX_BLOBTYPE_PGP && btype != KEYBOX_BLOBTYPE_X509)
    return 0;

  if (btype == KEYBOX_BLOBTYPE_PGP && *name == '<')
    name++; /* Hack to remove the leading '<' for gpg.  */

  namelen = strlen (name);
  if (namelen && name[namelen-1] == '>')
    namelen--;
  return blob_cmp_mail (blob, name, namelen, substr,
                        (btype == KEYBOX_BLOBTYPE_X509));
}


static void
release_sn_array (struct sn_array_s *array, size_t size)
{
  size_t n;

  for (n=0; n < size; n++)
    xfree (array[n].sn);
  xfree (array);
}



/*
 *
 * The search API
 *
 */

gpg_error_t
keybox_search_reset (KEYBOX_HANDLE hd)
{
  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (hd->found.blob)
    {
      _keybox_release_blob (hd->found.blob);
      hd->found.blob = NULL;
    }

  if (hd->fp)
    {
#if HAVE_W32_SYSTEM
      es_fclose (hd->fp);
      hd->fp = NULL;
#else
      if (es_fseeko (hd->fp, 0, SEEK_SET))
        {
          /* Ooops.  Seek did not work.  Close so that the search will
           * open the file again.  */
          _keybox_ll_close (hd->fp);
          hd->fp = NULL;
        }
#endif
    }
  hd->error = 0;
  hd->eof = 0;
  return 0;
}


/* Note: When in ephemeral mode the search function does visit all
   blobs but in standard mode, blobs flagged as ephemeral are ignored.
   If WANT_BLOBTYPE is not 0 only blobs of this type are considered.
   The value at R_SKIPPED is updated by the number of skipped long
   records (counts PGP and X.509). */
gpg_error_t
keybox_search (KEYBOX_HANDLE hd, KEYBOX_SEARCH_DESC *desc, size_t ndesc,
               keybox_blobtype_t want_blobtype,
               size_t *r_descindex, unsigned long *r_skipped)
{
  gpg_error_t rc;
  size_t n;
  int need_words, any_skip;
  KEYBOXBLOB blob = NULL;
  struct sn_array_s *sn_array = NULL;
  int pk_no, uid_no;
  off_t lastfoundoff;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Clear last found result but reord the offset of the last found
   * blob which we may need later. */
  if (hd->found.blob)
    {
      lastfoundoff = _keybox_get_blob_fileoffset (hd->found.blob);
      _keybox_release_blob (hd->found.blob);
      hd->found.blob = NULL;
    }
  else
    lastfoundoff = 0;

  if (hd->error)
    return hd->error; /* still in error state */
  if (hd->eof)
    return -1; /* still EOF */

  /* figure out what information we need */
  need_words = any_skip = 0;
  for (n=0; n < ndesc; n++)
    {
      switch (desc[n].mode)
        {
        case KEYDB_SEARCH_MODE_WORDS:
          need_words = 1;
          break;
        case KEYDB_SEARCH_MODE_FIRST:
          /* always restart the search in this mode */
          keybox_search_reset (hd);
          lastfoundoff = 0;
          break;
        default:
          break;
	}
      if (desc[n].skipfnc)
        any_skip = 1;
      if (desc[n].snlen == -1 && !sn_array)
        {
          sn_array = xtrycalloc (ndesc, sizeof *sn_array);
          if (!sn_array)
            return (hd->error = gpg_error_from_syserror ());
        }
    }

  (void)need_words;  /* Not yet implemented.  */

  if (!hd->fp)
    {
      rc = _keybox_ll_open (&hd->fp, hd->kb->fname, 0);
      if (rc)
        {
          xfree (sn_array);
          return rc;
        }
      /* log_debug ("%s: re-opened file\n", __func__); */
      if (ndesc && desc[0].mode != KEYDB_SEARCH_MODE_FIRST && lastfoundoff)
        {
          /* Search mode is not first and the last search operation
           * returned a blob which also was not the first one.  We now
           * need to skip over that blob and hope that the file has
           * not changed.  */
          if (es_fseeko (hd->fp, lastfoundoff, SEEK_SET))
            {
              rc = gpg_error_from_syserror ();
              log_debug ("%s: seeking to last found offset failed: %s\n",
                         __func__, gpg_strerror (rc));
              xfree (sn_array);
              return gpg_error (GPG_ERR_NOTHING_FOUND);
            }
          /* log_debug ("%s: re-opened file and sought to last offset\n", */
          /*            __func__); */
          rc = _keybox_read_blob (NULL, hd->fp, NULL);
          if (rc)
            {
              log_debug ("%s: skipping last found blob failed: %s\n",
                         __func__, gpg_strerror (rc));
              xfree (sn_array);
              return gpg_error (GPG_ERR_NOTHING_FOUND);
            }
        }
    }

  /* Kludge: We need to convert an SN given as hexstring to its binary
     representation - in some cases we are not able to store it in the
     search descriptor, because due to the way we use it, it is not
     possible to free allocated memory. */
  if (sn_array)
    {
      const unsigned char *s;
      int i, odd;
      size_t snlen;

      for (n=0; n < ndesc; n++)
        {
          if (!desc[n].sn)
            ;
          else if (desc[n].snlen == -1)
            {
              unsigned char *sn;

              s = desc[n].sn;
              for (i=0; *s && *s != '/'; s++, i++)
                ;
              odd = (i & 1);
              snlen = (i+1)/2;
              sn_array[n].sn = xtrymalloc (snlen);
              if (!sn_array[n].sn)
                {
                  hd->error = gpg_error_from_syserror ();
                  release_sn_array (sn_array, n);
                  return hd->error;
                }
              sn_array[n].snlen = snlen;
              sn = sn_array[n].sn;
              s = desc[n].sn;
              if (odd)
                {
                  *sn++ = xtoi_1 (s);
                  s++;
                }
              for (; *s && *s != '/';  s += 2)
                *sn++ = xtoi_2 (s);
            }
          else
            {
              const unsigned char *sn;

              sn = desc[n].sn;
              snlen = desc[n].snlen;
              sn_array[n].sn = xtrymalloc (snlen);
              if (!sn_array[n].sn)
                {
                  hd->error = gpg_error_from_syserror ();
                  release_sn_array (sn_array, n);
                  return hd->error;
                }
              sn_array[n].snlen = snlen;
              memcpy (sn_array[n].sn, sn, snlen);
            }
        }
    }


  pk_no = uid_no = 0;
  for (;;)
    {
      unsigned int blobflags;
      int blobtype;

      _keybox_release_blob (blob); blob = NULL;
      rc = _keybox_read_blob (&blob, hd->fp, NULL);
      if (gpg_err_code (rc) == GPG_ERR_TOO_LARGE
          && gpg_err_source (rc) == GPG_ERR_SOURCE_KEYBOX)
        {
          ++*r_skipped;
          continue; /* Skip too large records.  */
        }

      if (rc)
        break;

      blobtype = blob_get_type (blob);
      if (blobtype == KEYBOX_BLOBTYPE_HEADER)
        continue;
      if (want_blobtype && blobtype != want_blobtype)
        continue;

      blobflags = blob_get_blob_flags (blob);
      if (!hd->ephemeral && (blobflags & 2))
        continue; /* Not in ephemeral mode but blob is flagged ephemeral.  */

      for (n=0; n < ndesc; n++)
        {
          switch (desc[n].mode)
            {
            case KEYDB_SEARCH_MODE_NONE:
              never_reached ();
              break;
            case KEYDB_SEARCH_MODE_EXACT:
              uid_no = has_username (blob, desc[n].u.name, 0);
              if (uid_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_MAIL:
              uid_no = has_mail (blob, desc[n].u.name, 0);
              if (uid_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_MAILSUB:
              uid_no = has_mail (blob, desc[n].u.name, 1);
              if (uid_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_SUBSTR:
              uid_no =  has_username (blob, desc[n].u.name, 1);
              if (uid_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_MAILEND:
            case KEYDB_SEARCH_MODE_WORDS:
              /* not yet implemented */
              break;
            case KEYDB_SEARCH_MODE_ISSUER:
              if (has_issuer (blob, desc[n].u.name))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_ISSUER_SN:
              if (has_issuer_sn (blob, desc[n].u.name,
                                 sn_array? sn_array[n].sn : desc[n].sn,
                                 sn_array? sn_array[n].snlen : desc[n].snlen))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_SN:
              if (has_sn (blob, sn_array? sn_array[n].sn : desc[n].sn,
                                sn_array? sn_array[n].snlen : desc[n].snlen))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_SUBJECT:
              if (has_subject (blob, desc[n].u.name))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_SHORT_KID:
              pk_no = has_short_kid (blob, desc[n].u.kid[1]);
              if (pk_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_LONG_KID:
              pk_no = has_long_kid (blob, desc[n].u.kid[0], desc[n].u.kid[1]);
              if (pk_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_FPR:
            case KEYDB_SEARCH_MODE_FPR20:
              pk_no = has_fingerprint (blob, desc[n].u.fpr);
              if (pk_no)
                goto found;
              break;
            case KEYDB_SEARCH_MODE_KEYGRIP:
              if (has_keygrip (blob, desc[n].u.grip))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_FIRST:
              goto found;
              break;
            case KEYDB_SEARCH_MODE_NEXT:
              goto found;
              break;
            default:
              rc = gpg_error (GPG_ERR_INV_VALUE);
              goto found;
            }
	}
      continue;
    found:
      /* Record which DESC we matched on.  Note this value is only
	 meaningful if this function returns with no errors. */
      if(r_descindex)
	*r_descindex = n;
      for (n=any_skip?0:ndesc; n < ndesc; n++)
        {
          u32 kid[2];

          if (desc[n].skipfnc
              && blob_get_first_keyid (blob, kid)
	      && desc[n].skipfnc (desc[n].skipfncvalue, kid, uid_no))
		break;
        }
      if (n == ndesc)
        break; /* got it */
    }

  if (!rc)
    {
      hd->found.blob = blob;
      hd->found.pk_no = pk_no;
      hd->found.uid_no = uid_no;
    }
  else if (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
    {
      _keybox_release_blob (blob);
      hd->eof = 1;
    }
  else
    {
      _keybox_release_blob (blob);
      hd->error = rc;
    }

  if (sn_array)
    release_sn_array (sn_array, ndesc);

  return rc;
}




/*
   Functions to return a certificate or a keyblock.  To be used after
   a successful search operation.
*/


/* Return the last found keyblock.  Returns 0 on success and stores a
 * new iobuf at R_IOBUF.  R_UID_NO and R_PK_NO are used to retun the
 * number of the key or user id which was matched the search criteria;
 * if not known they are set to 0. */
gpg_error_t
keybox_get_keyblock (KEYBOX_HANDLE hd, iobuf_t *r_iobuf,
                     int *r_pk_no, int *r_uid_no)
{
  gpg_error_t err;
  const unsigned char *buffer;
  size_t length;
  size_t image_off, image_len;
  size_t siginfo_off, siginfo_len;

  *r_iobuf = NULL;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);

  if (blob_get_type (hd->found.blob) != KEYBOX_BLOBTYPE_PGP)
    return gpg_error (GPG_ERR_WRONG_BLOB_TYPE);

  buffer = _keybox_get_blob_image (hd->found.blob, &length);
  if (length < 40)
    return gpg_error (GPG_ERR_TOO_SHORT);
  image_off = get32 (buffer+8);
  image_len = get32 (buffer+12);
  if ((uint64_t)image_off+(uint64_t)image_len > (uint64_t)length)
    return gpg_error (GPG_ERR_TOO_SHORT);

  err = _keybox_get_flag_location (buffer, length, KEYBOX_FLAG_SIG_INFO,
                                   &siginfo_off, &siginfo_len);
  if (err)
    return err;

  *r_pk_no  = hd->found.pk_no;
  *r_uid_no = hd->found.uid_no;
  *r_iobuf = iobuf_temp_with_content (buffer+image_off, image_len);
  return 0;
}


#ifdef KEYBOX_WITH_X509
/*
  Return the last found cert.  Caller must free it.
 */
int
keybox_get_cert (KEYBOX_HANDLE hd, ksba_cert_t *r_cert)
{
  const unsigned char *buffer;
  size_t length;
  size_t cert_off, cert_len;
  ksba_reader_t reader = NULL;
  ksba_cert_t cert = NULL;
  unsigned int blobflags;
  int rc;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);

  if (blob_get_type (hd->found.blob) != KEYBOX_BLOBTYPE_X509)
    return gpg_error (GPG_ERR_WRONG_BLOB_TYPE);

  buffer = _keybox_get_blob_image (hd->found.blob, &length);
  if (length < 40)
    return gpg_error (GPG_ERR_TOO_SHORT);
  cert_off = get32 (buffer+8);
  cert_len = get32 (buffer+12);
  if ((uint64_t)cert_off+(uint64_t)cert_len > (uint64_t)length)
    return gpg_error (GPG_ERR_TOO_SHORT);

  rc = ksba_reader_new (&reader);
  if (rc)
    return rc;
  rc = ksba_reader_set_mem (reader, buffer+cert_off, cert_len);
  if (rc)
    {
      ksba_reader_release (reader);
      /* fixme: need to map the error codes */
      return gpg_error (GPG_ERR_GENERAL);
    }

  rc = ksba_cert_new (&cert);
  if (rc)
    {
      ksba_reader_release (reader);
      return rc;
    }

  rc = ksba_cert_read_der (cert, reader);
  if (rc)
    {
      ksba_cert_release (cert);
      ksba_reader_release (reader);
      /* fixme: need to map the error codes */
      return gpg_error (GPG_ERR_GENERAL);
    }

  rc = get_flag_from_image (buffer, length, KEYBOX_FLAG_BLOB, &blobflags);
  if (!rc)
    rc = ksba_cert_set_user_data (cert, "keydb.blobflags",
                                  &blobflags, sizeof blobflags);
  if (rc)
    {
      ksba_cert_release (cert);
      ksba_reader_release (reader);
      return gpg_error (rc);
    }

  *r_cert = cert;
  ksba_reader_release (reader);
  return 0;
}

#endif /*KEYBOX_WITH_X509*/

/* Return the flags named WHAT at the address of VALUE. IDX is used
   only for certain flags and should be 0 if not required. */
int
keybox_get_flags (KEYBOX_HANDLE hd, int what, int idx, unsigned int *value)
{
  const unsigned char *buffer;
  size_t length;
  gpg_err_code_t ec;

  (void)idx; /* Not yet used.  */

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);

  buffer = _keybox_get_blob_image (hd->found.blob, &length);
  ec = get_flag_from_image (buffer, length, what, value);
  return ec? gpg_error (ec):0;
}

off_t
keybox_offset (KEYBOX_HANDLE hd)
{
  if (!hd->fp)
    return 0;
  return es_ftello (hd->fp);
}

gpg_error_t
keybox_seek (KEYBOX_HANDLE hd, off_t offset)
{
  gpg_error_t err;

  if (hd->error)
    return hd->error; /* still in error state */

  if (! hd->fp)
    {
      if (!offset)
        {
          /* No need to open the file.  An unopened file is effectively at
             offset 0.  */
          return 0;
        }

      err = _keybox_ll_open (&hd->fp, hd->kb->fname, 0);
      if (err)
        return err;
    }

  err = es_fseeko (hd->fp, offset, SEEK_SET);
  hd->error = gpg_error_from_errno (err);

  return hd->error;
}
