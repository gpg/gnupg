/* keybox-search.c - Search operations
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "../jnlib/stringhelp.h" /* ascii_xxxx() */
#include "keybox-defs.h"

#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

struct sn_array_s {
    int snlen;
    unsigned char *sn;
};



static ulong
get32 (const byte *buffer)
{
  ulong a;
  a =  *buffer << 24;
  a |= buffer[1] << 16;
  a |= buffer[2] << 8;
  a |= buffer[3];
  return a;
}

static ulong
get16 (const byte *buffer)
{
  ulong a;
  a =  *buffer << 8;
  a |= buffer[1];
  return a;
}



static int
blob_get_type (KEYBOXBLOB blob)
{
  const unsigned char *buffer;
  size_t length;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 40)
    return -1; /* blob too short */

  return buffer[4];
}

static unsigned int
blob_get_blob_flags (KEYBOXBLOB blob)
{
  const unsigned char *buffer;
  size_t length;

  buffer = _keybox_get_blob_image (blob, &length);
  if (length < 8)
    return 0; /* oops */

  return get16 (buffer + 6);
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
  if (pos + keyinfolen*nkeys > length)
    return 0; /* out of bounds */

  for (idx=0; idx < nkeys; idx++)
    {
      off = pos + idx*keyinfolen;
      if (!memcmp (buffer + off, fpr, 20))
        return 1; /* found */
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
  if (pos + keyinfolen*nkeys > length)
    return 0; /* out of bounds */

  for (idx=0; idx < nkeys; idx++)
    {
      off = pos + idx*keyinfolen;
      if (!memcmp (buffer + off + fproff, fpr, fprlen))
        return 1; /* found */
    }
  return 0; /* not found */
}


static int
blob_cmp_name (KEYBOXBLOB blob, int idx,
               const char *name, size_t namelen, int substr)
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

  if (idx < 0)
    { /* compare all names starting with that (negated) index */
      idx = -idx;
      
      for ( ;idx < nuids; idx++)
        {
          size_t mypos = pos;

          mypos += idx*uidinfolen;
          off = get32 (buffer+mypos);
          len = get32 (buffer+mypos+4);
          if (off+len > length)
            return 0; /* error: better stop here out of bounds */
          if (len < 1)
            continue; /* empty name */
          if (substr)
            {
              if (ascii_memcasemem (buffer+off, len, name, namelen))
                return 1; /* found */
            }
          else
            {
              if (len == namelen && !memcmp (buffer+off, name, len))
                return 1; /* found */
            }
        }
      return 0; /* not found */
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
          return !!ascii_memcasemem (buffer+off, len, name, namelen);
        }
      else
        {
          return len == namelen && !memcmp (buffer+off, name, len);
        }
    }
}


/* compare all email addresses of the subject.  With SUBSTR given as
   True a substring search is done in the mail address */
static int
blob_cmp_mail (KEYBOXBLOB blob, const char *name, size_t namelen, int substr)
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

  for (idx=1 ;idx < nuids; idx++)
    {
      size_t mypos = pos;
      
      mypos += idx*uidinfolen;
      off = get32 (buffer+mypos);
      len = get32 (buffer+mypos+4);
      if (off+len > length)
        return 0; /* error: better stop here out of bounds */
      if (len < 2 || buffer[off] != '<')
        continue; /* empty name or trailing 0 not stored */
      len--; /* one back */
      if ( len < 3 || buffer[off+len] != '>')
        continue; /* not a proper email address */
      len--; 
      if (substr)
        {
          if (ascii_memcasemem (buffer+off+1, len, name, namelen))
            return 1; /* found */
        }
      else
        {
          if (len == namelen && !ascii_memcasecmp (buffer+off+1, name, len))
            return 1; /* found */
        }
    }
  return 0; /* not found */
}




/*
  The has_foo functions are used as helpers for search 
*/
static int
has_short_kid (KEYBOXBLOB blob, const unsigned char *kid)
{
  return blob_cmp_fpr_part (blob, kid+4, 16, 4);
}

static int
has_long_kid (KEYBOXBLOB blob, const unsigned char *kid)
{
  return blob_cmp_fpr_part (blob, kid, 12, 8);
}

static int
has_fingerprint (KEYBOXBLOB blob, const unsigned char *fpr)
{
  return blob_cmp_fpr (blob, fpr);
}


static int
has_issuer (KEYBOXBLOB blob, const char *name)
{
  size_t namelen;

  return_val_if_fail (name, 0);

  if (blob_get_type (blob) != BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  return blob_cmp_name (blob, 0 /* issuer */, name, namelen, 0);
}

static int
has_issuer_sn (KEYBOXBLOB blob, const char *name,
               const unsigned char *sn, int snlen)
{
  size_t namelen;

  return_val_if_fail (name, 0);
  return_val_if_fail (sn, 0);

  if (blob_get_type (blob) != BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  
  return (blob_cmp_sn (blob, sn, snlen)
          && blob_cmp_name (blob, 0 /* issuer */, name, namelen, 0));
}

static int
has_sn (KEYBOXBLOB blob, const unsigned char *sn, int snlen)
{
  return_val_if_fail (sn, 0);

  if (blob_get_type (blob) != BLOBTYPE_X509)
    return 0;
  return blob_cmp_sn (blob, sn, snlen);
}

static int
has_subject (KEYBOXBLOB blob, const char *name)
{
  size_t namelen;

  return_val_if_fail (name, 0);

  if (blob_get_type (blob) != BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  return blob_cmp_name (blob, 1 /* subject */, name, namelen, 0);
}

static int
has_subject_or_alt (KEYBOXBLOB blob, const char *name, int substr)
{
  size_t namelen;

  return_val_if_fail (name, 0);

  if (blob_get_type (blob) != BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  return blob_cmp_name (blob, -1 /* all subject names*/, name,
                        namelen, substr);
}


static int
has_mail (KEYBOXBLOB blob, const char *name, int substr)
{
  size_t namelen;

  return_val_if_fail (name, 0);

  if (blob_get_type (blob) != BLOBTYPE_X509)
    return 0;

  namelen = strlen (name);
  if (namelen && name[namelen-1] == '>')
    namelen--;
  return blob_cmp_mail (blob, name, namelen, substr);
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

  The search API

*/

int 
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
      fclose (hd->fp);
      hd->fp = NULL;
    }
  hd->error = 0;
  hd->eof = 0;
  return 0;   
}


/* Note: When in ephemeral mode the search function does visit all
   blobs but in standard mode, blobs flagged as ephemeral are ignored.  */
int 
keybox_search (KEYBOX_HANDLE hd, KEYBOX_SEARCH_DESC *desc, size_t ndesc)
{
  int rc;
  size_t n;
  int need_words, any_skip;
  KEYBOXBLOB blob = NULL;
  struct sn_array_s *sn_array = NULL;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* clear last found result */
  if (hd->found.blob)
    {
      _keybox_release_blob (hd->found.blob);
      hd->found.blob = NULL;
    }

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
            return (hd->error = gpg_error (gpg_err_code_from_errno (errno)));
        }
    }

  if (!hd->fp)
    {
      hd->fp = fopen (hd->kb->fname, "rb");
      if (!hd->fp)
        {
          hd->error = gpg_error (gpg_err_code_from_errno (errno));
          xfree (sn_array);
          return hd->error;
        }
    }

  /* kludge: we need to convert an SN given as hexstring to it's
     binary representation - in some cases we are not able to store it
     in the search descriptor, because due to its usgae it is not
     possible to free allocated memory */
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
                  hd->error = gpg_error (gpg_err_code_from_errno (errno));
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
                  hd->error = gpg_error (gpg_err_code_from_errno (errno));
                  release_sn_array (sn_array, n);
                  return hd->error;
                }
              sn_array[n].snlen = snlen;
              memcpy (sn_array[n].sn, sn, snlen);
            }
        }
    }


  for (;;)
    {
      unsigned int blobflags;

      _keybox_release_blob (blob); blob = NULL;
      rc = _keybox_read_blob (&blob, hd->fp);
      if (rc)
        break;

      blobflags = blob_get_blob_flags (blob);
      if (!hd->ephemeral && (blobflags & 2))
        continue; /* not in ephemeral mode but blob is flagged ephemeral */

      for (n=0; n < ndesc; n++) 
        {
          switch (desc[n].mode)
            {
            case KEYDB_SEARCH_MODE_NONE: 
              never_reached ();
              break;
            case KEYDB_SEARCH_MODE_EXACT: 
              if (has_subject_or_alt (blob, desc[n].u.name, 0))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_MAIL:
              if (has_mail (blob, desc[n].u.name, 0))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_MAILSUB:
              if (has_mail (blob, desc[n].u.name, 1))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_SUBSTR:
              if (has_subject_or_alt (blob, desc[n].u.name, 1))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_MAILEND:
            case KEYDB_SEARCH_MODE_WORDS: 
              never_reached (); /* not yet implemented */
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
              if (has_short_kid (blob, desc[n].u.kid))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_LONG_KID:
              if (has_long_kid (blob, desc[n].u.kid))
                goto found;
              break;
            case KEYDB_SEARCH_MODE_FPR:
            case KEYDB_SEARCH_MODE_FPR20:
              if (has_fingerprint (blob, desc[n].u.fpr))
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
      for (n=any_skip?0:ndesc; n < ndesc; n++) 
        {
/*            if (desc[n].skipfnc */
/*                && desc[n].skipfnc (desc[n].skipfncvalue, aki)) */
/*              break; */
        }
      if (n == ndesc)
        break; /* got it */
    }
  
  if (!rc)
    {
      hd->found.blob = blob;
    }
  else if (rc == -1)
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
#ifdef KEYBOX_WITH_X509
/*
  Return the last found cert.  Caller must free it.
 */
int
keybox_get_cert (KEYBOX_HANDLE hd, KsbaCert *r_cert)
{
  const unsigned char *buffer;
  size_t length;
  size_t cert_off, cert_len;
  KsbaReader reader = NULL;
  KsbaCert cert = NULL;
  int rc;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);

  if (blob_get_type (hd->found.blob) != BLOBTYPE_X509)
    return gpg_error (GPG_ERR_WRONG_BLOB_TYPE);

  buffer = _keybox_get_blob_image (hd->found.blob, &length);
  if (length < 40)
    return gpg_error (GPG_ERR_TOO_SHORT);
  cert_off = get32 (buffer+8);
  cert_len = get32 (buffer+12);
  if (cert_off+cert_len > length)
    return gpg_error (GPG_ERR_TOO_SHORT);

  reader = ksba_reader_new ();
  if (!reader)
    return gpg_error (GPG_ERR_ENOMEM);
  rc = ksba_reader_set_mem (reader, buffer+cert_off, cert_len);
  if (rc)
    {
      ksba_reader_release (reader);
      /* fixme: need to map the error codes */
      return gpg_error (GPG_ERR_GENERAL);
    }

  cert = ksba_cert_new ();
  if (!cert)
    {
      ksba_reader_release (reader);
      return gpg_error (GPG_ERR_ENOMEM);
    }

  rc = ksba_cert_read_der (cert, reader);
  if (rc)
    {
      ksba_cert_release (cert);
      ksba_reader_release (reader);
      /* fixme: need to map the error codes */
      return gpg_error (GPG_ERR_GENERAL);
    }

  *r_cert = cert;
  ksba_reader_release (reader);
  return 0;
}

#endif /*KEYBOX_WITH_X509*/
