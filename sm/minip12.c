/* minip12.c - A minimal pkcs-12 implementation.
 * Copyright (C) 2002, 2003, 2004, 2006, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2022, 2023 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* References:
 * RFC-7292 - PKCS #12: Personal Information Exchange Syntax v1.1
 * RFC-8351 - The PKCS #8 EncryptedPrivateKeyInfo Media Type
 * RFC-5958 - Asymmetric Key Packages
 * RFC-3447 - PKCS  #1: RSA Cryptography Specifications Version 2.1
 * RFC-5915 - Elliptic Curve Private Key Structure
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <errno.h>

#include <ksba.h>

#include "../common/util.h"
#include "../common/logging.h"
#include "../common/utf8conv.h"
#include "../common/tlv.h"
#include "../common/openpgpdefs.h" /* Only for openpgp_curve_to_oid.  */
#include "minip12.h"

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

/* Enable the next macro to dump stuff for debugging.  */
#undef ENABLE_DER_STRUCT_DUMPING


static unsigned char const oid_data[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static unsigned char const oid_encryptedData[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06 };
static unsigned char const oid_pkcs_12_keyBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01 };
static unsigned char const oid_pkcs_12_pkcs_8ShroudedKeyBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02 };
static unsigned char const oid_pkcs_12_CertBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03 };
static unsigned char const oid_pkcs_12_CrlBag[11] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x04 };

static unsigned char const oid_pbeWithSHAAnd3_KeyTripleDES_CBC[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03 };
static unsigned char const oid_pbeWithSHAAnd40BitRC2_CBC[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06 };
static unsigned char const oid_x509Certificate_for_pkcs_12[10] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01 };

static unsigned char const oid_pkcs5PBKDF2[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
static unsigned char const oid_pkcs5PBES2[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };
static unsigned char const oid_aes128_CBC[9] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
static unsigned char const oid_aes256_CBC[9] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A };

static unsigned char const oid_hmacWithSHA1[8] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07 };
static unsigned char const oid_hmacWithSHA224[8] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08 };
static unsigned char const oid_hmacWithSHA256[8] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09 };
static unsigned char const oid_hmacWithSHA384[8] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A };
static unsigned char const oid_hmacWithSHA512[8] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B };

static unsigned char const oid_rsaEncryption[9] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static unsigned char const oid_pcPublicKey[7] = {
  0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

static unsigned char const data_3desiter2048[30] = {
  0x30, 0x1C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86,
  0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03, 0x30, 0x0E,
  0x04, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0x02, 0x02, 0x08, 0x00 };
#define DATA_3DESITER2048_SALT_OFF  18

static unsigned char const data_rc2iter2048[30] = {
  0x30, 0x1C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86,
  0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06, 0x30, 0x0E,
  0x04, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0x02, 0x02, 0x08, 0x00 };
#define DATA_RC2ITER2048_SALT_OFF  18

static unsigned char const data_mactemplate[51] = {
  0x30, 0x31, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
  0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
  0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x08, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
  0x02, 0x08, 0x00 };
#define DATA_MACTEMPLATE_MAC_OFF 17
#define DATA_MACTEMPLATE_SALT_OFF 39

/* Note that the BMP String in this template reads:
 * "GnuPG exported certificate ffffffff"  */
static unsigned char const data_attrtemplate[106] = {
  0x31, 0x7c, 0x30, 0x55, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14, 0x31,
  0x48, 0x1e, 0x46, 0x00, 0x47, 0x00, 0x6e, 0x00,
  0x75, 0x00, 0x50, 0x00, 0x47, 0x00, 0x20, 0x00,
  0x65, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6f, 0x00,
  0x72, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00,
  0x20, 0x00, 0x63, 0x00, 0x65, 0x00, 0x72, 0x00,
  0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00,
  0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00,
  0x20, 0x00, 0x66, 0x00, 0x66, 0x00, 0x66, 0x00,
  0x66, 0x00, 0x66, 0x00, 0x66, 0x00, 0x66, 0x00,
  0x66, 0x30, 0x23, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15, 0x31, 0x16,
  0x04, 0x14 }; /* Need to append SHA-1 digest. */
#define DATA_ATTRTEMPLATE_KEYID_OFF 73

struct buffer_s
{
  unsigned char *buffer;
  size_t length;
};


struct tag_info
{
  int class;
  int is_constructed;
  unsigned long tag;
  size_t length;         /* length part of the TLV */
  size_t nhdr;
  int ndef;              /* It is an indefinite length */
};


#define TLV_MAX_DEPTH 20


struct bufferlist_s
{
  struct bufferlist_s *next;
  char *buffer;
};


/* An object to control the ASN.1 parsing.  */
struct tlv_ctx_s
{
  /* The orginal buffer with the entire pkcs#12 object and its length.  */
  const unsigned char *origbuffer;
  size_t origbufsize;

  /* The current buffer we are working on and its length. */
  const unsigned char *buffer;
  size_t bufsize;

  int in_ndef;         /* Flag indicating that we are in a NDEF. */
  int pending;         /* The last tlv_next has not yet been processed.  */

  struct tag_info ti;  /* The current tag.  */
  gpg_error_t lasterr; /* Last error from tlv function.  */
  const char *lastfunc;/* Name of last called function.  */

  struct bufferlist_s *bufferlist;  /* To keep track of malloced buffers. */

  unsigned int stacklen; /* Used size of the stack.  */
  struct {
    const unsigned char *buffer;  /* Saved value of BUFFER.   */
    size_t bufsize;               /* Saved value of BUFSIZE.  */
    size_t length;                /* Length of the container (ti.length). */
    int    in_ndef;               /* Saved IN_NDEF flag (ti.ndef).        */
  } stack[TLV_MAX_DEPTH];
};


/* Parser communication object.  */
struct p12_parse_ctx_s
{
  /* The callback for parsed certificates and its arg.  */
  void (*certcb)(void*, const unsigned char*, size_t);
  void *certcbarg;

  /* The supplied parseword.  */
  const char *password;

  /* Set to true if the password was wrong.  */
  int badpass;

  /* Malloced name of the curve.  */
  char *curve;

  /* The private key as an MPI array.   */
  gcry_mpi_t *privatekey;
};


static int opt_verbose;


static unsigned char *cram_octet_string (const unsigned char *input,
                                         size_t length, size_t *r_newlength);
static int need_octet_string_cramming (const unsigned char *input,
                                       size_t length);




void
p12_set_verbosity (int verbose, int debug)
{
  opt_verbose = !!verbose;
  if (debug)
    opt_verbose = 2;
}


#define dump_tag_info(a,b) _dump_tag_info ((a),__LINE__,(b))
static void
_dump_tag_info (const char *text, int lno, struct tlv_ctx_s *tlv)
{
  struct tag_info *ti;

  if (opt_verbose < 2)
    return;

  ti = &tlv->ti;

  log_debug ("p12_parse:%s:%d: @%04zu class=%d tag=%lu len=%zu nhdr=%zu %s%s\n",
             text, lno,
             (size_t)(tlv->buffer - tlv->origbuffer) - ti->nhdr,
             ti->class, ti->tag, ti->length, ti->nhdr,
             ti->is_constructed?" cons":"",
             ti->ndef?" ndef":"");
}


#define dump_tlv_ctx(a,b,c) _dump_tlv_ctx ((a),(b),__LINE__,(c))
static void
_dump_tlv_ctx (const char *text, const char *text2,
              int lno, struct tlv_ctx_s *tlv)
{
  if (opt_verbose < 2)
    return;

  log_debug ("p12_parse:%s%s%s:%d: @%04zu lvl=%u %s\n",
             text,
             text2? "/":"", text2? text2:"",
             lno,
             (size_t)(tlv->buffer - tlv->origbuffer),
             tlv->stacklen,
             tlv->in_ndef? " in-ndef":"");
}


static int
digest_algo_from_oid (unsigned char const *oid, size_t oidlen)
{
  int algo;

  if (oidlen == DIM(oid_hmacWithSHA1) &&
      !memcmp (oid, oid_hmacWithSHA1, oidlen))
    algo = GCRY_MD_SHA1;
  else if (oidlen == DIM(oid_hmacWithSHA224) &&
           !memcmp (oid, oid_hmacWithSHA224, oidlen))
    algo = GCRY_MD_SHA224;
  else if (oidlen == DIM(oid_hmacWithSHA256) &&
           !memcmp (oid, oid_hmacWithSHA256, oidlen))
    algo = GCRY_MD_SHA256;
  else if (oidlen == DIM(oid_hmacWithSHA384) &&
           !memcmp (oid, oid_hmacWithSHA384, oidlen))
    algo = GCRY_MD_SHA384;
  else if (oidlen == DIM(oid_hmacWithSHA512) &&
           !memcmp (oid, oid_hmacWithSHA512, oidlen))
    algo = GCRY_MD_SHA512;
  else
    algo = 0;
  return algo;
}


/* Wrapper around tlv_builder_add_ptr to add an OID.  When we
 * eventually put the whole tlv_builder stuff into Libksba, we can add
 * such a function there.  Right now we don't do this to avoid a
 * dependency on Libksba.  Function return 1 on error.  */
static int
builder_add_oid (tlv_builder_t tb, int class, const char *oid)
{
  gpg_error_t err;
  unsigned char *der;
  size_t derlen;

  err = ksba_oid_from_str (oid, &der, &derlen);
  if (err)
    {
      log_error ("%s: error converting '%s' to DER: %s\n",
                 __func__, oid, gpg_strerror (err));
      return 1;
    }

  tlv_builder_add_val (tb, class, TAG_OBJECT_ID, der, derlen);
  ksba_free (der);
  return 0;
}


/* Wrapper around tlv_builder_add_ptr to add an MPI.  TAG may either
 * be OCTET_STRING or BIT_STRING.  When we eventually put the whole
 * tlv_builder stuff into Libksba, we can add such a function there.
 * Right now we don't do this to avoid a dependency on Libksba.
 * Function return 1 on error.  STRIP is a hack to remove the first
 * octet from the value. */
static int
builder_add_mpi (tlv_builder_t tb, int class, int tag, gcry_mpi_t mpi,
                 int strip)
{
  int returncode;
  gpg_error_t err;
  const unsigned char *s;
  unsigned char *freethis = NULL;
  unsigned char *freethis2 = NULL;
  unsigned int nbits;
  size_t n;

  if (gcry_mpi_get_flag (mpi, GCRYMPI_FLAG_OPAQUE))
    {
      s = gcry_mpi_get_opaque (mpi, &nbits);
      n = (nbits+7)/8;
    }
  else
    {
      err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &freethis, &n, mpi);
      if (err)
        {
          log_error ("%s: error converting MPI: %s\n",
                     __func__, gpg_strerror (err));
          returncode = 1;
          goto leave;
        }
      s = freethis;
    }

  if (tag == TAG_BIT_STRING)
    {
      freethis2 = xtrymalloc_secure (n + 1);
      if (!freethis2)
        {
          err = gpg_error_from_syserror ();
          log_error ("%s: error converting MPI: %s\n",
                     __func__, gpg_strerror (err));
          returncode = 1;
          goto leave;
        }
      freethis2[0] = 0;
      memcpy (freethis2+1, s, n);
      s = freethis2;
      n++;
    }

  strip = !!strip;
  if (strip && n < 2)
    strip = 0;

  tlv_builder_add_val (tb, class, tag, s+strip, n-strip);
  returncode = 0;

 leave:
  xfree (freethis);
  xfree (freethis2);
  return returncode;
}



/* Parse the buffer at the address BUFFER which is of SIZE and return
 * the tag and the length part from the TLV triplet.  Update BUFFER
 * and SIZE on success.  Checks that the encoded length does not
 * exhaust the length of the provided buffer.  */
static int
parse_tag (unsigned char const **buffer, size_t *size, struct tag_info *ti)
{
  gpg_error_t err;
  int tag;

  err = parse_ber_header (buffer, size,
                          &ti->class, &tag,
                          &ti->is_constructed, &ti->ndef,
                          &ti->length, &ti->nhdr);
  if (err)
    return err;
  if (tag < 0)
    return gpg_error (GPG_ERR_EOVERFLOW);
  ti->tag = tag;

  if (ti->length > *size)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT); /* data larger than buffer. */

  return 0;
}


/* Create a new TLV object.  */
static struct tlv_ctx_s *
tlv_new (const unsigned char *buffer, size_t bufsize)
{
  struct tlv_ctx_s *tlv;
  tlv = xtrycalloc (1, sizeof *tlv);
  if (tlv)
    {
      tlv->origbuffer = buffer;
      tlv->origbufsize = bufsize;
      tlv->buffer = buffer;
      tlv->bufsize = bufsize;
    }
  return tlv;
}


/* This function can be used to store a malloced buffer into the TLV
 * object.  Ownership of BUFFER is thus transferred to TLV.  This
 * buffer will then only be released by tlv_release. */
static gpg_error_t
tlv_register_buffer (struct tlv_ctx_s *tlv, char *buffer)
{
  struct bufferlist_s *item;

  item = xtrycalloc (1, sizeof *item);
  if (!item)
    return gpg_error_from_syserror ();
  item->buffer = buffer;
  item->next = tlv->bufferlist;
  tlv->bufferlist = item;
  return 0;
}


static void
tlv_release (struct tlv_ctx_s *tlv)
{
  if (!tlv)
    return;
  while (tlv->bufferlist)
    {
      struct bufferlist_s *save = tlv->bufferlist->next;
      xfree (tlv->bufferlist->buffer);
      xfree (tlv->bufferlist);
      tlv->bufferlist = save;
    }
  xfree (tlv);
}


/* Helper for the tlv_peek functions.  */
static gpg_error_t
_tlv_peek (struct tlv_ctx_s *tlv, struct tag_info *ti)
{
  const unsigned char *p;
  size_t n;

  /* Note that we want to peek ahead of any current container but of
   * course not beyond our entire buffer.  */
  p = tlv->buffer;
  if ((p - tlv->origbuffer) > tlv->origbufsize)
    return gpg_error (GPG_ERR_BUG);
  n = tlv->origbufsize - (p - tlv->origbuffer);
  return parse_tag (&p, &n, ti);
}


/* Look for the next tag and return true if it matches CLASS and TAG.
 * Otherwise return false.  No state is changed.  */
static int
tlv_peek (struct tlv_ctx_s *tlv, int class, int tag)
{
  struct tag_info ti;

  return (!_tlv_peek (tlv, &ti)
          && ti.class == class && ti.tag == tag);
}


/* Look for the next tag and return true if it is the Null tag.
 * Otherwise return false.  No state is changed.  */
static int
tlv_peek_null (struct tlv_ctx_s *tlv)
{
  struct tag_info ti;

  return (!_tlv_peek (tlv, &ti)
          && ti.class == CLASS_UNIVERSAL && ti.tag == TAG_NULL
          && !ti.is_constructed && !ti.length);
}


/* Helper for tlv_expect_sequence and tlv_expect_context_tag.  */
static gpg_error_t
_tlv_push (struct tlv_ctx_s *tlv)
{
  /* Right now our pointer is at the value of the current container.
   * We push that info onto the stack.  */
  if (tlv->stacklen >= TLV_MAX_DEPTH)
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_MANY));
  tlv->stack[tlv->stacklen].buffer  = tlv->buffer;
  tlv->stack[tlv->stacklen].bufsize = tlv->bufsize;
  tlv->stack[tlv->stacklen].in_ndef = tlv->in_ndef;
  tlv->stack[tlv->stacklen].length  = tlv->ti.length;
  tlv->stacklen++;

  tlv->in_ndef = tlv->ti.ndef;

  /* We set the size of the buffer to the TLV length if it is known or
   * else to the size of the remaining entire buffer.  */
  if (tlv->in_ndef)
    {
      if ((tlv->buffer - tlv->origbuffer) > tlv->origbufsize)
        return (tlv->lasterr = gpg_error (GPG_ERR_BUG));
      tlv->bufsize = tlv->origbufsize - (tlv->buffer - tlv->origbuffer);
    }
  else
    tlv->bufsize = tlv->ti.length;

  dump_tlv_ctx (__func__, NULL, tlv);
  return 0;
}


/* Helper for tlv_next.  */
static gpg_error_t
_tlv_pop (struct tlv_ctx_s *tlv)
{
  size_t lastlen;

  /* We reached the end of a container, either due to the size limit
   * or due to an end tag.  Now we pop the last container so that we
   * are positioned at the value of the last container. */
  if (!tlv->stacklen)
    return gpg_error (GPG_ERR_EOF);

  tlv->stacklen--;
  tlv->in_ndef = tlv->stack[tlv->stacklen].in_ndef;
  if (tlv->in_ndef)
    {
      /* We keep buffer but adjust bufsize to the end of the origbuffer. */
      if ((tlv->buffer - tlv->origbuffer) > tlv->origbufsize)
        return (tlv->lasterr = gpg_error (GPG_ERR_BUG));
      tlv->bufsize = tlv->origbufsize - (tlv->buffer - tlv->origbuffer);
    }
  else
    {
      lastlen      = tlv->stack[tlv->stacklen].length;
      tlv->buffer  = tlv->stack[tlv->stacklen].buffer;
      tlv->bufsize = tlv->stack[tlv->stacklen].bufsize;
      if (lastlen > tlv->bufsize)
        {
          log_debug ("%s: container length larger than buffer (%zu/%zu)\n",
                     __func__, lastlen, tlv->bufsize);
          return gpg_error (GPG_ERR_INV_BER);
        }
      tlv->buffer += lastlen;
      tlv->bufsize -= lastlen;
    }

  dump_tlv_ctx (__func__, NULL, tlv);
  return 0;
}


/* Parse the next tag and value.  Also detect the end of a
 * container. */
#define tlv_next(a) _tlv_next ((a), __LINE__)
static gpg_error_t
_tlv_next (struct tlv_ctx_s *tlv, int lno)
{
  gpg_error_t err;

  tlv->lasterr = 0;
  tlv->lastfunc = __func__;

  if (tlv->pending)
    {
      tlv->pending = 0;
      if (opt_verbose > 1)
        log_debug ("%s: tlv_next skipped\n", __func__);
      return 0;
    }

  if (opt_verbose > 1)
    log_debug ("%s: tlv_next called\n", __func__);
  /* If we are at the end of an ndef container pop the stack.  */
  if (!tlv->in_ndef && !tlv->bufsize)
    {
      do
        err = _tlv_pop (tlv);
      while (!err && !tlv->in_ndef && !tlv->bufsize);
      if (err)
        return (tlv->lasterr = err);
      if (opt_verbose > 1)
        log_debug ("%s: container(s) closed due to size\n", __func__);
    }

 again:
  /* Get the next tag.  */
  err = parse_tag (&tlv->buffer, &tlv->bufsize, &tlv->ti);
  if (err)
    {
      if (opt_verbose > 1)
        log_debug ("%s: reading tag returned err=%d\n", __func__, err);
      return err;
    }

  /* If there is an end tag in an ndef container pop the stack.  Also
   * pop other containers which are fully consumed. */
  if (tlv->in_ndef && (tlv->ti.class == CLASS_UNIVERSAL
                       && !tlv->ti.tag && !tlv->ti.is_constructed))
    {
      do
        err = _tlv_pop (tlv);
      while (!err && !tlv->in_ndef && !tlv->bufsize);
      if (err)
        return (tlv->lasterr = err);
      if (opt_verbose > 1)
        log_debug ("%s: container(s) closed due to end tag\n", __func__);
      goto again;
    }

  _dump_tag_info (__func__, lno, tlv);
  return 0;
}


/* Return the current neting level of the TLV object.  */
static unsigned int
tlv_level (struct tlv_ctx_s *tlv)
{
  return tlv->stacklen;
}


/* Set a flag to indicate that the last tlv_next has not yet been
 * consumed.  */
static void
tlv_set_pending (struct tlv_ctx_s *tlv)
{
  tlv->pending = 1;
}


/* Skip over the value of the current tag.  Does not yet work for ndef
 * containers.  */
static void
tlv_skip (struct tlv_ctx_s *tlv)
{
  tlv->lastfunc = __func__;
  log_assert (tlv->bufsize >= tlv->ti.length);
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
}


/* Expect that the current tag is a sequence and setup the context for
 * processing.  */
static gpg_error_t
tlv_expect_sequence (struct tlv_ctx_s *tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_SEQUENCE
        && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return _tlv_push (tlv);
}


/* Expect that the current tag is a context tag and setup the context
 * for processing.  The tag of the context is returned at R_TAG.  */
static gpg_error_t
tlv_expect_context_tag (struct tlv_ctx_s *tlv, int *r_tag)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_CONTEXT && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  *r_tag = tlv->ti.tag;
  return _tlv_push (tlv);
}


/* Expect that the current tag is a SET and setup the context for
 * processing.  */
static gpg_error_t
tlv_expect_set (struct tlv_ctx_s *tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_SET
        && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return _tlv_push (tlv);
}


/* Expect an object of CLASS with TAG and store its value at
 * (R_DATA,R_DATALEN).  Then skip over its value to the next tag.
 * Note that the stored value is not allocated but points into
 * TLV.  */
static gpg_error_t
tlv_expect_object (struct tlv_ctx_s *tlv, int class, int tag,
                   unsigned char const **r_data, size_t *r_datalen)
{
  gpg_error_t err;
  const unsigned char *p;
  size_t n;
  int needpush = 0;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == class && tlv->ti.tag == tag))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  n = tlv->ti.length;
  if (!n && tlv->ti.ndef)
    {
      n = tlv->bufsize;
      needpush = 1;
    }
  else if (!tlv->ti.length)
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  if (class == CLASS_CONTEXT && tag == 0 && tlv->ti.is_constructed
      && need_octet_string_cramming (p, n))
    {
      char *newbuffer;

      newbuffer = cram_octet_string (p, n, r_datalen);
      if (!newbuffer)
        return (tlv->lasterr = gpg_error (GPG_ERR_BAD_BER));
      err = tlv_register_buffer (tlv, newbuffer);
      if (err)
        {
          xfree (newbuffer);
          return (tlv->lasterr = err);
        }
      *r_data = newbuffer;
    }
  else
    {
      *r_data = p;
      *r_datalen = n;
    }
  if (needpush)
    return _tlv_push (tlv);

  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  return 0;
}


/* Expect that the current tag is an object string and store its value
 * at (R_DATA,R_DATALEN).  Then skip over its value to the next tag.
 * Note that the stored value are not allocated but point into TLV.
 * If ENCAPSULATES is set the octet string is used as a new
 * container.  R_DATA and R_DATALEN are optional. */
static gpg_error_t
tlv_expect_octet_string (struct tlv_ctx_s *tlv, int encapsulates,
                         unsigned char const **r_data, size_t *r_datalen)
{
  gpg_error_t err;
  const unsigned char *p;
  size_t n;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_OCTET_STRING
        && (!tlv->ti.is_constructed || encapsulates)))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  if (!(n=tlv->ti.length) && !tlv->ti.ndef)
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  if (encapsulates && tlv->ti.is_constructed
      && need_octet_string_cramming (p, n))
    {
      char *newbuffer;

      newbuffer = cram_octet_string (p, n, r_datalen);
      if (!newbuffer)
        return (tlv->lasterr = gpg_error (GPG_ERR_BAD_BER));
      err = tlv_register_buffer (tlv, newbuffer);
      if (err)
        {
          xfree (newbuffer);
          return (tlv->lasterr = err);
        }
      *r_data = newbuffer;
    }
  else
    {
      if (r_data)
        *r_data = p;
      if (r_datalen)
        *r_datalen = tlv->ti.length;
    }
  if (encapsulates)
    return _tlv_push (tlv);

  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  return 0;
}


/* Expect that the current tag is an integer and return its value at
 * R_VALUE.  Then skip over its value to the next tag. */
static gpg_error_t
tlv_expect_integer (struct tlv_ctx_s *tlv, int *r_value)
{
  const unsigned char *p;
  size_t n;
  int value;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_INTEGER
        && !tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  if (!(n=tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  /* We currently support only positive values.  */
  if ((*p & 0x80))
    return (tlv->lasterr = gpg_error (GPG_ERR_ERANGE));

  for (value = 0; n; n--)
    {
      value <<= 8;
      value |= (*p++) & 0xff;
      if (value < 0)
        return (tlv->lasterr = gpg_error (GPG_ERR_EOVERFLOW));
    }
  *r_value = value;
  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  return 0;
}


/* Variant of tlv_expect_integer which returns an MPI.  If IGNORE_ZERO
 * is set a value of 0 is ignored and R_VALUE not changed and the
 * function returns GPG_ERR_FALSE.  No check for negative encoded
 * integers is doe because the old code here worked the same and we
 * can't foreclose invalid encoded PKCS#12 stuff - after all it is
 * PKCS#12 see https://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html */
static gpg_error_t
tlv_expect_mpinteger (struct tlv_ctx_s *tlv, int ignore_zero,
                      gcry_mpi_t *r_value)
{
  const unsigned char *p;
  size_t n;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_INTEGER
        && !tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  if (!(n=tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  if (ignore_zero && n == 1 && !*p)
    return gpg_error (GPG_ERR_FALSE);

  return gcry_mpi_scan (r_value, GCRYMPI_FMT_USG, p, n, NULL);
}


/* Expect that the current tag is an object id and store its value at
 * (R_OID,R_OIDLEN).  Then skip over its value to the next tag.  Note
 * that the stored value is not allocated but points into TLV. */
static gpg_error_t
tlv_expect_object_id (struct tlv_ctx_s *tlv,
                      unsigned char const **r_oid, size_t *r_oidlen)
{
  const unsigned char *p;
  size_t n;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_OBJECT_ID
        && !tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  if (!(n=tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  *r_oid = p;
  *r_oidlen = tlv->ti.length;
  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  return 0;
}



/* Given an ASN.1 chunk of a structure like:
 *
 *   24 NDEF:       OCTET STRING  -- This is not passed to us
 *   04    1:         OCTET STRING  -- INPUT point s to here
 *          :           30
 *   04    1:         OCTET STRING
 *          :           80
 *        [...]
 *   04    2:         OCTET STRING
 *          :           00 00
 *          :         } -- This denotes a Null tag and are the last
 *                      -- two bytes in INPUT.
 *
 * The example is from Mozilla Firefox 1.0.4 which actually exports
 * certs as single byte chunks of octet strings.
 *
 * Create a new buffer with the content of that octet string.  INPUT
 * is the original buffer with a LENGTH.  Returns
 * NULL on error or a new malloced buffer with its actual used length
 * stored at R_NEWLENGTH.    */
static unsigned char *
cram_octet_string (const unsigned char *input, size_t length,
                   size_t *r_newlength)
{
  const unsigned char *s = input;
  size_t n = length;
  unsigned char *output, *d;
  struct tag_info ti;

  /* Allocate output buf.  We know that it won't be longer than the
     input buffer. */
  d = output = gcry_malloc (length);
  if (!output)
    goto bailout;

  while (n)
    {
      if (parse_tag (&s, &n, &ti))
        goto bailout;
      if (ti.class == CLASS_UNIVERSAL && ti.tag == TAG_OCTET_STRING
          && !ti.ndef && !ti.is_constructed)
        {
          memcpy (d, s, ti.length);
          s += ti.length;
          d += ti.length;
          n -= ti.length;
        }
      else if (ti.class == CLASS_UNIVERSAL && !ti.tag && !ti.is_constructed)
        break; /* Ready */
      else
        goto bailout;
    }


  *r_newlength = d - output;
  return output;

 bailout:
  gcry_free (output);
  return NULL;
}


/* Return true if (INPUT,LENGTH) is a structure which should be passed
 * to cram_octet_string.  This is basically the same loop as in
 * cram_octet_string but without any actual copying.  */
static int
need_octet_string_cramming (const unsigned char *input, size_t length)
{
  const unsigned char *s = input;
  size_t n = length;
  struct tag_info ti;

  if (!length)
    return 0;

  while (n)
    {
      if (parse_tag (&s, &n, &ti))
        return 0;
      if (ti.class == CLASS_UNIVERSAL && ti.tag == TAG_OCTET_STRING
          && !ti.ndef && !ti.is_constructed)
        {
          s += ti.length;
          n -= ti.length;
        }
      else if (ti.class == CLASS_UNIVERSAL && !ti.tag && !ti.is_constructed)
        break; /* Ready */
      else
        return 0;
    }

  return 1;
}


static int
string_to_key (int id, char *salt, size_t saltlen, int iter, const char *pw,
               int req_keylen, unsigned char *keybuf)
{
  int rc, i, j;
  gcry_md_hd_t md;
  gcry_mpi_t num_b1 = NULL;
  int pwlen;
  unsigned char hash[20], buf_b[64], buf_i[128], *p;
  size_t cur_keylen;
  size_t n;

  cur_keylen = 0;
  pwlen = strlen (pw);
  if (pwlen > 63/2)
    {
      log_error ("password too long\n");
      return -1;
    }

  if (saltlen < 8)
    {
      log_error ("salt too short\n");
      return -1;
    }

  /* Store salt and password in BUF_I */
  p = buf_i;
  for(i=0; i < 64; i++)
    *p++ = salt [i%saltlen];
  for(i=j=0; i < 64; i += 2)
    {
      *p++ = 0;
      *p++ = pw[j];
      if (++j > pwlen) /* Note, that we include the trailing zero */
        j = 0;
    }

  for (;;)
    {
      rc = gcry_md_open (&md, GCRY_MD_SHA1, 0);
      if (rc)
        {
          log_error ( "gcry_md_open failed: %s\n", gpg_strerror (rc));
          return rc;
        }
      for(i=0; i < 64; i++)
        gcry_md_putc (md, id);
      gcry_md_write (md, buf_i, 128);
      memcpy (hash, gcry_md_read (md, 0), 20);
      gcry_md_close (md);
      for (i=1; i < iter; i++)
        gcry_md_hash_buffer (GCRY_MD_SHA1, hash, hash, 20);

      for (i=0; i < 20 && cur_keylen < req_keylen; i++)
        keybuf[cur_keylen++] = hash[i];
      if (cur_keylen == req_keylen)
        {
          gcry_mpi_release (num_b1);
          return 0; /* ready */
        }

      /* need more bytes. */
      for(i=0; i < 64; i++)
        buf_b[i] = hash[i % 20];
      rc = gcry_mpi_scan (&num_b1, GCRYMPI_FMT_USG, buf_b, 64, &n);
      if (rc)
        {
          log_error ( "gcry_mpi_scan failed: %s\n", gpg_strerror (rc));
          return -1;
        }
      gcry_mpi_add_ui (num_b1, num_b1, 1);
      for (i=0; i < 128; i += 64)
        {
          gcry_mpi_t num_ij;

          rc = gcry_mpi_scan (&num_ij, GCRYMPI_FMT_USG, buf_i + i, 64, &n);
          if (rc)
            {
              log_error ( "gcry_mpi_scan failed: %s\n",
                       gpg_strerror (rc));
              return -1;
            }
          gcry_mpi_add (num_ij, num_ij, num_b1);
          gcry_mpi_clear_highbit (num_ij, 64*8);
          rc = gcry_mpi_print (GCRYMPI_FMT_USG, buf_i + i, 64, &n, num_ij);
          if (rc)
            {
              log_error ( "gcry_mpi_print failed: %s\n",
                          gpg_strerror (rc));
              return -1;
            }
          gcry_mpi_release (num_ij);
        }
    }
}


static int
set_key_iv (gcry_cipher_hd_t chd, char *salt, size_t saltlen, int iter,
            const char *pw, int keybytes)
{
  unsigned char keybuf[24];
  int rc;

  log_assert (keybytes == 5 || keybytes == 24);
  if (string_to_key (1, salt, saltlen, iter, pw, keybytes, keybuf))
    return -1;
  rc = gcry_cipher_setkey (chd, keybuf, keybytes);
  if (rc)
    {
      log_error ( "gcry_cipher_setkey failed: %s\n", gpg_strerror (rc));
      return -1;
    }

  if (string_to_key (2, salt, saltlen, iter, pw, 8, keybuf))
    return -1;
  rc = gcry_cipher_setiv (chd, keybuf, 8);
  if (rc)
    {
      log_error ("gcry_cipher_setiv failed: %s\n", gpg_strerror (rc));
      return -1;
    }
  return 0;
}


static int
set_key_iv_pbes2 (gcry_cipher_hd_t chd, char *salt, size_t saltlen, int iter,
                  const void *iv, size_t ivlen, const char *pw,
                  int cipher_algo, int digest_algo)
{
  unsigned char *keybuf;
  size_t keylen;
  int rc;

  keylen = gcry_cipher_get_algo_keylen (cipher_algo);
  if (!keylen)
    return -1;
  keybuf = gcry_malloc_secure (keylen);
  if (!keybuf)
    return -1;

  rc = gcry_kdf_derive (pw, strlen (pw),
                        GCRY_KDF_PBKDF2, digest_algo,
                        salt, saltlen, iter, keylen, keybuf);
  if (rc)
    {
      log_error ("gcry_kdf_derive failed: %s\n", gpg_strerror (rc));
      gcry_free (keybuf);
      return -1;
    }

  rc = gcry_cipher_setkey (chd, keybuf, keylen);
  gcry_free (keybuf);
  if (rc)
    {
      log_error ("gcry_cipher_setkey failed: %s\n", gpg_strerror (rc));
      return -1;
    }


  rc = gcry_cipher_setiv (chd, iv, ivlen);
  if (rc)
    {
      log_error ("gcry_cipher_setiv failed: %s\n", gpg_strerror (rc));
      return -1;
    }
  return 0;
}


static void
crypt_block (unsigned char *buffer, size_t length, char *salt, size_t saltlen,
             int iter, const void *iv, size_t ivlen,
             const char *pw, int cipher_algo, int digest_algo, int encrypt)
{
  gcry_cipher_hd_t chd;
  int rc;

  rc = gcry_cipher_open (&chd, cipher_algo, GCRY_CIPHER_MODE_CBC, 0);
  if (rc)
    {
      log_error ( "gcry_cipher_open failed: %s\n", gpg_strerror(rc));
      wipememory (buffer, length);
      return;
    }

  if ((cipher_algo == GCRY_CIPHER_AES128 || cipher_algo == GCRY_CIPHER_AES256)
      ? set_key_iv_pbes2 (chd, salt, saltlen, iter, iv, ivlen, pw,
                          cipher_algo, digest_algo)
      : set_key_iv (chd, salt, saltlen, iter, pw,
                    cipher_algo == GCRY_CIPHER_RFC2268_40? 5:24))
    {
      wipememory (buffer, length);
      goto leave;
    }

  rc = encrypt? gcry_cipher_encrypt (chd, buffer, length, NULL, 0)
              : gcry_cipher_decrypt (chd, buffer, length, NULL, 0);

  if (rc)
    {
      wipememory (buffer, length);
      log_error ("%scrytion failed (%zu bytes): %s\n",
                 encrypt?"en":"de", length, gpg_strerror (rc));
      goto leave;
    }

 leave:
  gcry_cipher_close (chd);
}


/* Decrypt a block of data and try several encodings of the key.
   CIPHERTEXT is the encrypted data of size LENGTH bytes; PLAINTEXT is
   a buffer of the same size to receive the decryption result. SALT,
   SALTLEN, ITER and PW are the information required for decryption
   and CIPHER_ALGO is the algorithm id to use.  CHECK_FNC is a
   function called with the plaintext and used to check whether the
   decryption succeeded; i.e. that a correct passphrase has been
   given.  The function returns the length of the unpadded plaintext
   or 0 on error.  */
static size_t
decrypt_block (const void *ciphertext, unsigned char *plaintext, size_t length,
               char *salt, size_t saltlen,
               int iter, const void *iv, size_t ivlen,
               const char *pw, int cipher_algo, int digest_algo,
               int (*check_fnc) (const void *, size_t))
{
  static const char * const charsets[] = {
    "",   /* No conversion - use the UTF-8 passphrase direct.  */
    "ISO-8859-1",
    "ISO-8859-15",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "KOI8-R",
    "IBM437",
    "IBM850",
    "EUC-JP",
    "BIG5",
    NULL
  };
  int charsetidx = 0;
  char *convertedpw = NULL;   /* Malloced and converted password or NULL.  */
  size_t convertedpwsize = 0; /* Allocated length.  */
  size_t plainlen = 0;

  for (charsetidx=0; charsets[charsetidx]; charsetidx++)
    {
      if (*charsets[charsetidx])
        {
          jnlib_iconv_t cd;
          const char *inptr;
          char *outptr;
          size_t inbytes, outbytes;

          if (!convertedpw)
            {
              /* We assume one byte encodings.  Thus we can allocate
                 the buffer of the same size as the original
                 passphrase; the result will actually be shorter
                 then.  */
              convertedpwsize = strlen (pw) + 1;
              convertedpw = gcry_malloc_secure (convertedpwsize);
              if (!convertedpw)
                {
                  log_info ("out of secure memory while"
                            " converting passphrase\n");
                  break; /* Give up.  */
                }
            }

          cd = jnlib_iconv_open (charsets[charsetidx], "utf-8");
          if (cd == (jnlib_iconv_t)(-1))
            continue;

          inptr = pw;
          inbytes = strlen (pw);
          outptr = convertedpw;
          outbytes = convertedpwsize - 1;
          if ( jnlib_iconv (cd, (const char **)&inptr, &inbytes,
                      &outptr, &outbytes) == (size_t)-1)
            {
              jnlib_iconv_close (cd);
              continue;
            }
          *outptr = 0;
          jnlib_iconv_close (cd);
          log_info ("decryption failed; trying charset '%s'\n",
                    charsets[charsetidx]);
        }
      memcpy (plaintext, ciphertext, length);
      crypt_block (plaintext, length, salt, saltlen, iter, iv, ivlen,
                   convertedpw? convertedpw:pw, cipher_algo, digest_algo, 0);
      if (check_fnc (plaintext, length))
        {
          /* Strip the pkcs#7 padding.  */
          if (length)
            {
              int n, i;

              n = plaintext[length-1];
              if (n >= length || n > 16)
                log_info ("decryption failed; invalid padding size\n");
              else
                {
                  for (i=1; i < n; i++)
                    if (plaintext[length-i-1] != n)
                      break;
                  if (i < n)
                    log_info ("decryption failed; invalid padding octet\n");
                  else
                    plainlen = length - n;
                }
            }
          break; /* Decryption probably succeeded. */
        }
    }
  gcry_free (convertedpw);
  return plainlen;
}


/* Return true if the decryption of an bag_encrypted_data object has
   likely succeeded.  */
static int
bag_decrypted_data_p (const void *plaintext, size_t length)
{
  struct tag_info ti;
  const unsigned char *p = plaintext;
  size_t n = length;

#ifdef ENABLE_DER_STRUCT_DUMPING
  {
  #  warning debug code is enabled
      FILE *fp = fopen ("tmp-minip12-plain-data.der", "wb");
      if (!fp || fwrite (p, n, 1, fp) != 1)
        exit (2);
      fclose (fp);
  }
#endif /*ENABLE_DER_STRUCT_DUMPING*/

  if (parse_tag (&p, &n, &ti))
    return 0;
  if (ti.class || ti.tag != TAG_SEQUENCE)
    return 0;
  if (parse_tag (&p, &n, &ti))
    return 0;

  return 1;
}


static int
parse_bag_encrypted_data (struct p12_parse_ctx_s *ctx, struct tlv_ctx_s *tlv)
{
  gpg_error_t err = 0;
  const char *where;
  const unsigned char *oid;
  size_t oidlen;
  const unsigned char *data;
  size_t datalen;
  int intval;
  char salt[32];
  size_t saltlen;
  char iv[16];
  unsigned int iter;
  unsigned char *plain = NULL;
  int is_3des = 0;
  int is_pbes2 = 0;
  int is_aes256 = 0;
  int keyelem_count;
  int renewed_tlv = 0;
  int loopcount;
  unsigned int startlevel, startlevel2;
  int digest_algo = GCRY_MD_SHA1;

  where = "bag.encryptedData";
  if (opt_verbose)
    log_info ("processing %s\n", where);

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_context_tag (tlv, &intval) || intval != 0 )
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  where = "bag.encryptedData.version";
  if (tlv_next (tlv))
    goto bailout;
  if ((err = tlv_expect_integer (tlv, &intval)))
    goto bailout;
  if (intval)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto bailout;
    }

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  where = "bag.encryptedData.data";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_object_id (tlv, &oid, &oidlen))
    goto bailout;
  if (oidlen != DIM(oid_data) || memcmp (oid, oid_data, DIM(oid_data)))
    goto bailout;

  where = "bag.encryptedData.keyinfo";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_object_id (tlv, &oid, &oidlen))
    goto bailout;
  if (oidlen == DIM(oid_pbeWithSHAAnd40BitRC2_CBC)
      && !memcmp (oid, oid_pbeWithSHAAnd40BitRC2_CBC,
                  DIM(oid_pbeWithSHAAnd40BitRC2_CBC)))
    ;
  else if (oidlen == DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)
           && !memcmp (oid, oid_pbeWithSHAAnd3_KeyTripleDES_CBC,
                       DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)))
    is_3des = 1;
  else if (oidlen == DIM(oid_pkcs5PBES2)
           && !memcmp (oid, oid_pkcs5PBES2, oidlen))
    is_pbes2 = 1;
  else
    {
      err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
      goto bailout;
    }

  /*FIXME: This code is duplicated in parse_shrouded_key_bag.  */
  if (is_pbes2)
    {
      size_t parmlen;  /* Remaining length of the parameter sequence.  */

      where = "pkcs5PBES2-params";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;
      if (oidlen != DIM(oid_pkcs5PBKDF2)
          || memcmp (oid, oid_pkcs5PBKDF2, oidlen))
        {
          err = gpg_error (GPG_ERR_INV_BER); /* Not PBKDF2.  */
          goto bailout;
        }

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;
      parmlen = tlv->ti.length;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      parmlen -= tlv->ti.length + tlv->ti.nhdr;
      if (datalen < 8 || datalen > sizeof salt)
        {
          log_info ("bad length of salt (%zu)\n", datalen);
          err = gpg_error (GPG_ERR_INV_LENGTH);
          goto bailout;
        }
      saltlen = datalen;
      memcpy (salt, data, saltlen);

      if (tlv_next (tlv))
        goto bailout;
      if ((err = tlv_expect_integer (tlv, &intval)))
        goto bailout;
      parmlen -= tlv->ti.length + tlv->ti.nhdr;
      if (!intval) /* Not a valid iteration count.  */
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto bailout;
        }
      iter = intval;

      if (parmlen > 2)  /* There is the optional prf.  */
        {
          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_sequence (tlv))
            goto bailout;
          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_object_id (tlv, &oid, &oidlen))
            goto bailout;
          digest_algo = digest_algo_from_oid (oid, oidlen);
          if (!digest_algo)
            {
              gpgrt_log_printhex (oid, oidlen, "kdf digest algo:");
              err = gpg_error (GPG_ERR_DIGEST_ALGO);
              goto bailout;
            }
          if (opt_verbose > 1)
            log_debug ("kdf digest algo = %d\n", digest_algo);

          if (tlv_peek_null (tlv))
            {
              /* Read the optional Null tag.  */
              if (tlv_next (tlv))
                goto bailout;
            }
        }
      else
        digest_algo = GCRY_MD_SHA1;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;

      if (oidlen == DIM(oid_aes128_CBC)
          && !memcmp (oid, oid_aes128_CBC, oidlen))
        ;
      else if (oidlen == DIM(oid_aes256_CBC)
               && !memcmp (oid, oid_aes256_CBC, oidlen))
        is_aes256 = 1;
      else
        {
          gpgrt_log_printhex (oid, oidlen, "cipher algo:");
          err = gpg_error (GPG_ERR_CIPHER_ALGO);
          goto bailout;
        }

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      if (datalen != sizeof iv)
        {
          err = gpg_error (GPG_ERR_INV_LENGTH);
          goto bailout; /* Bad IV.  */
        }
      memcpy (iv, data, datalen);
    }
  else
    {
      where = "rc2or3des-params";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      if (datalen < 8 || datalen > 20)
        {
          log_info ("bad length of salt (%zu) for 3DES\n", datalen);
          err = gpg_error (GPG_ERR_INV_LENGTH);
          goto bailout;
        }
      saltlen = datalen;
      memcpy (salt, data, saltlen);

      if (tlv_next (tlv))
        goto bailout;
      if ((err = tlv_expect_integer (tlv, &intval)))
        goto bailout;
      if (!intval)
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto bailout;
        }
      iter = intval;
    }

  where = "rc2or3desoraes-ciphertext";
  if (tlv_next (tlv))
    goto bailout;

  if (tlv_expect_object (tlv, CLASS_CONTEXT, 0, &data, &datalen))
    goto bailout;

  if (opt_verbose)
    log_info ("%zu bytes of %s encrypted text\n", datalen,
              is_pbes2?(is_aes256?"AES256":"AES128"):is_3des?"3DES":"RC2");

  plain = gcry_malloc_secure (datalen);
  if (!plain)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating decryption buffer\n");
      goto bailout;
    }
  datalen = decrypt_block (data, plain, datalen, salt, saltlen, iter,
                 iv, is_pbes2?16:0, ctx->password,
                 is_pbes2 ? (is_aes256?GCRY_CIPHER_AES256:GCRY_CIPHER_AES128) :
                 is_3des  ? GCRY_CIPHER_3DES : GCRY_CIPHER_RFC2268_40,
                 digest_algo,
                 bag_decrypted_data_p);
  if (!datalen)
    {
      err = gpg_error (GPG_ERR_DECRYPT_FAILED);
      ctx->badpass = 1;  /* This is the most likley reason.  */
      goto bailout;
    }

  /* We do not need the TLV anymore and allocated a new one.  */
  where = "bag.encryptedData.decrypted-text";
  tlv = tlv_new (plain, datalen);
  if (!tlv)
    {
      err = gpg_error_from_syserror ();
      goto bailout;
    }
  renewed_tlv = 1;

  if (tlv_next (tlv))
    {
      ctx->badpass = 1;
      goto bailout;
    }
  if (tlv_expect_sequence (tlv))
    {
      ctx->badpass = 1;
      goto bailout;
    }

  /* Loop over all certificates inside the bag. */
  loopcount = 0;
  startlevel = tlv_level (tlv);
  while (!(err = tlv_next (tlv)) && tlv_level (tlv) == startlevel)
    {
      int iscrlbag = 0;
      int iskeybag = 0;

      loopcount++;
      where = "certbag.nextcert";
      if (tlv_expect_sequence (tlv))
        goto bailout;

      where = "certbag.oid";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;
      if (oidlen == DIM(oid_pkcs_12_CertBag)
          && !memcmp (oid, oid_pkcs_12_CertBag, DIM(oid_pkcs_12_CertBag)))
        ;
      else if (oidlen == DIM(oid_pkcs_12_CrlBag)
               && !memcmp (oid, oid_pkcs_12_CrlBag, DIM(oid_pkcs_12_CrlBag)))
        iscrlbag = 1;
      else if (oidlen == DIM(oid_pkcs_12_keyBag)
               && !memcmp (oid, oid_pkcs_12_keyBag, DIM(oid_pkcs_12_keyBag)))
        {
          /* The TrustedMIME plugin for MS Outlook started to create
             files with just one outer 3DES encrypted container and
             inside the certificates as well as the key. */
          iskeybag = 1;
        }
      else
        {
          gpgrt_log_printhex (oid, oidlen, "cert bag type OID:");
          err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
          goto bailout;
        }

      where = "certbag.before.certheader";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_context_tag (tlv, &intval) || intval != 0 )
        goto bailout;

      if (iscrlbag)
        {
          log_info ("skipping unsupported crlBag\n");
        }
      else if (iskeybag && ctx->privatekey)
        {
          log_info ("one keyBag already processed; skipping this one\n");
        }
      else if (iskeybag)
        {
          if (opt_verbose)
            log_info ("processing simple keyBag\n");

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_sequence (tlv))
            goto bailout;

          if (tlv_next (tlv))
            goto bailout;
          if ((err = tlv_expect_integer (tlv, &intval)))
            goto bailout;
          if (intval)
            {
              err = gpg_error (GPG_ERR_INV_VALUE);
              goto bailout;
            }

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_sequence (tlv))
            goto bailout;

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_object_id (tlv, &oid, &oidlen))
            goto bailout;
          if (oidlen != DIM(oid_rsaEncryption)
              || memcmp (oid, oid_rsaEncryption, oidlen))
            {
              err = gpg_error (GPG_ERR_PUBKEY_ALGO);
              goto bailout;
            }

          /* We ignore the next octet string.  */
          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
            goto bailout;

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_sequence (tlv))
            goto bailout;

          if (ctx->privatekey)
            {
              err = gpg_error (GPG_ERR_DUP_VALUE);
              log_error ("a private key has already been received\n");
              goto bailout;
            }
          ctx->privatekey = gcry_calloc (10, sizeof *ctx->privatekey);
          if (!ctx->privatekey)
            {
              err = gpg_error_from_syserror ();
              log_error ("error allocating private key element array\n");
              goto bailout;
            }

          where = "reading.keybag.key-parameters";
          keyelem_count = 0;
          startlevel2 = tlv_level (tlv);
          while (!(err = tlv_next (tlv)) && tlv_level (tlv) == startlevel2)
            {
              if (keyelem_count >= 9)
                {
                  err = gpg_error (GPG_ERR_TOO_MANY);
                  goto bailout;
                }

              err = tlv_expect_mpinteger (tlv, !keyelem_count,
                                          ctx->privatekey+keyelem_count);
              if (!keyelem_count && gpg_err_code (err) == GPG_ERR_FALSE)
                ; /* Ignore the first value iff it is zero. */
              else if (err)
                {
                  log_error ("error parsing RSA key parameter %d: %s\n",
                             keyelem_count, gpg_strerror (err));
                  goto bailout;
                }
              if (opt_verbose > 1)
                log_debug ("RSA key parameter %d found\n", keyelem_count);
              keyelem_count++;
            }
          if (!err)
            tlv_set_pending (tlv);
          else if (err && gpg_err_code (err) != GPG_ERR_EOF)
            goto bailout;
          err = 0;
        }
      else
        {
          if (opt_verbose)
            log_info ("processing certBag\n");

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_sequence (tlv))
            goto bailout;

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_object_id (tlv, &oid, &oidlen))
            goto bailout;
          if (oidlen != DIM(oid_x509Certificate_for_pkcs_12)
              || memcmp (oid, oid_x509Certificate_for_pkcs_12,
                         DIM(oid_x509Certificate_for_pkcs_12)))
            {
              err = gpg_error (GPG_ERR_UNSUPPORTED_CERT);
              goto bailout;
            }

          where = "certbag.before.octetstring";
          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_context_tag (tlv, &intval))
            goto bailout;
          if (intval)
            {
              err = gpg_error (GPG_ERR_BAD_BER);
              goto bailout;
            }

          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
            goto bailout;

          /* Return the certificate. */
          if (ctx->certcb)
            ctx->certcb (ctx->certcbarg, data, datalen);
        }

      /* Skip the optional SET with the pkcs12 cert attributes. */
      where = "bag.attribute_set";
      if (tlv_peek (tlv, CLASS_UNIVERSAL, TAG_SET))
        {
          if (tlv_next (tlv))
            goto bailout;
          err = tlv_expect_set (tlv);
          if (err)
            goto bailout;
          tlv_skip (tlv);
          if (opt_verbose)
            log_info ("skipping %s\n", where);
        }
    }
  if (!err)
    tlv_set_pending (tlv);
  else if (err && gpg_err_code (err) != GPG_ERR_EOF)
    {
      if (!loopcount)  /* The first while(tlv_next) failed.  */
        ctx->badpass = 1;
      goto bailout;
    }
  err = 0;

 leave:
  if (renewed_tlv)
    tlv_release (tlv);
  gcry_free (plain);
  if (ctx->badpass)
    {
      /* Note, that the following string might be used by other programs
         to check for a bad passphrase; it should therefore not be
         translated or changed. */
      log_error ("possibly bad passphrase given\n");
    }
  return err;

 bailout:
  if (!err)
    err = gpg_error (GPG_ERR_GENERAL);
  log_error ("%s(%s): lvl=%u (%s): %s - %s\n",
             __func__, where,
             tlv? tlv->stacklen : 0,
             tlv? tlv->lastfunc : "",
             tlv ? gpg_strerror (tlv->lasterr) : "init failed",
             gpg_strerror (err));
  goto leave;
}


/* Return true if the decryption of a bag_data object has likely
   succeeded.  */
static int
bag_data_p (const void *plaintext, size_t length)
{
  struct tag_info ti;
  const unsigned char *p = plaintext;
  size_t n = length;

#ifdef ENABLE_DER_STRUCT_DUMPING
  {
#  warning debug code is enabled
    FILE *fp = fopen ("tmp-minip12-plain-key.der", "wb");
    if (!fp || fwrite (p, n, 1, fp) != 1)
      exit (2);
    fclose (fp);
  }
#endif /*ENABLE_DER_STRUCT_DUMPING*/

  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_SEQUENCE)
    return 0;
  if (parse_tag (&p, &n, &ti) || ti.class || ti.tag != TAG_INTEGER
      || ti.length != 1 || *p)
    return 0;

  return 1;
}


static gpg_error_t
parse_shrouded_key_bag (struct p12_parse_ctx_s *ctx, struct tlv_ctx_s *tlv)
{
  gpg_error_t err = 0;
  const char *where;
  const unsigned char *oid;
  size_t oidlen;
  const unsigned char *data;
  size_t datalen;
  int intval;
  char salt[20];
  size_t saltlen;
  char iv[16];
  unsigned int iter;
  struct tlv_ctx_s *saved_tlv = NULL;
  int renewed_tlv = 0;  /* True if the TLV must be released.  */
  unsigned char *plain = NULL;
  int is_pbes2 = 0;
  int is_aes256 = 0;
  int digest_algo = GCRY_MD_SHA1;

  where = "shrouded_key_bag";
  if (opt_verbose)
    log_info ("processing %s\n", where);

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_context_tag (tlv, &intval) || intval != 0 )
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  where = "shrouded_key_bag.cipherinfo";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_object_id (tlv, &oid, &oidlen))
    goto bailout;

  if (oidlen == DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)
      && !memcmp (oid, oid_pbeWithSHAAnd3_KeyTripleDES_CBC,
                  DIM(oid_pbeWithSHAAnd3_KeyTripleDES_CBC)))
    ; /* Standard cipher.  */
  else if (oidlen == DIM(oid_pkcs5PBES2)
           && !memcmp (oid, oid_pkcs5PBES2, DIM(oid_pkcs5PBES2)))
    is_pbes2 = 1;
  else
    {
      err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
      goto bailout;
    }

  if (is_pbes2)
    {
      size_t parmlen;  /* Remaining length of the parameter sequence.  */

      where = "shrouded_key_bag.pkcs5PBES2-params";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;
      if (!(oidlen == DIM(oid_pkcs5PBKDF2)
            && !memcmp (oid, oid_pkcs5PBKDF2, oidlen)))
        goto bailout; /* Not PBKDF2.  */

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;
      parmlen = tlv->ti.length;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      parmlen -= tlv->ti.length + tlv->ti.nhdr;
      if (datalen < 8 || datalen > sizeof salt)
        {
          log_info ("bad length of salt (%zu) for AES\n", datalen);
          err = gpg_error (GPG_ERR_INV_LENGTH);
          goto bailout;
        }
      saltlen = datalen;
      memcpy (salt, data, saltlen);

      if (tlv_next (tlv))
        goto bailout;
      if ((err = tlv_expect_integer (tlv, &intval)))
        goto bailout;
      parmlen -= tlv->ti.length + tlv->ti.nhdr;
      if (!intval) /* Not a valid iteration count.  */
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto bailout;
        }
      iter = intval;

      if (parmlen > 2)  /* There is the optional prf.  */
        {
          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_sequence (tlv))
            goto bailout;
          if (tlv_next (tlv))
            goto bailout;
          if (tlv_expect_object_id (tlv, &oid, &oidlen))
            goto bailout;
          digest_algo = digest_algo_from_oid (oid, oidlen);
          if (!digest_algo)
            {
              gpgrt_log_printhex (oid, oidlen, "kdf digest algo:");
              err = gpg_error (GPG_ERR_DIGEST_ALGO);
              goto bailout;
            }
          if (opt_verbose > 1)
            log_debug ("kdf digest algo = %d\n", digest_algo);

          if (tlv_peek_null (tlv))
            {
              /* Read the optional Null tag.  */
              if (tlv_next (tlv))
                goto bailout;
            }
        }
      else
        digest_algo = GCRY_MD_SHA1;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;
      if (oidlen == DIM(oid_aes128_CBC)
          && !memcmp (oid, oid_aes128_CBC, oidlen))
        ;
      else if (oidlen == DIM(oid_aes256_CBC)
               && !memcmp (oid, oid_aes256_CBC, oidlen))
        is_aes256 = 1;
      else
        {
          gpgrt_log_printhex (oid, oidlen, "cipher is:");
          err = gpg_error (GPG_ERR_CIPHER_ALGO);
          goto bailout;
        }

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      if (datalen != sizeof iv)
        goto bailout; /* Bad IV.  */
      memcpy (iv, data, datalen);
    }
  else
    {
      where = "shrouded_key_bag.3des-params";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      if (datalen < 8 || datalen > 20)
        {
          log_info ("bad length of salt (%zu) for 3DES\n", datalen);
          err = gpg_error (GPG_ERR_INV_LENGTH);
          goto bailout;
        }
      saltlen = datalen;
      memcpy (salt, data, saltlen);

      if (tlv_next (tlv))
        goto bailout;
      if ((err = tlv_expect_integer (tlv, &intval)))
        goto bailout;
      if (!intval)
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto bailout;
        }
      iter = intval;
    }

  where = "shrouded_key_bag.3desoraes-ciphertext";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
    goto bailout;

  if (opt_verbose)
    log_info ("%zu bytes of %s encrypted text\n",
              datalen, is_pbes2? (is_aes256?"AES256":"AES128"):"3DES");

  plain = gcry_malloc_secure (datalen);

  if (!plain)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating decryption buffer\n");
      goto bailout;
    }
  datalen = decrypt_block (data, plain, datalen, salt, saltlen, iter,
                 iv, is_pbes2? 16:0, ctx->password,
                 is_pbes2 ? (is_aes256?GCRY_CIPHER_AES256:GCRY_CIPHER_AES128)
                          : GCRY_CIPHER_3DES,
                 digest_algo,
                 bag_data_p);
  if (!datalen)
    {
      err = gpg_error (GPG_ERR_DECRYPT_FAILED);
      ctx->badpass = 1;
      goto bailout;
    }

  /* We do not need the TLV anymore and allocated a new one.  */
  where = "shrouded_key_bag.decrypted-text";
  saved_tlv = tlv;
  tlv = tlv_new (plain, datalen);
  if (!tlv)
    {
      err = gpg_error_from_syserror ();
      goto bailout;
    }
  renewed_tlv = 1;
  if (opt_verbose > 1)
    log_debug ("new parser context\n");

  if (tlv_next (tlv))
    {
      ctx->badpass = 1;
      goto bailout;
    }
  if (tlv_expect_sequence (tlv))
    {
      ctx->badpass = 1;
      goto bailout;
    }

  if (tlv_next (tlv))
    {
      ctx->badpass = 1;
      goto bailout;
    }
  if ((err = tlv_expect_integer (tlv, &intval)))
    {
      ctx->badpass = 1;
      goto bailout;
    }
  if (intval)
    {
      ctx->badpass = 1;
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto bailout;
    }

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_object_id (tlv, &oid, &oidlen))
    goto bailout;
  if (oidlen == DIM(oid_rsaEncryption)
      && !memcmp (oid, oid_rsaEncryption, oidlen))
    {
      if (opt_verbose > 1)
        log_debug ("RSA parameters\n");

      if (tlv_peek_null (tlv))
        {
          /* Read the optional Null tag.  */
          if (tlv_next (tlv))
            goto bailout;
        }
    }
  else if (oidlen == DIM(oid_pcPublicKey)
           && !memcmp (oid, oid_pcPublicKey, oidlen))
    {
      /* See RFC-5915 for the format.  */
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;
      ksba_free (ctx->curve);
      ctx->curve = ksba_oid_to_str (oid, oidlen);
      if (!ctx->curve)
        {
          err = gpg_error (GPG_ERR_INV_OID_STRING);
          goto bailout;
        }
      if (opt_verbose > 1)
        log_debug ("OID of curve is: %s\n", ctx->curve);
    }
  else /* Unknown key format */
    {
      gpgrt_log_printhex (oid, oidlen, "key format OID:");
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      goto bailout;
    }

  /* An octet string to encapsulate the key elements.  */
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_octet_string (tlv, 1, &data, &datalen))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  if (ctx->privatekey)
    {
      err = gpg_error (GPG_ERR_DUP_VALUE);
      log_error ("a private key has already been received\n");
      goto bailout;
    }
  ctx->privatekey = gcry_calloc (10, sizeof *ctx->privatekey);
  if (!ctx->privatekey)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating privatekey element array\n");
      goto bailout;
    }

  where = "shrouded_key_bag.reading.key-parameters";
  if (ctx->curve)  /* ECC case.  */
    {
      if (tlv_next (tlv))
        goto bailout;
      if ((err = tlv_expect_integer (tlv, &intval)))
        goto bailout;
      if (intval != 1)
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          log_error ("error parsing private ecPublicKey parameter: %s\n",
                     "bad version");
          goto bailout;
        }

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
        goto bailout;
      if (opt_verbose > 1)
        log_printhex (data, datalen, "ecc q=");
      err = gcry_mpi_scan (ctx->privatekey, GCRYMPI_FMT_USG,
                           data, datalen, NULL);
      if (err)
        {
          log_error ("error parsing key parameter: %s\n", gpg_strerror (err));
          goto bailout;
        }
    }
  else  /* RSA case */
    {
      int keyelem_count = 0;
      int firstparam = 1;
      unsigned int startlevel = tlv_level (tlv);

      while (!(err = tlv_next (tlv)) && tlv_level (tlv) == startlevel)
        {
          if (keyelem_count >= 9)
            {
              err = gpg_error (GPG_ERR_TOO_MANY);
              goto bailout;
            }

          err = tlv_expect_mpinteger (tlv, firstparam,
                                      ctx->privatekey+keyelem_count);
          if (firstparam && gpg_err_code (err) == GPG_ERR_FALSE)
            ; /* Ignore the first value iff it is zero. */
          else if (err)
            {
              log_error ("error parsing RSA key parameter %d: %s\n",
                         keyelem_count, gpg_strerror (err));
              goto bailout;
            }
          else
            {
              if (opt_verbose > 1)
                log_debug ("RSA key parameter %d found\n", keyelem_count);
              keyelem_count++;
            }
          firstparam = 0;
        }
      if (!err)
        tlv_set_pending (tlv);
      else if (err && gpg_err_code (err) != GPG_ERR_EOF)
        goto bailout;
      err = 0;
    }

  if (opt_verbose > 1)
    log_debug ("restoring parser context\n");
  tlv_release (tlv);
  renewed_tlv = 0;
  tlv = saved_tlv;

  where = "shrouded_key_bag.attribute_set";
  /* Check for an optional set of attributes.  */
  if (tlv_peek (tlv, CLASS_UNIVERSAL, TAG_SET))
    {
      if (tlv_next (tlv))
        goto bailout;
      err = tlv_expect_set (tlv);
      if (err)
        goto bailout;
      tlv_skip (tlv);
      if (opt_verbose)
        log_info ("skipping %s\n", where);
    }


 leave:
  gcry_free (plain);
  if (renewed_tlv)
    {
      tlv_release (tlv);
      if (opt_verbose > 1)
        log_debug ("parser context released\n");
    }
  return err;

 bailout:
  if (!err)
    err = gpg_error (GPG_ERR_GENERAL);
  log_error ("%s(%s): lvl=%d (%s): %s - %s\n",
             __func__, where,
             tlv? tlv->stacklen : 0,
             tlv? tlv->lastfunc : "",
             tlv ? gpg_strerror (tlv->lasterr) : "init failed",
             gpg_strerror (err));
  goto leave;
}


static gpg_error_t
parse_cert_bag (struct p12_parse_ctx_s *ctx, struct tlv_ctx_s *tlv)
{
  gpg_error_t err = 0;
  const char *where;
  int intval;
  const unsigned char *oid;
  size_t oidlen;
  const unsigned char *data;
  size_t datalen;

  if (opt_verbose)
    log_info ("processing certBag\n");

  /* Expect:
   *  [0]
   *    SEQUENCE
   *      OBJECT IDENTIFIER pkcs-12-certBag
   */
  where = "certbag.before.certheader";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_context_tag (tlv, &intval))
    goto bailout;
  if (intval)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto bailout;
    }

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_object_id (tlv, &oid, &oidlen))
    goto bailout;
  if (oidlen != DIM(oid_x509Certificate_for_pkcs_12)
      || memcmp (oid, oid_x509Certificate_for_pkcs_12, oidlen))
    goto bailout;


  /* Expect:
   *  [0]
   *    OCTET STRING encapsulates -- the certificates
   */
  where = "certbag.before.octetstring";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_context_tag (tlv, &intval) || intval != 0 )
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_octet_string (tlv, 0, &data, &datalen))
    goto bailout;

  /* Return the certificate from the octet string. */
  if (ctx->certcb)
     ctx->certcb (ctx->certcbarg, data, datalen);

  /* Expect optional:
   *  SET
   *    SEQUENCE  -- we actually ignore this.
   */
  where = "certbag.attribute_set";
  /* Check for an optional set of attributes.  */
  if (tlv_peek (tlv, CLASS_UNIVERSAL, TAG_SET))
    {
      if (tlv_next (tlv))
        goto bailout;
      err = tlv_expect_set (tlv);
      if (err)
        goto bailout;
      tlv_skip (tlv);
      if (opt_verbose)
        log_info ("skipping %s\n", where);
    }


 leave:
  return err;

 bailout:
  log_error ("%s(%s): lvl=%u (%s): %s - %s\n",
             __func__, where,
             tlv? tlv->stacklen : 0,
             tlv? tlv->lastfunc : "",
             tlv ? gpg_strerror (tlv->lasterr) : "init failed",
             gpg_strerror (err));
  if (!err)
    err = gpg_error (GPG_ERR_GENERAL);
  goto leave;
}


static gpg_error_t
parse_bag_data (struct p12_parse_ctx_s *ctx, struct tlv_ctx_s *tlv)
{
  gpg_error_t err = 0;
  const char *where;
  int intval;
  const unsigned char *oid;
  size_t oidlen;
  unsigned int startlevel;

  if (opt_verbose)
    log_info ("processing bag data\n");

  /* Expect:
   * [0]
   *   OCTET STRING, encapsulates
   */
  where = "data";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_context_tag (tlv, &intval) || intval != 0 )
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_octet_string (tlv, 1, NULL, NULL))
    goto bailout;

  if (tlv_peek (tlv, CLASS_UNIVERSAL, TAG_OCTET_STRING))
    {
      if (tlv_next (tlv))
        goto bailout;
      err = tlv_expect_octet_string (tlv, 1, NULL, NULL);
      if (err)
        goto bailout;
    }

  /* Expect:
   * SEQUENCE
   */
  where = "data.outerseqs";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  startlevel = tlv_level (tlv);
  dump_tlv_ctx ("data.outerseqs", "beginloop", tlv);
  while (!(err = tlv_next (tlv)) && tlv_level (tlv) == startlevel)
    {
      /* Expect:
       * SEQUENCE
       */
      where = "data.innerseqs";
      if (tlv_expect_sequence (tlv))
        goto bailout;

      /* Expect:
       * OBJECT IDENTIFIER
       */
      where = "data.oid";
      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;

      /* Divert to the actual parser.  */
      if (oidlen == DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag)
          && !memcmp (oid, oid_pkcs_12_pkcs_8ShroudedKeyBag,
                      DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag)))
        {
          if ((err = parse_shrouded_key_bag (ctx, tlv)))
            goto bailout;
        }
      else if (oidlen == DIM(oid_pkcs_12_CertBag)
                && !memcmp (oid, oid_pkcs_12_CertBag, DIM(oid_pkcs_12_CertBag)))
        {
          if ((err = parse_cert_bag (ctx, tlv)))
            goto bailout;
        }
      else
        {
          tlv_skip (tlv);
          log_info ("unknown inner data type - skipped\n");
        }
    }
  dump_tlv_ctx ("data.outerseqs", "endloop", tlv);
  if (!err)
    tlv_set_pending (tlv);
  else if (err && gpg_err_code (err) != GPG_ERR_EOF)
    goto bailout;
  err = 0;

 leave:
  return err;

 bailout:
  if (!err)
    err = gpg_error (GPG_ERR_GENERAL);
  log_error ("%s(%s): lvl=%d (%s): %s - %s\n",
             __func__, where,
             tlv? tlv->stacklen : 0,
             tlv? tlv->lastfunc : "",
             tlv ? gpg_strerror (tlv->lasterr) : "init failed",
             gpg_strerror (err));
  goto leave;
}


/* Parse a PKCS12 object and return an array of MPI representing the
   secret key parameters.  This is a very limited implementation in
   that it is only able to look for 3DES encoded encryptedData and
   tries to extract the first private key object it finds.  In case of
   an error NULL is returned. CERTCB and CERTCBARG are used to pass
   X.509 certificates back to the caller.  If R_CURVE is not NULL and
   an ECC key was found the OID of the curve is stored there. */
gcry_mpi_t *
p12_parse (const unsigned char *buffer, size_t length, const char *pw,
           void (*certcb)(void*, const unsigned char*, size_t),
           void *certcbarg, int *r_badpass, char **r_curve)
{
  gpg_error_t err = 0;
  const char *where = "";
  struct tlv_ctx_s *tlv;
  struct p12_parse_ctx_s ctx = { NULL };
  const unsigned char *oid;
  size_t oidlen;
  int intval;
  unsigned int startlevel;

  *r_badpass = 0;

  ctx.certcb = certcb;
  ctx.certcbarg = certcbarg;
  ctx.password = pw;

  tlv = tlv_new (buffer, length);
  if (!tlv)
    {
      err = gpg_error_from_syserror ();
      goto bailout;
    }

  where = "pfx";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  where = "pfxVersion";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_integer (tlv, &intval) || intval != 3)
    goto bailout;

  where = "authSave";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_object_id (tlv, &oid, &oidlen))
    goto bailout;
  if (oidlen != DIM(oid_data) || memcmp (oid, oid_data, DIM(oid_data)))
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_context_tag (tlv, &intval) || intval != 0 )
    goto bailout;

  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_octet_string (tlv, 1, NULL, NULL))
    goto bailout;

  if (tlv_peek (tlv, CLASS_UNIVERSAL, TAG_OCTET_STRING))
    {
      if (tlv_next (tlv))
        goto bailout;
      err = tlv_expect_octet_string (tlv, 1, NULL, NULL);
      if (err)
        goto bailout;
    }

  where = "bags";
  if (tlv_next (tlv))
    goto bailout;
  if (tlv_expect_sequence (tlv))
    goto bailout;

  startlevel = tlv_level (tlv);
  dump_tlv_ctx ("bags", "beginloop", tlv);
  while (!(err = tlv_next (tlv)) && tlv_level (tlv) == startlevel)
    {
      where = "bag-sequence";
      dump_tlv_ctx (where, NULL, tlv);
      if (tlv_expect_sequence (tlv))
        goto bailout;

      if (tlv_next (tlv))
        goto bailout;
      if (tlv_expect_object_id (tlv, &oid, &oidlen))
        goto bailout;

      if (oidlen == DIM(oid_encryptedData)
          && !memcmp (oid, oid_encryptedData, DIM(oid_encryptedData)))
        {
          where = "bag.encryptedData";
          if ((err=parse_bag_encrypted_data (&ctx, tlv)))
            goto bailout;
        }
      else if (oidlen == DIM(oid_data)
               && !memcmp (oid, oid_data, DIM(oid_data)))
        {
          where = "bag.data";
          if ((err=parse_bag_data (&ctx, tlv)))
            goto bailout;
        }
      else if (oidlen == DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag)
          && !memcmp (oid, oid_pkcs_12_pkcs_8ShroudedKeyBag,
                      DIM(oid_pkcs_12_pkcs_8ShroudedKeyBag)))
        {
          where = "bag.shroudedkeybag";
          if ((err = parse_shrouded_key_bag (&ctx, tlv)))
            goto bailout;
        }
      else
        {
          tlv_skip (tlv);
          log_info ("unknown outer bag type - skipped\n");
        }
    }
  dump_tlv_ctx ("bags", "endloop", tlv);
  if (!err)
    tlv_set_pending (tlv);
  else if (err && gpg_err_code (err) != GPG_ERR_EOF)
    goto bailout;
  err = 0;

  tlv_release (tlv);
  if (r_curve)
    *r_curve = ctx.curve;
  else
    gcry_free (ctx.curve);

  return ctx.privatekey;

 bailout:
  *r_badpass = ctx.badpass;
  log_error ("%s(%s): @%04zu lvl=%u %s: %s - %s\n",
             __func__, where,
             tlv? (size_t)(tlv->buffer - tlv->origbuffer):0,
             tlv? tlv->stacklen : 0,
             tlv? tlv->lastfunc : "",
             tlv? gpg_strerror (tlv->lasterr) : "init failed",
             gpg_strerror (err));
  if (ctx.privatekey)
    {
      int i;

      for (i=0; ctx.privatekey[i]; i++)
        gcry_mpi_release (ctx.privatekey[i]);
      gcry_free (ctx.privatekey);
      ctx.privatekey = NULL;
    }
  tlv_release (tlv);
  gcry_free (ctx.curve);
  if (r_curve)
    *r_curve = NULL;
  return NULL;
}



static size_t
compute_tag_length (size_t n)
{
  int needed = 0;

  if (n < 128)
    needed += 2; /* tag and one length byte */
  else if (n < 256)
    needed += 3; /* tag, number of length bytes, 1 length byte */
  else if (n < 65536)
    needed += 4; /* tag, number of length bytes, 2 length bytes */
  else
    {
      log_error ("object too larger to encode\n");
      return 0;
    }
  return needed;
}

static unsigned char *
store_tag_length (unsigned char *p, int tag, size_t n)
{
  if (tag == TAG_SEQUENCE)
    tag |= 0x20; /* constructed */

  *p++ = tag;
  if (n < 128)
    *p++ = n;
  else if (n < 256)
    {
      *p++ = 0x81;
      *p++ = n;
    }
  else if (n < 65536)
    {
      *p++ = 0x82;
      *p++ = n >> 8;
      *p++ = n;
    }

  return p;
}


/* Create the final PKCS-12 object from the sequences contained in
   SEQLIST.  PW is the password. That array is terminated with an NULL
   object. */
static unsigned char *
create_final (struct buffer_s *sequences, const char *pw, size_t *r_length)
{
  int i;
  size_t needed = 0;
  size_t len[8], n;
  unsigned char *macstart;
  size_t maclen;
  unsigned char *result, *p;
  size_t resultlen;
  char salt[8];
  unsigned char keybuf[20];
  gcry_md_hd_t md;
  int rc;
  int with_mac = 1;


  /* 9 steps to create the pkcs#12 Krampf. */

  /* 8. The MAC. */
  /* We add this at step 0. */

  /* 7. All the buffers. */
  for (i=0; sequences[i].buffer; i++)
    needed += sequences[i].length;

  /* 6. This goes into a sequences. */
  len[6] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 5. Encapsulate all in an octet string. */
  len[5] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 4. And tag it with [0]. */
  len[4] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 3. Prepend an data OID. */
  needed += 2 + DIM (oid_data);

  /* 2. Put all into a sequences. */
  len[2] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* 1. Prepend the version integer 3. */
  needed += 3;

  /* 0. And the final outer sequence. */
  if (with_mac)
    needed += DIM (data_mactemplate);
  len[0] = needed;
  n = compute_tag_length (needed);
  needed += n;

  /* Allocate a buffer. */
  result = gcry_malloc (needed);
  if (!result)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }
  p = result;

  /* 0. Store the very outer sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the version integer 3. */
  *p++ = TAG_INTEGER;
  *p++ = 1;
  *p++ = 3;

  /* 2. Store another sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[2]);

  /* 3. Store the data OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_data));
  memcpy (p, oid_data, DIM (oid_data));
  p += DIM (oid_data);

  /* 4. Next comes a context tag. */
  p = store_tag_length (p, 0xa0, len[4]);

  /* 5. And an octet string. */
  p = store_tag_length (p, TAG_OCTET_STRING, len[5]);

  /* 6. And the inner sequence. */
  macstart = p;
  p = store_tag_length (p, TAG_SEQUENCE, len[6]);

  /* 7. Append all the buffers. */
  for (i=0; sequences[i].buffer; i++)
    {
      memcpy (p, sequences[i].buffer, sequences[i].length);
      p += sequences[i].length;
    }

  if (with_mac)
    {
      /* Intermezzo to compute the MAC. */
      maclen = p - macstart;
      gcry_randomize (salt, 8, GCRY_STRONG_RANDOM);
      if (string_to_key (3, salt, 8, 2048, pw, 20, keybuf))
        {
          gcry_free (result);
          return NULL;
        }
      rc = gcry_md_open (&md, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
      if (rc)
        {
          log_error ("gcry_md_open failed: %s\n", gpg_strerror (rc));
          gcry_free (result);
          return NULL;
        }
      rc = gcry_md_setkey (md, keybuf, 20);
      if (rc)
        {
          log_error ("gcry_md_setkey failed: %s\n", gpg_strerror (rc));
          gcry_md_close (md);
          gcry_free (result);
          return NULL;
        }
      gcry_md_write (md, macstart, maclen);

      /* 8. Append the MAC template and fix it up. */
      memcpy (p, data_mactemplate, DIM (data_mactemplate));
      memcpy (p + DATA_MACTEMPLATE_SALT_OFF, salt, 8);
      memcpy (p + DATA_MACTEMPLATE_MAC_OFF, gcry_md_read (md, 0), 20);
      p += DIM (data_mactemplate);
      gcry_md_close (md);
    }

  /* Ready. */
  resultlen = p - result;
  if (needed != resultlen)
    log_debug ("p12_parse: warning: length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)resultlen);

  *r_length = resultlen;
  return result;
}


/* Build a DER encoded SEQUENCE with the key:
 *
 * SEQUENCE {  -- OneAsymmetricKey (RFC-5958)
 *   INTEGER 0
 *   SEQUENCE {
 *     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 *     NULL
 *     }
 *   OCTET STRING, encapsulates {
 *     SEQUENCE {   -- RSAPrivateKey (RFC-3447)
 *       INTEGER 0  -- Version
 *       INTEGER    -- n
 *       INTEGER    -- e
 *       INTEGER    -- d
 *       INTEGER    -- p
 *       INTEGER    -- q
 *       INTEGER    -- d mod (p-1)
 *       INTEGER    -- d mod (q-1)
 *       INTEGER    -- q^-1 mod p
 *       }
 *     }
 *   }
 *
 * MODE controls what is being generated:
 *   0 - As described above
 *   1 - Ditto but without the padding
 *   2 - Only the inner part (pkcs#1)
 */

static unsigned char *
build_rsa_key_sequence (gcry_mpi_t *kparms, int mode, size_t *r_length)
{
  int rc, i;
  size_t needed, n;
  unsigned char *plain, *p;
  size_t plainlen;
  size_t outseqlen, oidseqlen, octstrlen, inseqlen;

  needed = 3; /* The version integer with value 0. */
  for (i=0; kparms[i]; i++)
    {
      n = 0;
      rc = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &n, kparms[i]);
      if (rc)
        {
          log_error ("error formatting parameter: %s\n", gpg_strerror (rc));
          return NULL;
        }
      needed += n;
      n = compute_tag_length (n);
      if (!n)
        return NULL;
      needed += n;
    }
  if (i != 8)
    {
      log_error ("invalid parameters for p12_build\n");
      return NULL;
    }
  /* Now this all goes into a sequence. */
  inseqlen = needed;
  n = compute_tag_length (needed);
  if (!n)
    return NULL;
  needed += n;

  if (mode != 2)
    {
      /* Encapsulate all into an octet string. */
      octstrlen = needed;
      n = compute_tag_length (needed);
      if (!n)
        return NULL;
      needed += n;
      /* Prepend the object identifier sequence. */
      oidseqlen = 2 + DIM (oid_rsaEncryption) + 2;
      needed += 2 + oidseqlen;
      /* The version number. */
      needed += 3;
      /* And finally put the whole thing into a sequence. */
      outseqlen = needed;
      n = compute_tag_length (needed);
      if (!n)
        return NULL;
      needed += n;
    }

  /* allocate 8 extra bytes for padding */
  plain = gcry_malloc_secure (needed+8);
  if (!plain)
    {
      log_error ("error allocating encryption buffer\n");
      return NULL;
    }

  /* And now fill the plaintext buffer. */
  p = plain;
  if (mode != 2)
    {
      p = store_tag_length (p, TAG_SEQUENCE, outseqlen);
      /* Store version. */
      *p++ = TAG_INTEGER;
      *p++ = 1;
      *p++ = 0;
      /* Store object identifier sequence. */
      p = store_tag_length (p, TAG_SEQUENCE, oidseqlen);
      p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_rsaEncryption));
      memcpy (p, oid_rsaEncryption, DIM (oid_rsaEncryption));
      p += DIM (oid_rsaEncryption);
      *p++ = TAG_NULL;
      *p++ = 0;
      /* Start with the octet string. */
      p = store_tag_length (p, TAG_OCTET_STRING, octstrlen);
    }

  p = store_tag_length (p, TAG_SEQUENCE, inseqlen);
  /* Store the key parameters. */
  *p++ = TAG_INTEGER;
  *p++ = 1;
  *p++ = 0;
  for (i=0; kparms[i]; i++)
    {
      n = 0;
      rc = gcry_mpi_print (GCRYMPI_FMT_STD, NULL, 0, &n, kparms[i]);
      if (rc)
        {
          log_error ("oops: error formatting parameter: %s\n",
                     gpg_strerror (rc));
          gcry_free (plain);
          return NULL;
        }
      p = store_tag_length (p, TAG_INTEGER, n);

      n = plain + needed - p;
      rc = gcry_mpi_print (GCRYMPI_FMT_STD, p, n, &n, kparms[i]);
      if (rc)
        {
          log_error ("oops: error storing parameter: %s\n",
                     gpg_strerror (rc));
          gcry_free (plain);
          return NULL;
        }
      p += n;
    }

  plainlen = p - plain;
  log_assert (needed == plainlen);

  if (!mode)
    {
      /* Append some pad characters; we already allocated extra space. */
      n = 8 - plainlen % 8;
      for (i=0; i < n; i++, plainlen++)
        *p++ = n;
    }

  *r_length = plainlen;
  return plain;
}


/* Build a DER encoded SEQUENCE for an ECC key:
 *
 * SEQUENCE {  -- OneAsymmetricKey (RFC-5958)
 *   INTEGER 0
 *   SEQUENCE {
 *     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 *     OBJECT IDENTIFIER -- curvename
 *     }
 *   OCTET STRING, encapsulates {
 *     SEQUENCE {      -- ECPrivateKey
 *       INTEGER  1    --  version
 *       OCTET STRING  -- privateKey
 *       [1] {
 *          BIT STRING - publicKey
 *       }
 *     }
 *   }
 * }
 *
 * For details see RFC-5480 and RFC-5915 (ECparameters are not created).
 *
 * KPARMS[0] := Opaque MPI with the curve name as dotted-decimal string.
 * KPARMS[1] := Opaque MPI with the public key (q)
 * KPARMS[2] := Opaque MPI with the private key (d)
 * MODE controls what is being generated:
 *    0 - As described above
 *    1 - Ditto but without the extra padding needed for pcsk#12
 *    2 - Only the octet string (ECPrivateKey)
 */

static unsigned char *
build_ecc_key_sequence (gcry_mpi_t *kparms, int mode, size_t *r_length)
{
  gpg_error_t err;
  unsigned int nbits, n;
  const unsigned char *s;
  char *p;
  tlv_builder_t tb;
  void *result;
  size_t resultlen;
  const char *curve;
  unsigned int curvebits;
  int e;
  int i;
  int strip_one;

  for (i=0; kparms[i]; i++)
    ;
  if (i != 3)
    {
      log_error ("%s: invalid number of parameters\n", __func__);
      return NULL;
    }

  s = gcry_mpi_get_opaque (kparms[0], &nbits);
  n = (nbits+7)/8;
  p = xtrymalloc (n + 1);
  if (!p)
    {
      err = gpg_error_from_syserror ();
      log_error ("%s:%d: error getting parameter: %s\n",
                 __func__, __LINE__, gpg_strerror (err));
      return NULL;
    }
  memcpy (p, s, n);
  p[n] = 0;
  /* We need to use our OpenPGP mapping to turn a curve name into its
   * canonical numerical OID.  We should have a Libgcrypt function to
   * do this; see bug report #4926.  */
  curve = openpgp_curve_to_oid (p, &curvebits, NULL);
  xfree (p);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_error ("%s:%d: error getting parameter: %s\n",
                 __func__, __LINE__, gpg_strerror (err));
      return NULL;
    }

  /* Unfortunately the private key D may come with a single leading
   * zero byte.  This is becuase at some point it was treated as
   * signed MPI and the code made sure that it is always interpreted
   * as unsigned.  Fortunately we got the size of the curve and can
   * detect such a case reliable.  */
  s = gcry_mpi_get_opaque (kparms[2], &nbits);
  n = (nbits+7)/8;
  strip_one = (n == (curvebits+7)/8 + 1 && !*s);


  tb = tlv_builder_new (1);
  if (!tb)
    {
      err = gpg_error_from_syserror ();
      log_error ("%s:%d: error creating new TLV builder: %s\n",
                 __func__, __LINE__, gpg_strerror (err));
      return NULL;
    }
  e = 0;
  tlv_builder_add_tag (tb, 0, TAG_SEQUENCE);
  tlv_builder_add_ptr (tb, 0, TAG_INTEGER, "\0", 1);
  tlv_builder_add_tag (tb, 0, TAG_SEQUENCE);
  e|= builder_add_oid (tb, 0, "1.2.840.10045.2.1");
  e|= builder_add_oid (tb, 0, curve);
  tlv_builder_add_end (tb);
  tlv_builder_add_tag (tb, 0, TAG_OCTET_STRING);
  tlv_builder_add_tag (tb, 0, TAG_SEQUENCE);
  tlv_builder_add_ptr (tb, 0, TAG_INTEGER, "\x01", 1);
  e|= builder_add_mpi (tb, 0, TAG_OCTET_STRING, kparms[2], strip_one);
  tlv_builder_add_tag (tb, CLASS_CONTEXT, 1);
  e|= builder_add_mpi (tb, 0, TAG_BIT_STRING, kparms[1], 0);
  tlv_builder_add_end (tb);
  tlv_builder_add_end (tb);
  tlv_builder_add_end (tb);
  tlv_builder_add_end (tb);

  err = tlv_builder_finalize (tb, &result, &resultlen);
  if (err || e)
    {
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      log_error ("%s:%d: tlv building failed: %s\n",
                 __func__, __LINE__, gpg_strerror (err));
      return NULL;
    }

  /* Append some pad characters if needed. */
  if (!mode && (n = 8 - resultlen % 8))
    {
      p = xtrymalloc_secure (resultlen + n);
      if (!p)
        {
          err = gpg_error_from_syserror ();
          log_error ("%s:%d: error allocating buffer: %s\n",
                     __func__, __LINE__, gpg_strerror (err));
          xfree (result);
          return NULL;
        }
      memcpy (p, result, resultlen);
      xfree (result);
      result = p;
      p = (unsigned char*)result + resultlen;
      for (i=0; i < n; i++, resultlen++)
        *p++ = n;
    }

  *r_length = resultlen;

  return result;
}


static unsigned char *
build_key_bag (unsigned char *buffer, size_t buflen, char *salt,
               const unsigned char *sha1hash, const char *keyidstr,
               size_t *r_length)
{
  size_t len[11], needed;
  unsigned char *p, *keybag;
  size_t keybaglen;

  /* Walk 11 steps down to collect the info: */

  /* 10. The data goes into an octet string. */
  needed = compute_tag_length (buflen);
  needed += buflen;

  /* 9. Prepend the algorithm identifier. */
  needed += DIM (data_3desiter2048);

  /* 8. Put a sequence around. */
  len[8] = needed;
  needed += compute_tag_length (needed);

  /* 7. Prepend a [0] tag. */
  len[7] = needed;
  needed += compute_tag_length (needed);

  /* 6b. The attributes which are appended at the end. */
  if (sha1hash)
    needed += DIM (data_attrtemplate) + 20;

  /* 6. Prepend the shroudedKeyBag OID. */
  needed += 2 + DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag);

  /* 5+4. Put all into two sequences. */
  len[5] = needed;
  needed += compute_tag_length ( needed);
  len[4] = needed;
  needed += compute_tag_length (needed);

  /* 3. This all goes into an octet string. */
  len[3] = needed;
  needed += compute_tag_length (needed);

  /* 2. Prepend another [0] tag. */
  len[2] = needed;
  needed += compute_tag_length (needed);

  /* 1. Prepend the data OID. */
  needed += 2 + DIM (oid_data);

  /* 0. Prepend another sequence. */
  len[0] = needed;
  needed += compute_tag_length (needed);

  /* Now that we have all length information, allocate a buffer. */
  p = keybag = gcry_malloc (needed);
  if (!keybag)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }

  /* Walk 11 steps up to store the data. */

  /* 0. Store the first sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the data OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_data));
  memcpy (p, oid_data, DIM (oid_data));
  p += DIM (oid_data);

  /* 2. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[2]);

  /* 3. And an octet string. */
  p = store_tag_length (p, TAG_OCTET_STRING, len[3]);

  /* 4+5. Two sequences. */
  p = store_tag_length (p, TAG_SEQUENCE, len[4]);
  p = store_tag_length (p, TAG_SEQUENCE, len[5]);

  /* 6. Store the shroudedKeyBag OID. */
  p = store_tag_length (p, TAG_OBJECT_ID,
                        DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag));
  memcpy (p, oid_pkcs_12_pkcs_8ShroudedKeyBag,
          DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag));
  p += DIM (oid_pkcs_12_pkcs_8ShroudedKeyBag);

  /* 7. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[7]);

  /* 8. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[8]);

  /* 9. Now for the pre-encoded algorithm identifier and the salt. */
  memcpy (p, data_3desiter2048, DIM (data_3desiter2048));
  memcpy (p + DATA_3DESITER2048_SALT_OFF, salt, 8);
  p += DIM (data_3desiter2048);

  /* 10. And the octet string with the encrypted data. */
  p = store_tag_length (p, TAG_OCTET_STRING, buflen);
  memcpy (p, buffer, buflen);
  p += buflen;

  /* Append the attributes whose length we calculated at step 2b. */
  if (sha1hash)
    {
      int i;

      memcpy (p, data_attrtemplate, DIM (data_attrtemplate));
      for (i=0; i < 8; i++)
        p[DATA_ATTRTEMPLATE_KEYID_OFF+2*i+1] = keyidstr[i];
      p += DIM (data_attrtemplate);
      memcpy (p, sha1hash, 20);
      p += 20;
    }


  keybaglen = p - keybag;
  if (needed != keybaglen)
    log_debug ("p12_parse: warning: length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)keybaglen);

  *r_length = keybaglen;
  return keybag;
}


static unsigned char *
build_cert_bag (unsigned char *buffer, size_t buflen, char *salt,
                size_t *r_length)
{
  size_t len[9], needed;
  unsigned char *p, *certbag;
  size_t certbaglen;

  /* Walk 9 steps down to collect the info: */

  /* 8. The data goes into an octet string. */
  needed = compute_tag_length (buflen);
  needed += buflen;

  /* 7. The algorithm identifier. */
  needed += DIM (data_rc2iter2048);

  /* 6. The data OID. */
  needed += 2 + DIM (oid_data);

  /* 5. A sequence. */
  len[5] = needed;
  needed += compute_tag_length ( needed);

  /* 4. An integer. */
  needed += 3;

  /* 3. A sequence. */
  len[3] = needed;
  needed += compute_tag_length (needed);

  /* 2.  A [0] tag. */
  len[2] = needed;
  needed += compute_tag_length (needed);

  /* 1. The encryptedData OID. */
  needed += 2 + DIM (oid_encryptedData);

  /* 0. The first sequence. */
  len[0] = needed;
  needed += compute_tag_length (needed);

  /* Now that we have all length information, allocate a buffer. */
  p = certbag = gcry_malloc (needed);
  if (!certbag)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }

  /* Walk 9 steps up to store the data. */

  /* 0. Store the first sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the encryptedData OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_encryptedData));
  memcpy (p, oid_encryptedData, DIM (oid_encryptedData));
  p += DIM (oid_encryptedData);

  /* 2. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[2]);

  /* 3. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[3]);

  /* 4. Store the integer 0. */
  *p++ = TAG_INTEGER;
  *p++ = 1;
  *p++ = 0;

  /* 5. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[5]);

  /* 6. Store the data OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_data));
  memcpy (p, oid_data, DIM (oid_data));
  p += DIM (oid_data);

  /* 7. Now for the pre-encoded algorithm identifier and the salt. */
  memcpy (p, data_rc2iter2048, DIM (data_rc2iter2048));
  memcpy (p + DATA_RC2ITER2048_SALT_OFF, salt, 8);
  p += DIM (data_rc2iter2048);

  /* 8. And finally the [0] tag with the encrypted data. */
  p = store_tag_length (p, 0x80, buflen);
  memcpy (p, buffer, buflen);
  p += buflen;
  certbaglen = p - certbag;

  if (needed != certbaglen)
    log_debug ("p12_parse: warning: length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)certbaglen);

  *r_length = certbaglen;
  return certbag;
}


static unsigned char *
build_cert_sequence (const unsigned char *buffer, size_t buflen,
                     const unsigned char *sha1hash, const char *keyidstr,
                     size_t *r_length)
{
  size_t len[8], needed, n;
  unsigned char *p, *certseq;
  size_t certseqlen;
  int i;

  log_assert (strlen (keyidstr) == 8);

  /* Walk 8 steps down to collect the info: */

  /* 7. The data goes into an octet string. */
  needed = compute_tag_length (buflen);
  needed += buflen;

  /* 6. A [0] tag. */
  len[6] = needed;
  needed += compute_tag_length (needed);

  /* 5. An OID. */
  needed += 2 + DIM (oid_x509Certificate_for_pkcs_12);

  /* 4. A sequence. */
  len[4] = needed;
  needed += compute_tag_length (needed);

  /* 3. A [0] tag. */
  len[3] = needed;
  needed += compute_tag_length (needed);

  /* 2b. The attributes which are appended at the end. */
  if (sha1hash)
    needed += DIM (data_attrtemplate) + 20;

  /* 2. An OID. */
  needed += 2 + DIM (oid_pkcs_12_CertBag);

  /* 1. A sequence. */
  len[1] = needed;
  needed += compute_tag_length (needed);

  /* 0. The first sequence. */
  len[0] = needed;
  needed += compute_tag_length (needed);

  /* Now that we have all length information, allocate a buffer. */
  p = certseq = gcry_malloc (needed + 8 /*(for padding)*/);
  if (!certseq)
    {
      log_error ("error allocating buffer\n");
      return NULL;
    }

  /* Walk 8 steps up to store the data. */

  /* 0. Store the first sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[0]);

  /* 1. Store the second sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[1]);

  /* 2. Store the pkcs12-cert-bag OID. */
  p = store_tag_length (p, TAG_OBJECT_ID, DIM (oid_pkcs_12_CertBag));
  memcpy (p, oid_pkcs_12_CertBag, DIM (oid_pkcs_12_CertBag));
  p += DIM (oid_pkcs_12_CertBag);

  /* 3. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[3]);

  /* 4. Store a sequence. */
  p = store_tag_length (p, TAG_SEQUENCE, len[4]);

  /* 5. Store the x509Certificate OID. */
  p = store_tag_length (p, TAG_OBJECT_ID,
                        DIM (oid_x509Certificate_for_pkcs_12));
  memcpy (p, oid_x509Certificate_for_pkcs_12,
          DIM (oid_x509Certificate_for_pkcs_12));
  p += DIM (oid_x509Certificate_for_pkcs_12);

  /* 6. Store a [0] tag. */
  p = store_tag_length (p, 0xa0, len[6]);

  /* 7. And the octet string with the actual certificate. */
  p = store_tag_length (p, TAG_OCTET_STRING, buflen);
  memcpy (p, buffer, buflen);
  p += buflen;

  /* Append the attributes whose length we calculated at step 2b. */
  if (sha1hash)
    {
      memcpy (p, data_attrtemplate, DIM (data_attrtemplate));
      for (i=0; i < 8; i++)
        p[DATA_ATTRTEMPLATE_KEYID_OFF+2*i+1] = keyidstr[i];
      p += DIM (data_attrtemplate);
      memcpy (p, sha1hash, 20);
      p += 20;
    }

  certseqlen = p - certseq;
  if (needed != certseqlen)
    log_debug ("p12_parse: warning: length mismatch: %lu, %lu\n",
               (unsigned long)needed, (unsigned long)certseqlen);

  /* Append some pad characters; we already allocated extra space. */
  n = 8 - certseqlen % 8;
  for (i=0; i < n; i++, certseqlen++)
    *p++ = n;

  *r_length = certseqlen;
  return certseq;
}


/* Expect the RSA key parameters in KPARMS and a password in PW.
   Create a PKCS structure from it and return it as well as the length
   in R_LENGTH; return NULL in case of an error.  If CHARSET is not
   NULL, re-encode PW to that character set. */
unsigned char *
p12_build (gcry_mpi_t *kparms, const void *cert, size_t certlen,
           const char *pw, const char *charset, size_t *r_length)
{
  unsigned char *buffer = NULL;
  size_t n, buflen;
  char salt[8];
  struct buffer_s seqlist[3];
  int seqlistidx = 0;
  unsigned char sha1hash[20];
  char keyidstr[8+1];
  char *pwbuf = NULL;
  size_t pwbufsize = 0;

  n = buflen = 0; /* (avoid compiler warning). */
  memset (sha1hash, 0, 20);
  *keyidstr = 0;

  if (charset && pw && *pw)
    {
      jnlib_iconv_t cd;
      const char *inptr;
      char *outptr;
      size_t inbytes, outbytes;

      /* We assume that the converted passphrase is at max 2 times
         longer than its utf-8 encoding. */
      pwbufsize = strlen (pw)*2 + 1;
      pwbuf = gcry_malloc_secure (pwbufsize);
      if (!pwbuf)
        {
          log_error ("out of secure memory while converting passphrase\n");
          goto failure;
        }

      cd = jnlib_iconv_open (charset, "utf-8");
      if (cd == (jnlib_iconv_t)(-1))
        {
          log_error ("can't convert passphrase to"
                     " requested charset '%s': %s\n",
                     charset, strerror (errno));
          goto failure;
        }

      inptr = pw;
      inbytes = strlen (pw);
      outptr = pwbuf;
      outbytes = pwbufsize - 1;
      if ( jnlib_iconv (cd, (const char **)&inptr, &inbytes,
                      &outptr, &outbytes) == (size_t)-1)
        {
          log_error ("error converting passphrase to"
                     " requested charset '%s': %s\n",
                     charset, strerror (errno));
          jnlib_iconv_close (cd);
          goto failure;
        }
      *outptr = 0;
      jnlib_iconv_close (cd);
      pw = pwbuf;
    }


  if (cert && certlen)
    {
      /* Calculate the hash value we need for the bag attributes. */
      gcry_md_hash_buffer (GCRY_MD_SHA1, sha1hash, cert, certlen);
      sprintf (keyidstr, "%02x%02x%02x%02x",
               sha1hash[16], sha1hash[17], sha1hash[18], sha1hash[19]);

      /* Encode the certificate. */
      buffer = build_cert_sequence (cert, certlen, sha1hash, keyidstr,
                                    &buflen);
      if (!buffer)
        goto failure;

      /* Encrypt it. */
      gcry_randomize (salt, 8, GCRY_STRONG_RANDOM);
      crypt_block (buffer, buflen, salt, 8, 2048, NULL, 0, pw,
                   GCRY_CIPHER_RFC2268_40, GCRY_MD_SHA1, 1);

      /* Encode the encrypted stuff into a bag. */
      seqlist[seqlistidx].buffer = build_cert_bag (buffer, buflen, salt, &n);
      seqlist[seqlistidx].length = n;
      gcry_free (buffer);
      buffer = NULL;
      if (!seqlist[seqlistidx].buffer)
        goto failure;
      seqlistidx++;
    }


  if (kparms)
    {
      /* Encode the key. */
      int i;

      /* Right, that is a stupid way to distinguish ECC from RSA.  */
      for (i=0; kparms[i]; i++)
        ;

      if (i == 3 && gcry_mpi_get_flag (kparms[0], GCRYMPI_FLAG_OPAQUE))
        buffer = build_ecc_key_sequence (kparms, 0, &buflen);
      else
        buffer = build_rsa_key_sequence (kparms, 0, &buflen);
      if (!buffer)
        goto failure;

      /* Encrypt it. */
      gcry_randomize (salt, 8, GCRY_STRONG_RANDOM);
      crypt_block (buffer, buflen, salt, 8, 2048, NULL, 0,
                   pw, GCRY_CIPHER_3DES, GCRY_MD_SHA1, 1);

      /* Encode the encrypted stuff into a bag. */
      if (cert && certlen)
        seqlist[seqlistidx].buffer = build_key_bag (buffer, buflen, salt,
                                                    sha1hash, keyidstr, &n);
      else
        seqlist[seqlistidx].buffer = build_key_bag (buffer, buflen, salt,
                                                    NULL, NULL, &n);
      seqlist[seqlistidx].length = n;
      gcry_free (buffer);
      buffer = NULL;
      if (!seqlist[seqlistidx].buffer)
        goto failure;
      seqlistidx++;
    }

  seqlist[seqlistidx].buffer = NULL;
  seqlist[seqlistidx].length = 0;

  buffer = create_final (seqlist, pw, &buflen);

 failure:
  if (pwbuf)
    {
      /* Note that wipememory is not really needed due to the use of
         gcry_malloc_secure.  */
      wipememory (pwbuf, pwbufsize);
      gcry_free (pwbuf);
    }
  for ( ; seqlistidx; seqlistidx--)
    gcry_free (seqlist[seqlistidx].buffer);

  *r_length = buffer? buflen : 0;
  return buffer;
}


/* This is actually not a PKCS#12 function but one which creates an
 * unencrypted PKCS#1 private key.  */
unsigned char *
p12_raw_build (gcry_mpi_t *kparms, int rawmode, size_t *r_length)
{
  unsigned char *buffer;
  size_t buflen;
  int i;

  log_assert (rawmode == 1 || rawmode == 2);

  /* Right, that is a stupid way to distinguish ECC from RSA.  */
  for (i=0; kparms[i]; i++)
    ;

  if (gcry_mpi_get_flag (kparms[0], GCRYMPI_FLAG_OPAQUE))
    buffer = build_ecc_key_sequence (kparms, rawmode, &buflen);
  else
    buffer = build_rsa_key_sequence (kparms, rawmode, &buflen);
  if (!buffer)
    return NULL;

  *r_length = buflen;
  return buffer;
}
