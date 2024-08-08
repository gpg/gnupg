/* tlv-parser.c - Parse BER encoded objects
 * Copyright (C) 2023, 2024 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gpg-error.h>

#include "util.h"
#include "tlv.h"


#define TLV_MAX_DEPTH 25



/* An object to control the ASN.1 parsing.  */
struct tlv_parser_s
{
  /* The original buffer with the entire pkcs#12 object and its length.  */
  unsigned char *origbuffer;
  size_t origbufsize;

  /* The original offset for debugging.  */
  size_t origoff;

  /* Here we keep a copy of the former TLV.  This is returned by
   * tlv_parser_release.  */
  tlv_parser_t lasttlv;

  /* The current buffer we are working on and its length. */
  unsigned char *buffer;
  size_t bufsize;

  size_t crammed;      /* 0 or actual length of crammed octet strings.  */
  int in_ndef;         /* Flag indicating that we are in a NDEF. */
  int pending;         /* The last tlv_next has not yet been processed.  */

  struct tag_info ti;  /* The current tag.  */
  gpg_error_t lasterr; /* Last error from tlv function.  */
  const char *lastfunc;/* Name of last called function.  */
  int verbosity;       /* Arg from tlv_parser_new.       */

  unsigned int stacklen; /* Used size of the stack.  */
  struct {
    unsigned char *buffer;        /* Saved value of BUFFER.   */
    size_t bufsize;               /* Saved value of BUFSIZE.  */
    size_t length;                /* Length of the container (ti.length). */
    size_t crammed;               /* Saved CRAMMED value.                 */
    int    in_ndef;               /* Saved IN_NDEF flag (ti.ndef).        */
  } stack[TLV_MAX_DEPTH];
};


static size_t cram_octet_string (tlv_parser_t tlv, int testmode);



void
_tlv_parser_dump_tag (const char *text, int lno, tlv_parser_t tlv)
{
  struct tag_info *ti;

  if (!tlv || tlv->verbosity < 2)
    return;

  ti = &tlv->ti;

  log_debug ("%s:%d: %zu@%04zu class=%d tag=%lu %c len=%zu%s nhdr=%zu\n",
             text, lno, tlv->origoff, tlv_parser_offset (tlv) - ti->nhdr,
             ti->class, ti->tag, ti->is_constructed?'c':'p',
             ti->length,ti->ndef?" ndef":"", ti->nhdr);
}


void
_tlv_parser_dump_state (const char *text, const char *text2,
                        int lno, tlv_parser_t tlv)
{
  if (!tlv || tlv->verbosity < 2)
    return;

  log_debug ("p12_parse:%s%s%s:%d: %zu@%04zu lvl=%u %s\n",
             text,
             text2? "/":"", text2? text2:"",
             lno, tlv->origoff, tlv_parser_offset (tlv),
             tlv->stacklen,
             tlv->in_ndef? " in-ndef":"");
}


static void
dump_to_file (const void *s, size_t n, const char *name)
{
#if 0
  FILE *fp;
  char fname[100];
  static int fcount;

  snprintf (fname, sizeof fname, "tmp-%03d-%s", ++fcount, name);
  log_debug ("dumping %zu bytes to '%s'\n", n, fname);
  fp = fopen (fname, "wb");
  if (!fp || fwrite (s, n, 1, fp) != 1)
    exit (2);
  fclose (fp);
#else
  (void)s;
  (void)n;
  (void)name;
#endif
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
    {
      /* data larger than buffer. */
      log_debug ("%s: ti->length=%zu for a buffer of size=%zu\n",
                 __func__, ti->length, *size);
      return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
    }

  return 0;
}

/* Public version of parse_tag.  */
gpg_error_t
tlv_parse_tag (unsigned char const **buffer, size_t *size, struct tag_info *ti)
{
  return parse_tag (buffer, size, ti);
}


/* Create a new TLV object.  */
tlv_parser_t
_tlv_parser_new (const unsigned char *buffer, size_t bufsize,
                int verbosity, tlv_parser_t lasttlv, int lno)
{
  tlv_parser_t tlv;

  if (verbosity > 1)
    log_debug ("%s:%d: %zu@%zu (%p,%zu)\n", __func__, lno,
               lasttlv?lasttlv->origoff:0, tlv_parser_offset (lasttlv),
               buffer, bufsize);

  tlv = xtrycalloc (1, sizeof *tlv);
  if (tlv)
    {
      char *mybuf = xtrymalloc ( bufsize + 1);
      if (!mybuf)
        {
          xfree (tlv);
          return NULL;
        }
      memcpy (mybuf, buffer, bufsize);
      mybuf[bufsize] = 0;
      tlv->origbuffer = mybuf;
      tlv->origbufsize = bufsize;
      tlv->origoff = tlv_parser_offset (lasttlv);
      tlv->buffer = mybuf;
      tlv->bufsize = bufsize;
      tlv->crammed = 0;
      tlv->verbosity = verbosity;
      tlv->lasttlv = lasttlv;
      dump_to_file (mybuf, bufsize, "context");
    }
  return tlv;
}


/* Free the TLV object and returns the last TLV object stored in this
 * TLV.  */
tlv_parser_t
_tlv_parser_release (tlv_parser_t tlv, int lno)
{
  tlv_parser_t result;

  if (!tlv)
    return NULL;
  result = tlv->lasttlv;
  if (tlv->verbosity > 1)
    {
      if (result)
        log_debug ("%s:%d: done; returning last TLV %zu@%zu (%p,%zu)\n",
                   __func__, lno, result->origoff,
                   tlv_parser_offset (result), result->buffer, result->bufsize);
      else
        log_debug ("%s:%d: done\n", __func__, lno);
    }
  xfree (tlv->origbuffer);
  xfree (tlv);
  return result;
}


/* Helper for tlv_expect_sequence and tlv_expect_context_tag.  */
static gpg_error_t
_tlv_push (tlv_parser_t tlv)
{

  /* Right now our pointer is at the value of the current container.
   * We push that info onto the stack.  */
  if (tlv->stacklen >= TLV_MAX_DEPTH)
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_MANY));
  tlv->stack[tlv->stacklen].buffer  = tlv->buffer;
  tlv->stack[tlv->stacklen].bufsize = tlv->bufsize;
  tlv->stack[tlv->stacklen].in_ndef = tlv->in_ndef;
  tlv->stack[tlv->stacklen].length  = tlv->ti.length;
  tlv->stack[tlv->stacklen].crammed = tlv->crammed;
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

  _tlv_parser_dump_state (__func__, NULL, 0, tlv);
  return 0;
}


/* Helper for tlv_next.  */
static gpg_error_t
_tlv_pop (tlv_parser_t tlv)
{
  size_t length;

  /* We reached the end of a container, either due to the size limit
   * or due to an end tag.  Now we pop the last container so that we
   * are positioned at the value of the last container. */
  if (!tlv->stacklen)
    return gpg_error (GPG_ERR_EOF);

  tlv->stacklen--;
  tlv->in_ndef = tlv->stack[tlv->stacklen].in_ndef;
  length = tlv->ti.length = tlv->stack[tlv->stacklen].length;
  tlv->crammed = tlv->stack[tlv->stacklen].crammed;
  if (tlv->in_ndef)
    {
      /* We keep buffer but adjust bufsize to the end of the origbuffer. */
      if ((tlv->buffer - tlv->origbuffer) > tlv->origbufsize)
        return (tlv->lasterr = gpg_error (GPG_ERR_BUG));
      tlv->bufsize = tlv->origbufsize - (tlv->buffer - tlv->origbuffer);
    }
  else
    {
      tlv->buffer  = tlv->stack[tlv->stacklen].buffer;
      tlv->bufsize = tlv->stack[tlv->stacklen].bufsize;
      if (length > tlv->bufsize)
        {
          if (tlv->verbosity > 1)
            log_debug ("%s: container larger than buffer (%zu/%zu)\n",
                       __func__, length, tlv->bufsize);
          return gpg_error (GPG_ERR_INV_BER);
        }
      tlv->buffer += length;
      tlv->bufsize -= length;

    }
  _tlv_parser_dump_state (__func__, NULL, 0, tlv);
  return 0;
}


/* Parse the next tag and value.  Also detect the end of a
 * container.  The caller should use the tlv_next macro. */
gpg_error_t
_tlv_parser_next (tlv_parser_t tlv, unsigned int flag, int lno)
{
  gpg_error_t err;
  const unsigned char *buffer;
  size_t save_bufsize;
  const unsigned char *save_buffer;
  int i;

  tlv->lasterr = 0;
  tlv->lastfunc = __func__;

  if (tlv->pending)
    {
      tlv->pending = 0;
      if (tlv->verbosity > 1)
        log_debug ("%s:%d: skipped\n", __func__, lno);
      return 0;
    }

  if (tlv->verbosity > 1)
    log_debug ("%s:%d: called (%p,%zu)\n", __func__, lno,
               tlv->buffer, tlv->bufsize);
  /* If we are at the end of an ndef container pop the stack.  */
  if (!tlv->in_ndef && !tlv->bufsize)
    {
      if (tlv->verbosity > 1)
        for (i=0; i < tlv->stacklen; i++)
          log_debug ("%s: stack[%d] (%p,@%zu,%zu) len=%zu (%zu) %s\n",
                     __func__, i,
                     tlv->stack[i].buffer,
                     tlv->stack[i].buffer - tlv->origbuffer,
                     tlv->stack[i].bufsize,
                     tlv->stack[i].length,
                     tlv->stack[i].crammed,
                     tlv->stack[i].in_ndef? " ndef":"");
      do
        err = _tlv_pop (tlv);
      while (!err && !tlv->in_ndef && !tlv->bufsize);

      if (err)
        return (tlv->lasterr = err);
      if (tlv->verbosity > 1)
        log_debug ("%s: container(s) closed due to size (lvl=%d)\n",
                   __func__, tlv->stacklen);
    }

 again:
  /* Get the next tag.  */
  save_buffer = buffer = tlv->buffer;
  save_bufsize = tlv->bufsize;
  err = parse_tag (&buffer, &tlv->bufsize, &tlv->ti);
  tlv->buffer = (unsigned char *)buffer;
  if (err)
    {
      if (tlv->verbosity > 1)
        {
          log_debug ("%s: reading tag returned err=%d\n", __func__, err);
          log_printhex (save_buffer, save_bufsize > 40? 40: save_bufsize,
                        "%s: data was\n", __func__);
          dump_to_file (tlv->origbuffer, save_buffer - tlv->origbuffer,
                        "parseerr");
        }
      return err;
    }

  if ( ( (tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_OCTET_STRING)
         || ((flag & TLV_PARSER_FLAG_T5793)
             && tlv->ti.class == CLASS_CONTEXT && tlv->ti.tag == 0))
       && tlv->ti.is_constructed && cram_octet_string (tlv, 1))
    {
      if (tlv->verbosity > 1)
        log_debug ("%s: cramming %s\n", __func__,
                   tlv->ti.tag? "constructed octet strings":"for Mozilla bug");
      if (!cram_octet_string (tlv, 0))
        return (tlv->lasterr = gpg_error (GPG_ERR_BAD_BER));
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
      if (tlv->verbosity > 1)
        log_debug ("%s: container(s) closed due to end tag (lvl=%d)\n",
                   __func__, tlv->stacklen);
      goto again;
    }

  _tlv_parser_dump_tag (__func__, lno, tlv);
  return 0;
}


/* Return the current neting level of the TLV object.  */
unsigned int
tlv_parser_level (tlv_parser_t tlv)
{
  return tlv? tlv->stacklen : 0;
}

/* Returns the current offset of the parser.  */
size_t
tlv_parser_offset (tlv_parser_t tlv)
{
  return tlv? (size_t)(tlv->buffer - tlv->origbuffer) : 0;
}


/* Return a string with the last function used.  If TLV is NULL an
 * empty string is returned.  */
const char *
tlv_parser_lastfunc (tlv_parser_t tlv)
{
  return tlv? tlv->lastfunc:"";
}


const char *
tlv_parser_lasterrstr (tlv_parser_t tlv)
{
  return tlv? gpg_strerror (tlv->lasterr) : "tlv parser not yet initialized";
}


/* Set a flag to indicate that the last tlv_next has not yet been
 * consumed.  */
void
tlv_parser_set_pending (tlv_parser_t tlv)
{
  tlv->pending = 1;
}


/* Return the length of the last read tag.  If with_header is 1 the
 * lengtb of the header is added to the returned length.  */
size_t
tlv_parser_tag_length (tlv_parser_t tlv, int with_header)
{
  if (with_header)
    return tlv->ti.length + tlv->ti.nhdr;
  else
    return tlv->ti.length;
}


/* Skip over the value of the current tag.  Does not yet work for ndef
 * containers.  */
void
tlv_parser_skip (tlv_parser_t tlv)
{
  tlv->lastfunc = __func__;
  log_assert (tlv->bufsize >= tlv->ti.length);
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
}


/* Expect that the current tag is a sequence and setup the context for
 * processing.  */
gpg_error_t
tlv_expect_sequence (tlv_parser_t tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_SEQUENCE
        && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return _tlv_push (tlv);
}


/* Expect that the current tag is a context tag and setup the context
 * for processing.  The tag of the context is returned at R_TAG.  */
gpg_error_t
tlv_expect_context_tag (tlv_parser_t tlv, int *r_tag)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_CONTEXT && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  *r_tag = tlv->ti.tag;
  return _tlv_push (tlv);
}


/* Expect that the current tag is a SET and setup the context for
 * processing.  */
gpg_error_t
tlv_expect_set (tlv_parser_t tlv)
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
gpg_error_t
tlv_expect_object (tlv_parser_t tlv, int class, int tag,
                   unsigned char const **r_data, size_t *r_datalen)
{
  const unsigned char *p;
  size_t n;
  int needpush = 0;

  tlv->lastfunc = __func__;
  /* Note that the parser has already crammed the octet strings for a
   * [0] to workaround the Mozilla bug.  */
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

  if (tlv->verbosity > 1)
    log_debug ("%s: %zu@%zu %c len=%zu (%zu) bufsize=%zu of %zu\n",
               __func__,
               tlv->origoff, tlv_parser_offset (tlv),
               tlv->ti.is_constructed? 'c':'p',
               n, tlv->crammed,
               tlv->bufsize, tlv->origbufsize);

  if (r_data)
    *r_data = p;
  if (r_datalen)
    *r_datalen = tlv->crammed? tlv->crammed : n;

  if (needpush)
    return _tlv_push (tlv);

  if (!(tlv->bufsize >= n))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += n;
  tlv->bufsize -= n;
  tlv->crammed = 0;
  return 0;
}


/* Expect that the current tag is an object string and store its value
 * at (R_DATA,R_DATALEN).  Then skip over its value to the next tag.
 * Note that the stored value are not allocated but point into TLV. */
gpg_error_t
tlv_expect_octet_string (tlv_parser_t tlv,
                         unsigned char const **r_data, size_t *r_datalen)
{
  size_t n;

  tlv->lastfunc = __func__;
  /* The parser has already crammed constructed octet strings.  */
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_OCTET_STRING))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  if (!(n=tlv->ti.length) || tlv->ti.ndef )
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  if (tlv->verbosity > 1)
    log_debug ("%s: %zu@%zu %c len=%zu (%zu) bufsize=%zu of %zu\n",
               __func__,
               tlv->origoff, tlv_parser_offset (tlv),
               tlv->ti.is_constructed? 'c':'p',
               n, tlv->crammed,
               tlv->bufsize, tlv->origbufsize);

  if (r_data)
    *r_data = tlv->buffer;
  if (r_datalen)
    *r_datalen = tlv->crammed? tlv->crammed : tlv->ti.length;

  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  tlv->crammed = 0;
  return 0;
}


/* Expect that the current tag is an integer and return its value at
 * R_VALUE.  Then skip over its value to the next tag. */
gpg_error_t
tlv_expect_integer (tlv_parser_t tlv, int *r_value)
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
 * integers is done because the old code here worked the same and we
 * can't foreclose invalid encoded PKCS#12 stuff - after all it is
 * PKCS#12 see https://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html */
#ifdef GCRYPT_VERSION
gpg_error_t
tlv_expect_mpinteger (tlv_parser_t tlv, int ignore_zero,
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
#endif /*GCRYPT_VERSION*/


/* Expect that the current tag is an object id and store its value at
 * (R_OID,R_OIDLEN).  Then skip over its value to the next tag.  Note
 * that the stored value is not allocated but points into TLV. */
gpg_error_t
tlv_expect_object_id (tlv_parser_t tlv,
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


/* Expect a NULL tag.  */
gpg_error_t
tlv_expect_null (tlv_parser_t tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_NULL
        && !tlv->ti.is_constructed && !tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return 0;
}


/* Given a BER encoded constructed octet string like the example below
 * from Mozilla Firefox 1.0.4 (which actually exports certs as single
 * byte chunks of octet strings) in the buffer described by TLV.
 * Although the example uses an ndef for the length of the constructed
 * octet string, a fixed length is also allowed.
 *
 *   24 NDEF:       OCTET STRING
 *   04    1:         OCTET STRING  -- TLV->buffer points to here
 *          :           30
 *   04    1:         OCTET STRING
 *          :           80
 *        [...]
 *   04    2:         OCTET STRING
 *          :           00 00
 *          :         } -- This denotes a Null tag and are the last
 *                      -- two bytes in INPUT.
 *
 * Turn it into a primitive octet string of this form:
 *
 *   24    2:       OCTET STRING
 *          :         30 80
 *
 * and fill it up with FE to the original length.  Unless TESTMODE is
 * true the TLV object including the the member and the data is
 * adjusted accordingly; however the intiial tag is not changed (in
 * the example the "24 NDEF") because this is not needed anymore.
 *
 * On error 0 is returned and in this case the buffer might have
 * already been modified and thus the caller should better stop
 * parsing - unless TESTMODE was used.  */
static size_t
cram_octet_string (tlv_parser_t tlv, int testmode)
{
  gpg_error_t err;
  size_t totallen;    /* Length of the non-crammed octet strings.  */
  size_t crammedlen;  /* Length of the crammed octet strings.  */
  const unsigned char *s, *save_s;
  unsigned char *d;
  size_t n, save_n;
  struct tag_info ti;

  if (tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TAG_OCTET_STRING)
    ;  /* Okay.  */
  else if (tlv->ti.class == CLASS_CONTEXT && tlv->ti.tag == 0)
    ;  /* Workaround for Mozilla bug; see T5793  */
  else
    return 0;  /* Oops - we should not have been called.  */
  if (!tlv->ti.is_constructed)
    return 0;  /* Oops - Not a constructed octet string.  */
  if (!tlv->ti.ndef && tlv->ti.length < 4)
    return 0;  /* Fixed length but too short.  */

  /* Let S point to the first octet string chunk.  */
  s = tlv->buffer;
  n = tlv->ti.ndef? tlv->bufsize : tlv->ti.length;

  d = (unsigned char *)s;
  totallen = crammedlen = 0;
  while (n)
    {
      save_s = s;
      save_n = n;
      if ((err=parse_tag (&s, &n, &ti)))
        {
          if (tlv->verbosity > 1)
            {
              log_debug ("%s: parse_tag(n=%zu) failed : %s\n",
                         __func__, save_n, gpg_strerror (err));
              log_printhex (save_s, save_n > 40? 40:save_n, "%s: data was",
                            __func__);
            }
          return 0;
        }
      if (tlv->verbosity > 1)
        log_debug ("%s:%s ti.ndef=%d ti.tag=%lu ti.length=%zu (n %zu->%zu)\n",
                   __func__, testmode?"test:":"",
                   ti.ndef, ti.tag, ti.length, save_n, n);
      if (ti.class == CLASS_UNIVERSAL && ti.tag == TAG_OCTET_STRING
          && !ti.ndef && !ti.is_constructed)
        {
          if (!testmode)
            memmove (d, s, ti.length);
          d += ti.length;  /* Update destination */
          totallen += ti.length + ti.nhdr;
          crammedlen += ti.length;
          s += ti.length;  /* Skip to next tag.  */
          n -= ti.length;
        }
      else if (ti.class == CLASS_UNIVERSAL && !ti.tag && !ti.is_constructed)
        {
          totallen += ti.nhdr;
          break; /* EOC - Ready */
        }
      else
        return 0; /* Invalid data.  */
    }
  if (!testmode)
    {
      memset (d, '\xfe', totallen - crammedlen);
      tlv->ti.length = totallen;
      tlv->ti.is_constructed = 0;
      tlv->ti.ndef = 0;
      tlv->crammed = crammedlen;
      if (tlv->verbosity > 1)
        {
          log_debug ("%s: crammed length is %zu\n", __func__, crammedlen);
          log_debug ("%s:   total length is %zu\n", __func__, totallen);
        }
      dump_to_file (tlv->buffer, totallen, "crammed");
    }
  return totallen;
}
