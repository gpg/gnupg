/* tlv-parser.c - Parse BER encoded objects
 * Copyright (C) 2023 g10 Code GmbH
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


struct bufferlist_s
{
  struct bufferlist_s *next;
  char *buffer;
};


/* An object to control the ASN.1 parsing.  */
struct tlv_parser_s
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
  int verbosity;       /* Arg from tlv_parser_new.       */

  struct bufferlist_s *bufferlist;  /* To keep track of malloced buffers. */

  unsigned int stacklen; /* Used size of the stack.  */
  struct {
    const unsigned char *buffer;  /* Saved value of BUFFER.   */
    size_t bufsize;               /* Saved value of BUFSIZE.  */
    size_t length;                /* Length of the container (ti.length). */
    int    in_ndef;               /* Saved IN_NDEF flag (ti.ndef).        */
  } stack[TLV_MAX_DEPTH];
};


static unsigned char *cram_octet_string (const unsigned char *input,
                                         size_t length, size_t *r_newlength);
static int need_octet_string_cramming (const unsigned char *input,
                                       size_t length);



void
_tlv_parser_dump_tag (const char *text, int lno, tlv_parser_t tlv)
{
  struct tag_info *ti;

  if (!tlv || tlv->verbosity < 2)
    return;

  ti = &tlv->ti;

  log_debug ("p12_parse:%s:%d: @%04zu class=%d tag=%lu len=%zu nhdr=%zu %s%s\n",
             text, lno,
             (size_t)(tlv->buffer - tlv->origbuffer) - ti->nhdr,
             ti->class, ti->tag, ti->length, ti->nhdr,
             ti->is_constructed?" cons":"",
             ti->ndef?" ndef":"");
}


void
_tlv_parser_dump_state (const char *text, const char *text2,
                        int lno, tlv_parser_t tlv)
{
  if (!tlv || tlv->verbosity < 2)
    return;

  log_debug ("p12_parse:%s%s%s:%d: @%04zu lvl=%u %s\n",
             text,
             text2? "/":"", text2? text2:"",
             lno,
             (size_t)(tlv->buffer - tlv->origbuffer),
             tlv->stacklen,
             tlv->in_ndef? " in-ndef":"");
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

/* Public version of parse_tag.  */
gpg_error_t
tlv_parse_tag (unsigned char const **buffer, size_t *size, struct tag_info *ti)
{
  return parse_tag (buffer, size, ti);
}


/* Create a new TLV object.  */
tlv_parser_t
tlv_parser_new (const unsigned char *buffer, size_t bufsize, int verbosity)
{
  tlv_parser_t tlv;
  tlv = xtrycalloc (1, sizeof *tlv);
  if (tlv)
    {
      tlv->origbuffer = buffer;
      tlv->origbufsize = bufsize;
      tlv->buffer = buffer;
      tlv->bufsize = bufsize;
      tlv->verbosity = verbosity;
    }
  return tlv;
}


/* This function can be used to store a malloced buffer into the TLV
 * object.  Ownership of BUFFER is thus transferred to TLV.  This
 * buffer will then only be released by tlv_release. */
static gpg_error_t
register_buffer (tlv_parser_t tlv, char *buffer)
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


void
tlv_parser_release (tlv_parser_t tlv)
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
_tlv_peek (tlv_parser_t tlv, struct tag_info *ti)
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
int
_tlv_parser_peek (tlv_parser_t tlv, int class, int tag)
{
  struct tag_info ti;

  return (!_tlv_peek (tlv, &ti)
          && ti.class == class && ti.tag == tag);
}


/* Look for the next tag and return true if it is the Null tag.
 * Otherwise return false.  No state is changed.  */
int
_tlv_parser_peek_null (tlv_parser_t tlv)
{
  struct tag_info ti;

  return (!_tlv_peek (tlv, &ti)
          && ti.class == CLASS_UNIVERSAL && ti.tag == TAG_NULL
          && !ti.is_constructed && !ti.length);
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

  _tlv_parser_dump_state (__func__, NULL, 0, tlv);
  return 0;
}


/* Parse the next tag and value.  Also detect the end of a
 * container.  The caller should use the tlv_next macro. */
gpg_error_t
_tlv_parser_next (tlv_parser_t tlv, int lno)
{
  gpg_error_t err;

  tlv->lasterr = 0;
  tlv->lastfunc = __func__;

  if (tlv->pending)
    {
      tlv->pending = 0;
      if (tlv->verbosity > 1)
        log_debug ("%s: skipped\n", __func__);
      return 0;
    }

  if (tlv->verbosity > 1)
    log_debug ("%s: called\n", __func__);
  /* If we are at the end of an ndef container pop the stack.  */
  if (!tlv->in_ndef && !tlv->bufsize)
    {
      do
        err = _tlv_pop (tlv);
      while (!err && !tlv->in_ndef && !tlv->bufsize);
      if (err)
        return (tlv->lasterr = err);
      if (tlv->verbosity > 1)
        log_debug ("%s: container(s) closed due to size\n", __func__);
    }

 again:
  /* Get the next tag.  */
  err = parse_tag (&tlv->buffer, &tlv->bufsize, &tlv->ti);
  if (err)
    {
      if (tlv->verbosity > 1)
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
      if (tlv->verbosity > 1)
        log_debug ("%s: container(s) closed due to end tag\n", __func__);
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
      err = register_buffer (tlv, newbuffer);
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
gpg_error_t
tlv_expect_octet_string (tlv_parser_t tlv, int encapsulates,
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
      err = register_buffer (tlv, newbuffer);
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
  d = output = xtrymalloc (length);
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
  xfree (output);
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
