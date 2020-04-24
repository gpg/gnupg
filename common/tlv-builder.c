/* tlv-builder.c - Build DER encoded objects
 * Copyright (C) 2020 g10 Code GmbH
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


struct item_s
{
  int class;
  int tag;
  unsigned int is_constructed:1; /* This is a constructed element.  */
  unsigned int is_stop:1;        /* This is a STOP item.            */
  const void *value;
  size_t valuelen;
  char *buffer;                  /* Malloced space or NULL.  */
};


struct tlv_builder_s
{
  gpg_error_t error;      /* Last error.  */
  int use_secure;         /* Use secure memory for the result.    */
  size_t nallocateditems; /* Number of allocated items.  */
  size_t nitems;          /* Number of used items.  */
  struct item_s *items;   /* Array of items.  */
  int laststop;           /* Used as return value of compute_length.  */
};


/* Allocate a new TLV Builder instance.  Returns NULL on error.  If
 * SECURE is set the final object is stored in secure memory.  */
tlv_builder_t
tlv_builder_new (int secure)
{
  tlv_builder_t tb;

  tb = xtrycalloc (1, sizeof *tb);
  if (tb && secure)
    tb->use_secure = 1;
  return tb;
}


/* Make sure the array of items is large enough for one new item.
 * Records any error in TB and returns true in that case.  */
static int
ensure_space (tlv_builder_t tb)
{
  struct item_s *newitems;

  if (!tb || tb->error)
    return 1;

  if (tb->nitems == tb->nallocateditems)
    {
      tb->nallocateditems += 32;
      newitems = gpgrt_reallocarray (tb->items, tb->nitems,
                                     tb->nallocateditems, sizeof *newitems);
      if (!newitems)
        tb->error = gpg_error_from_syserror ();
      else
        tb->items = newitems;
    }
  return !!tb->error;
}



/* Add a new primitive element to the builder instance TB.  The
 * element is described by CLASS, TAG, VALUE, and VALUEEN.  CLASS and
 * TAG must describe a primitive element and (VALUE,VALUELEN) specify
 * its value.  The value is a pointer and its object must not be
 * changed as long as the instance TB exists.  For a TAG_NULL no vlaue
 * is expected.  Errors are not returned but recorded for later
 * retrieval.  */
void
tlv_builder_add_ptr (tlv_builder_t tb, int class, int tag,
                     void *value, size_t valuelen)
{
  if (ensure_space (tb))
    return;
  tb->items[tb->nitems].class    = class;
  tb->items[tb->nitems].tag      = tag;
  tb->items[tb->nitems].value    = value;
  tb->items[tb->nitems].valuelen = valuelen;
  tb->nitems++;
}


/* This is the same as tlv_builder_add_ptr but it takes a copy of the
 * value and thus the caller does not need to care about it.  */
void
tlv_builder_add_val (tlv_builder_t tb, int class, int tag,
                     const void *value, size_t valuelen)
{
  void *p;

  if (ensure_space (tb))
    return;
  if (!value || !valuelen)
    {
      tb->error = gpg_error (GPG_ERR_INV_VALUE);
      return;
    }
  p = tb->use_secure? xtrymalloc_secure (valuelen) : xtrymalloc (valuelen);
  if (!p)
    {
      tb->error = gpg_error_from_syserror ();
      return;
    }
  memcpy (p, value, valuelen);
  tb->items[tb->nitems].buffer   = p;
  tb->items[tb->nitems].class    = class;
  tb->items[tb->nitems].tag      = tag;
  tb->items[tb->nitems].value    = p;
  tb->items[tb->nitems].valuelen = valuelen;
  tb->nitems++;
}


/* Add a new constructed object to the builder instance TB.  The
 * object is described by CLASS and TAG which must describe a
 * constructed object.  The elements of the constructed objects are
 * added with more call to the add functions.  To close a constructed
 * element a call to tlv_builer_add_end is required.  Errors are not
 * returned but recorded for later retrieval.  */
void
tlv_builder_add_tag (tlv_builder_t tb, int class, int tag)
{
  if (ensure_space (tb))
    return;
  tb->items[tb->nitems].class    = class;
  tb->items[tb->nitems].tag      = tag;
  tb->items[tb->nitems].is_constructed = 1;
  tb->nitems++;
}


/* A call to this function closes a constructed element.  This must be
 * called even for an empty constructed element.  */
void
tlv_builder_add_end (tlv_builder_t tb)
{
  if (ensure_space (tb))
    return;
  tb->items[tb->nitems].is_stop = 1;
  tb->nitems++;
}


/* Compute and set the length of all constructed elements in the item
 * array of TB starting at IDX up to the corresponding stop item.  On
 * error tb->error is set.  */
static size_t
compute_lengths (tlv_builder_t tb, int idx)
{
  size_t total = 0;

  if (tb->error)
    return 0;

  for (; idx < tb->nitems; idx++)
    {
      if (tb->items[idx].is_stop)
        {
          tb->laststop = idx;
          break;
        }
      if (tb->items[idx].is_constructed)
        {
          tb->items[idx].valuelen = compute_lengths (tb, idx+1);
          if (tb->error)
            return 0;
          /* Note: The last processed IDX is stored at tb->LASTSTOP.  */
        }
      total += get_tlv_length (tb->items[idx].class, tb->items[idx].tag,
                               tb->items[idx].is_constructed,
                               tb->items[idx].valuelen);
      if (tb->items[idx].is_constructed)
        idx = tb->laststop;
    }
  return total;
}


/* Return the constructed DER encoding and release this instance.  On
 * success the object is stored at R_OBJ and its length at R_OBJLEN.
 * The caller needs to release that memory.  On error NULL is stored
 * at R_OBJ and an error code is returned.  Note than an error may
 * stem from any of the previous call made to this object or from
 * constructing the the DER object.  */
gpg_error_t
tlv_builder_finalize (tlv_builder_t tb, void **r_obj, size_t *r_objlen)
{
  gpg_error_t err;
  membuf_t  mb;
  int mb_initialized = 0;
  int idx;

  *r_obj = NULL;
  *r_objlen = 0;

  if (!tb)
    return gpg_error (GPG_ERR_INTERNAL);
  if (tb->error)
    {
      err = tb->error;
      goto leave;
    }
  if (!tb->nitems || !tb->items[tb->nitems-1].is_stop)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }

  compute_lengths (tb, 0);
  err = tb->error;
  if (err)
    goto leave;

  /* for (idx=0; idx < tb->nitems; idx++) */
  /*   log_debug ("TLVB[%2d]: c=%d t=%2d %s p=%p l=%zu\n", */
  /*              idx, */
  /*              tb->items[idx].class, */
  /*              tb->items[idx].tag, */
  /*              tb->items[idx].is_stop? "stop": */
  /*              tb->items[idx].is_constructed? "cons":"prim", */
  /*              tb->items[idx].value, */
  /*              tb->items[idx].valuelen); */

  if (tb->use_secure)
    init_membuf_secure (&mb, 512);
  else
    init_membuf (&mb, 512);
  mb_initialized = 1;

  for (idx=0; idx < tb->nitems; idx++)
    {
      if (tb->items[idx].is_stop)
        continue;
      put_tlv_to_membuf (&mb, tb->items[idx].class, tb->items[idx].tag,
                         tb->items[idx].is_constructed,
                         tb->items[idx].valuelen);
      if (tb->items[idx].value)
        put_membuf (&mb, tb->items[idx].value, tb->items[idx].valuelen);
    }

  *r_obj = get_membuf (&mb, r_objlen);
  if (!*r_obj)
    err = gpg_error_from_syserror ();
  mb_initialized = 0;

 leave:
  if (mb_initialized)
    xfree (get_membuf (&mb, NULL));
  for (idx=0; idx < tb->nitems; idx++)
    xfree (tb->items[idx].buffer);
  xfree (tb->items);
  xfree (tb);
  return err;
}


/* Write TAG of CLASS to MEMBUF.  CONSTRUCTED is a flag telling
 * whether the value is constructed.  LENGTH gives the length of the
 * value, if it is 0 undefinite length is assumed.  LENGTH is ignored
 * for the NULL tag.  TAG must be less that 0x1f.  */
void
put_tlv_to_membuf (membuf_t *membuf, int class, int tag,
                   int constructed, size_t length)
{
  unsigned char buf[20];
  int buflen = 0;
  int i;

  if (tag < 0x1f)
    {
      *buf = (class << 6) | tag;
      if (constructed)
        *buf |= 0x20;
      buflen++;
    }
  else
    BUG ();

  if (!tag && !class)
    buf[buflen++] = 0; /* end tag */
  else if (tag == TAG_NULL && !class)
    buf[buflen++] = 0; /* NULL tag */
  else if (!length)
    buf[buflen++] = 0x80; /* indefinite length */
  else if (length < 128)
    buf[buflen++] = length;
  else
    {
      /* If we know the sizeof a size_t we could support larger
       * objects - however this is pretty ridiculous */
      i = (length <= 0xff ? 1:
           length <= 0xffff ? 2:
           length <= 0xffffff ? 3: 4);

      buf[buflen++] = (0x80 | i);
      if (i > 3)
        buf[buflen++] = length >> 24;
      if (i > 2)
        buf[buflen++] = length >> 16;
      if (i > 1)
        buf[buflen++] = length >> 8;
      buf[buflen++] = length;
    }

  put_membuf (membuf, buf, buflen);
}


/* Return the length of the to be constructed TLV.  CONSTRUCTED is a
 * flag telling whether the value is constructed.  LENGTH gives the
 * length of the value, if it is 0 undefinite length is assumed.
 * LENGTH is ignored for the NULL tag.  TAG must be less that 0x1f.  */
size_t
get_tlv_length (int class, int tag, int constructed, size_t length)
{
  size_t buflen = 0;
  int i;

  (void)constructed;  /* Not used, but passed for uniformity of such calls.  */

  /* coverity[identical_branches] */
  if (tag < 0x1f)
    {
      buflen++;
    }
  else
    {
      buflen++; /* assume one and let the actual write function bail out */
    }

  if (!tag && !class)
    buflen++; /* end tag */
  else if (tag == TAG_NULL && !class)
    buflen++; /* NULL tag */
  else if (!length)
    buflen++; /* indefinite length */
  else if (length < 128)
    buflen++;
  else
    {
      i = (length <= 0xff ? 1:
           length <= 0xffff ? 2:
           length <= 0xffffff ? 3: 4);

      buflen++;
      if (i > 3)
        buflen++;
      if (i > 2)
        buflen++;
      if (i > 1)
        buflen++;
      buflen++;
    }

  return buflen + length;
}
