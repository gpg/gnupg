/* mdfilter.c - filter data and calculate a message digest
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <npth.h>

#include "gpg.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "../common/util.h"
#include "filter.h"



/****************
 * This filter is used to collect a message digest
 */
int
md_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    md_filter_context_t *mfx = opaque;
    int i, rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	if( mfx->maxbuf_size && size > mfx->maxbuf_size )
	    size = mfx->maxbuf_size;
	i = iobuf_read( a, buf, size );
	if( i == -1 ) i = 0;
	if( i ) {
	    gcry_md_write(mfx->md, buf, i );
	    if( mfx->md2 )
		gcry_md_write(mfx->md2, buf, i );
	}
	else
	    rc = -1; /* eof */
	*ret_len = i;
    }
    else if( control == IOBUFCTRL_DESC )
        mem2str (buf, "md_filter", *ret_len);
    return rc;
}


void
free_md_filter_context( md_filter_context_t *mfx )
{
    gcry_md_close(mfx->md);
    gcry_md_close(mfx->md2);
    mfx->md = NULL;
    mfx->md2 = NULL;
    mfx->maxbuf_size = 0;
}


/****************
 * Threaded implementation for hashing.
 */

struct md_thd_filter_context {
  gcry_md_hd_t md;
  npth_t thd;
  /**/
  npth_mutex_t mutex;
  npth_cond_t  cond;
  size_t bufsize;
  unsigned int produce : 1;
  unsigned int consume : 1;
  ssize_t written0;
  ssize_t written1;
  unsigned char buf[1];
};


static void
lock_md (struct md_thd_filter_context *mfx)
{
  int rc = npth_mutex_lock (&mfx->mutex);
  if (rc)
    log_fatal ("%s: failed to acquire mutex: %s\n", __func__,
               gpg_strerror (gpg_error_from_errno (rc)));
}


static void
unlock_md (struct md_thd_filter_context * mfx)
{
  int rc = npth_mutex_unlock (&mfx->mutex);
  if (rc)
    log_fatal ("%s: failed to release mutex: %s\n", __func__,
               gpg_strerror (gpg_error_from_errno (rc)));
}

static int
get_buffer_to_hash (struct md_thd_filter_context *mfx,
                    unsigned char **r_buf, size_t *r_len)
{
  int rc = 0;

  lock_md (mfx);

  if ((mfx->consume == 0 && mfx->written0 < 0)
      || (mfx->consume != 0 && mfx->written1 < 0))
    {
      rc = npth_cond_wait (&mfx->cond, &mfx->mutex);
      if (rc)
        {
          unlock_md (mfx);
          return -1;
        }
    }

  if (mfx->consume == 0)
    {
      *r_buf = mfx->buf;
      *r_len = mfx->written0;
    }
  else
    {
      *r_buf = mfx->buf + mfx->bufsize;
      *r_len = mfx->written1;
    }

  unlock_md (mfx);

  return 0;
}

static int
put_buffer_to_recv (struct md_thd_filter_context *mfx)
{
  int rc = 0;

  lock_md (mfx);
  if (mfx->consume == 0)
    {
      mfx->written0 = -1;
      mfx->consume = 1;
    }
  else
    {
      mfx->written1 = -1;
      mfx->consume = 0;
    }

  rc = npth_cond_signal (&mfx->cond);
  if (rc)
    {
      unlock_md (mfx);
      return -1;
    }

  unlock_md (mfx);
  return 0;
}

static int
get_buffer_to_fill (struct md_thd_filter_context *mfx,
                    unsigned char **r_buf, size_t len)
{
  lock_md (mfx);

  if (len > mfx->bufsize)
    {
      unlock_md (mfx);
      return GPG_ERR_BUFFER_TOO_SHORT;
    }

  if ((mfx->produce == 0 && mfx->written0 >= 0)
      || (mfx->produce != 0 && mfx->written1 >= 0))
    {
      int rc = npth_cond_wait (&mfx->cond, &mfx->mutex);
      if (rc)
        {
          unlock_md (mfx);
          return gpg_error_from_errno (rc);
        }
    }

  if (mfx->produce == 0)
    *r_buf = mfx->buf;
  else
    *r_buf = mfx->buf + mfx->bufsize;
  unlock_md (mfx);
  return 0;
}

static int
put_buffer_to_send (struct md_thd_filter_context *mfx, size_t len)
{
  int rc;

  lock_md (mfx);
  if (mfx->produce == 0)
    {
      mfx->written0 = len;
      mfx->produce = 1;
    }
  else
    {
      mfx->written1 = len;
      mfx->produce = 0;
    }

  rc = npth_cond_signal (&mfx->cond);
  if (rc)
    {
      unlock_md (mfx);
      return gpg_error_from_errno (rc);
    }

  unlock_md (mfx);

  /* Yield to the md_thread to let it compute the hash in parallel */
  npth_usleep (0);
  return 0;
}


static void *
md_thread (void *arg)
{
  struct md_thd_filter_context *mfx = arg;

  while (1)
    {
      unsigned char *buf;
      size_t len;

      if (get_buffer_to_hash (mfx, &buf, &len) < 0)
        /* Error  */
        return NULL;

      if (len == 0)
        break;

      npth_unprotect ();
      gcry_md_write (mfx->md, buf, len);
      npth_protect ();

      if (put_buffer_to_recv (mfx) < 0)
        /* Error  */
        return NULL;
    }

  return NULL;
}

int
md_thd_filter (void *opaque, int control,
               IOBUF a, byte *buf, size_t *ret_len)
{
  size_t size = *ret_len;
  struct md_thd_filter_context **r_mfx = opaque;
  struct md_thd_filter_context *mfx = *r_mfx;
  int rc=0;

  if (control == IOBUFCTRL_INIT)
    {
      npth_attr_t tattr;
      size_t n;

      n = 2 * iobuf_set_buffer_size (0) * 1024;
      mfx = xtrymalloc (n + offsetof (struct md_thd_filter_context, buf));
      if (!mfx)
        return gpg_error_from_syserror ();
      *r_mfx = mfx;
      mfx->bufsize = n / 2;
      mfx->consume = mfx->produce = 0;
      mfx->written0 = -1;
      mfx->written1 = -1;

      rc = npth_mutex_init (&mfx->mutex, NULL);
      if (rc)
        {
          return gpg_error_from_errno (rc);
        }
      rc = npth_cond_init (&mfx->cond, NULL);
      if (rc)
        {
          npth_mutex_destroy (&mfx->mutex);
          return gpg_error_from_errno (rc);
        }
      rc = npth_attr_init (&tattr);
      if (rc)
        {
          npth_cond_destroy (&mfx->cond);
          npth_mutex_destroy (&mfx->mutex);
          return gpg_error_from_errno (rc);
        }
      npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);
      rc = npth_create (&mfx->thd, &tattr, md_thread, mfx);
      if (rc)
        {
          npth_cond_destroy (&mfx->cond);
          npth_mutex_destroy (&mfx->mutex);
          npth_attr_destroy (&tattr);
          return gpg_error_from_errno (rc);
        }
      npth_attr_destroy (&tattr);
    }
  else if (control == IOBUFCTRL_UNDERFLOW)
    {
      int i;
      unsigned char *md_buf = NULL;

      i = iobuf_read (a, buf, size);
      if (i == -1)
        i = 0;

      rc = get_buffer_to_fill (mfx, &md_buf, i);
      if (rc)
        return rc;

      if (i)
        memcpy (md_buf, buf, i);

      rc = put_buffer_to_send (mfx, i);
      if (rc)
        return rc;

      if (i == 0)
        {
          npth_join (mfx->thd, NULL);
          rc = -1; /* eof */
        }

      *ret_len = i;
    }
  else if (control == IOBUFCTRL_FREE)
    {
      npth_cond_destroy (&mfx->cond);
      npth_mutex_destroy (&mfx->mutex);
      xfree (mfx);
      *r_mfx = NULL;
    }
  else if (control == IOBUFCTRL_DESC)
    mem2str (buf, "md_thd_filter", *ret_len);

  return rc;
}

void
md_thd_filter_set_md (struct md_thd_filter_context *mfx, gcry_md_hd_t md)
{
  mfx->md = md;
}
