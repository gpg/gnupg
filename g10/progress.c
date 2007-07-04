/* progress.c - emit progress status lines
 * Copyright (C) 2003, 2006 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <assert.h>

#include "gpg.h"
#include "iobuf.h"
#include "filter.h"
#include "status.h"
#include "util.h"
#include "options.h"

/* Create a new context for use with the progress filter.  We need to
   allocate such contexts on the heap because there is no guarantee
   that at the end of a function the filter has already been popped
   off.  In general this will happen but with malformed packets it is
   possible that a filter has not yet reached the end-of-stream when
   the function has done all processing.  Checking in each function
   that end-of-stream has been reached would be to cumbersome.

   What we also do is to shortcut the progress handler by having this
   function return NULL if progress information has not been
   requested.
*/
progress_filter_context_t *
new_progress_context (void)
{
  progress_filter_context_t *pfx;

  if (!opt.enable_progress_filter)
    return NULL;

  if (!is_status_enabled ())
    return NULL;

  pfx = xcalloc (1, sizeof *pfx);
  pfx->refcount = 1;

  return pfx;
}

/* Release a progress filter context.  Passing NULL is explicitly
   allowed and a no-op.  */
void
release_progress_context (progress_filter_context_t *pfx)
{
  if (!pfx)
    return;
  assert (pfx->refcount);
  if ( --pfx->refcount )
    return;
  xfree (pfx->what);
  xfree (pfx);
}


/****************
 * The filter is used to report progress to the user.
 */
static int
progress_filter (void *opaque, int control,
		 IOBUF a, byte *buf, size_t *ret_len)
{
  int rc = 0;
  progress_filter_context_t *pfx = opaque;

  if (control == IOBUFCTRL_INIT)
    {
      char buffer[50];

      pfx->last = 0;
      pfx->offset = 0;
      pfx->last_time = make_timestamp ();

      sprintf (buffer, "%.20s ? %lu %lu",
               pfx->what? pfx->what : "?",
               pfx->offset,
	       pfx->total);
      write_status_text (STATUS_PROGRESS, buffer);
    }
  else if (control == IOBUFCTRL_UNDERFLOW)
    {
      u32 timestamp = make_timestamp ();
      int len = iobuf_read (a, buf, *ret_len);

      if (len >= 0)
	{
	  pfx->offset += len;
	  *ret_len = len;
	}
      else
	{
	  *ret_len = 0;
	  rc = -1;
	}
      if ((len == -1 && pfx->offset != pfx->last)
	  || timestamp - pfx->last_time > 0)
	{
	  char buffer[50];
	  
	  sprintf (buffer, "%.20s ? %lu %lu",
                   pfx->what? pfx->what : "?", 
                   pfx->offset,
		   pfx->total);
	  write_status_text (STATUS_PROGRESS, buffer);

	  pfx->last = pfx->offset;
	  pfx->last_time = timestamp;
	}
    }
  else if (control == IOBUFCTRL_FREE)
    {
      release_progress_context (pfx);
    }
  else if (control == IOBUFCTRL_DESC)
    *(char**)buf = "progress_filter";
  return rc;
}

void
handle_progress (progress_filter_context_t *pfx, IOBUF inp, const char *name)
{
  off_t filesize = 0;

  if (!pfx)
    return;

  assert (opt.enable_progress_filter);
  assert (is_status_enabled ());

  if ( !iobuf_is_pipe_filename (name) && *name )
    filesize = iobuf_get_filelength (inp, NULL);
  else if (opt.set_filesize)
    filesize = opt.set_filesize;

  /* register the progress filter */
  pfx->what = xstrdup (name ? name : "stdin");
  pfx->total = filesize;
  pfx->refcount++;
  iobuf_push_filter (inp, progress_filter, pfx);
}
