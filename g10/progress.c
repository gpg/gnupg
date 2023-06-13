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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>

#include "gpg.h"
#include "../common/iobuf.h"
#include "filter.h"
#include "../common/status.h"
#include "../common/util.h"
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
  log_assert (pfx->refcount);
  if ( --pfx->refcount )
    return;
  xfree (pfx->what);
  xfree (pfx);
}


static void
write_status_progress (const char *what, uint64_t current, uint64_t total)
{
  char buffer[60];
  char units[] = "BKMGTPEZY?";
  int unitidx = 0;

  /* Although we use an unsigned long for the values, 32 bit
   * applications using GPGME will use an "int" and thus are limited
   * in the total size which can be represented.  On Windows, where
   * sizeof(int)==sizeof(long), this is even worse and will lead to an
   * integer overflow for all files larger than 2 GiB.  Although, the
   * allowed value range of TOTAL and CURRENT is nowhere specified, we
   * better protect applications from the need to handle negative
   * values.  The common usage pattern of the progress information is
   * to display how many percent of the operation has been done and
   * thus scaling CURRENT and TOTAL down before they get to large,
   * should not have a noticeable effect except for rounding
   * imprecision.
   * Update 2023-06-13: We now use uint64_t but to keep the API stable
   * we still do the scaling.
   */

  if (!total && opt.input_size_hint)
    total = opt.input_size_hint;

  if (total)
    {
      if (current > total)
        current = total;

      while (total > 1024*1024)
        {
          total /= 1024;
          current /= 1024;
          unitidx++;
        }
    }
  else
    {
      while (current > 1024*1024)
        {
          current /= 1024;
          unitidx++;
        }
    }

  if (unitidx > 9)
    unitidx = 9;

  snprintf (buffer, sizeof buffer, "%.20s ? %lu %lu %c%s",
            what? what : "?", (unsigned long)current, (unsigned long)total,
            units[unitidx],
            unitidx? "iB" : "");
  write_status_text (STATUS_PROGRESS, buffer);
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
      pfx->last = 0;
      pfx->offset = 0;
      pfx->last_time = make_timestamp ();

      write_status_progress (pfx->what, pfx->offset, pfx->total);
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
          write_status_progress (pfx->what, pfx->offset, pfx->total);
	  pfx->last = pfx->offset;
	  pfx->last_time = timestamp;
	}
    }
  else if (control == IOBUFCTRL_FREE)
    {
      release_progress_context (pfx);
    }
  else if (control == IOBUFCTRL_DESC)
    mem2str (buf, "progress_filter", *ret_len);
  return rc;
}

void
handle_progress (progress_filter_context_t *pfx, IOBUF inp, const char *name)
{
  uint64_t filesize = 0;

  if (!pfx)
    return;

  log_assert (opt.enable_progress_filter);
  log_assert (is_status_enabled ());

  if ( !iobuf_is_pipe_filename (name) && *name )
    filesize = iobuf_get_filelength (inp);
  else if (opt.set_filesize)
    filesize = opt.set_filesize;

  /* register the progress filter */
  pfx->what = xstrdup (name ? name : "stdin");
  pfx->total = filesize;
  pfx->refcount++;
  iobuf_push_filter (inp, progress_filter, pfx);
}
