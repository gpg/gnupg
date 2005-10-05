/* progress.c
 * Copyright (C) 2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <config.h>
#include <stdio.h>

#include "iobuf.h"
#include "filter.h"
#include "status.h"
#include "util.h"
#include "options.h"

/****************
 * The filter is used to report progress to the user.
 */
int
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
      /* Note, that we must always dealloc resources of a filter
         within the filter handler and not anywhere else.  (We set it
         to NULL and check all uses just in case.) */
      xfree (pfx->what);
      pfx->what = NULL;
    }
  else if (control == IOBUFCTRL_DESC)
    *(char**)buf = "progress_filter";
  return rc;
}

void
handle_progress (progress_filter_context_t *pfx, IOBUF inp, const char *name)
{
  off_t filesize = 0;

  if (!opt.enable_progress_filter)
    return;

  if (!is_status_enabled ())
    return;

  if ( !iobuf_is_pipe_filename (name) && *name )
    filesize = iobuf_get_filelength (inp, NULL);
  else if (opt.set_filesize)
    filesize = opt.set_filesize;

  /* register the progress filter */
  pfx->what = xstrdup (name ? name : "stdin");
  pfx->total = filesize;
  iobuf_push_filter (inp, progress_filter, pfx);
}
