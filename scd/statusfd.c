/* statusfd.c - SCdaemon status fd handling
 * Copyright (C) 2007 Free Software Foundation, Inc.
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

/* AUTHOR: Moritz Schulte <moritz@g10code.com>. */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pth.h>

#include "scdaemon.h"
#include "statusfd.h"

struct statusfd_s
{
  FILE *stream;
  struct statusfd_s *next, **prevp;
};

typedef struct statusfd_s *statusfd_t;

static statusfd_t statusfd_list;



static int
statusfd_add (FILE *stream)
{
  statusfd_t statusfd_obj;
  int rc;

  statusfd_obj = xtrymalloc (sizeof (*statusfd_obj));

  if (statusfd_obj)
    {
      statusfd_obj->stream = stream;
      statusfd_obj->next = statusfd_list;
      statusfd_obj->prevp = &statusfd_list;
      if (statusfd_list)
	statusfd_list->prevp = &statusfd_obj->next;
      statusfd_list = statusfd_obj;
      rc = 0;
    }
  else
    rc = gpg_error_from_syserror ();

  return rc;
}

static void
statusfd_remove (statusfd_t statusfd)
{
  *statusfd->prevp = statusfd->next;
  if (statusfd->next)
    statusfd->next->prevp = statusfd->prevp;

  xfree (statusfd);
}

static void
statusfd_broadcast (const char *fmt, ...)
{
  statusfd_t statusfd = statusfd_list;
  statusfd_t statusfd_next;
  int ret;
  va_list ap;

  va_start (ap, fmt);

  while (statusfd)
    {
      ret = vfprintf (statusfd->stream, fmt, ap);
      if (ret >= 0)
	ret = fflush (statusfd->stream);

      if (ret < 0)
	{
	  /* Error on this statusfd stream, remove it. */
	  /* FIXME: only remove on certain errros? -moritz */

	  statusfd_next = statusfd->next;
	  statusfd_remove (statusfd);
	  statusfd = statusfd_next;
	  continue;
	}

      statusfd = statusfd->next;
    }

  va_end (ap);
}

int
statusfd_register (int fd)
{
  FILE *stream;
  int rc;

  stream = fdopen (fd, "a");
  if (! stream)
    rc = gpg_error_from_syserror ();
  else
    rc = statusfd_add (stream);

  if (rc && stream)
    fclose (stream);

  return rc;
}

void
statusfd_event_card_inserted (int slot)
{
  statusfd_broadcast ("CARD INSERTED\n");
}

void
statusfd_event_card_removed (int slot)
{
  statusfd_broadcast ("CARD REMOVED\n");
}
