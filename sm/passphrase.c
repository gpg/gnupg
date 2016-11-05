/* passphrase.c -  Get a passphrase
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2006, 2007, 2009, 2011 Free Software Foundation, Inc.
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
#include <unistd.h>

#include "passphrase.h"
#include "gpgsm.h"
#include "../common/shareddefs.h"
#include "../common/ttyio.h"

static char *fd_passwd = NULL;

int
have_static_passphrase ()
{
  return (!!fd_passwd
          && (opt.batch || opt.pinentry_mode == PINENTRY_MODE_LOOPBACK));
}

/* Return a static passphrase.  The returned value is only valid as
   long as no other passphrase related function is called.  NULL may
   be returned if no passphrase has been set; better use
   have_static_passphrase first.  */
const char *
get_static_passphrase (void)
{
  return fd_passwd;
}

void
read_passphrase_from_fd (int fd)
{
  int i, len;
  char *pw;

  if (!opt.batch && opt.pinentry_mode != PINENTRY_MODE_LOOPBACK)
    { /* Not used but we have to do a dummy read, so that it won't end
         up at the begin of the message if the quite usual trick to
         prepend the passphtrase to the message is used. */
      char buf[1];

      while (!(read (fd, buf, 1) != 1 || *buf == '\n'))
        ;
      *buf = 0;
      return;
    }

  for (pw = NULL, i = len = 100; ; i++)
    {
      if (i >= len-1)
        {
          char *pw2 = pw;
          len += 100;
          pw = xmalloc_secure (len);
          if (pw2)
            {
              memcpy (pw, pw2, i);
              xfree (pw2);
            }
          else
            i = 0;
	}
      if (read (fd, pw+i, 1) != 1 || pw[i] == '\n')
        break;
    }
  pw[i] = 0;
  if (!opt.batch && opt.pinentry_mode != PINENTRY_MODE_LOOPBACK)
    tty_printf("\b\b\b   \n" );

  xfree (fd_passwd);
  fd_passwd = pw;
}
