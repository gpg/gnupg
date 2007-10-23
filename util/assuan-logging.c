/* assuan-logging.c - Default logging function.
 *	Copyright (C) 2002, 2003, 2004 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Please note that this is a stripped down and modified version of
   the orginal Assuan code from libassuan. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif /*HAVE_W32_SYSTEM*/

#include "assuan-defs.h"

static char prefix_buffer[80];
static FILE *_assuan_log;

void
_assuan_set_default_log_stream (FILE *fp)
{
  if (!_assuan_log)
    _assuan_log = fp;
}

void
assuan_set_assuan_log_stream (FILE *fp)
{
  _assuan_log = fp;
}

FILE *
assuan_get_assuan_log_stream (void)
{
  return _assuan_log ? _assuan_log : stderr;
}


/* Set the prefix to be used for logging to TEXT or
   resets it to the default if TEXT is NULL. */
void
assuan_set_assuan_log_prefix (const char *text)
{
  if (text)
    {
      strncpy (prefix_buffer, text, sizeof (prefix_buffer)-1);
      prefix_buffer[sizeof (prefix_buffer)-1] = 0;
    }
  else
    *prefix_buffer = 0;
}

const char *
assuan_get_assuan_log_prefix (void)
{
  return prefix_buffer;
}


void
_assuan_log_printf (const char *format, ...)
{
  va_list arg_ptr;
  FILE *fp;
  const char *prf;

  fp = assuan_get_assuan_log_stream ();
  prf = assuan_get_assuan_log_prefix ();
  if (*prf)
    {
      fputs (prf, fp);
      fputs (": ", fp);
    }

  va_start (arg_ptr, format);
  vfprintf (fp, format, arg_ptr );
  va_end (arg_ptr);
}



#ifdef HAVE_W32_SYSTEM
const char *
_assuan_w32_strerror (int ec)
{
  static char strerr[256];
  
  if (ec == -1)
    ec = (int)GetLastError ();
  FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, ec,
                 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                 strerr, sizeof (strerr)-1, NULL);
  return strerr;    
}
#endif /*HAVE_W32_SYSTEM*/
