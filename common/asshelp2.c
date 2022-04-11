/* asshelp2.c - More helper functions for Assuan
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
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
#include <assuan.h>

#include "util.h"
#include "asshelp.h"
#include "status.h"


/* A variable with a function to be used to return the current assuan
 * context for a CTRL variable.  This needs to be set using the
 * set_assuan_ctx_func function.  */
static assuan_context_t (*the_assuan_ctx_func)(ctrl_t ctrl);


/* Set FUNC to be used as a mapping function from CTRL to an assuan
 * context.  Pass NULL for FUNC to disable the use of the assuan
 * context in this module.  */
void
set_assuan_context_func (assuan_context_t (*func)(ctrl_t ctrl))
{
  the_assuan_ctx_func = func;
}


/* Helper function to print an assuan status line using a printf
   format string.  */
gpg_error_t
vprint_assuan_status (assuan_context_t ctx,
                      const char *keyword,
                      const char *format, va_list arg_ptr)
{
  int rc;
  size_t n;
  char *buf;

  rc = gpgrt_vasprintf (&buf, format, arg_ptr);
  if (rc < 0)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
  n = strlen (buf);
  if (n && buf[n-1] == '\n')
    buf[n-1] = 0;  /* Strip trailing LF to avoid earning from Assuan  */
  rc = assuan_write_status (ctx, keyword, buf);
  xfree (buf);
  return rc;
}


/* Helper function to print an assuan status line using a printf
   format string.  */
gpg_error_t
print_assuan_status (assuan_context_t ctx,
                     const char *keyword,
                     const char *format, ...)
{
  va_list arg_ptr;
  gpg_error_t err;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, keyword, format, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* Helper function to print a list of strings as an assuan status
 * line.  KEYWORD is the first item on the status line.  ARG_PTR is a
 * list of strings which are all separated by a space in the output.
 * The last argument must be a NULL.  Linefeeds and carriage returns
 * characters (which are not allowed in an Assuan status line) are
 * silently quoted in C-style.  */
gpg_error_t
vprint_assuan_status_strings (assuan_context_t ctx,
                              const char *keyword, va_list arg_ptr)
{
  gpg_error_t err = 0;
  const char *text;
  char buf[950], *p;
  size_t n;

  p = buf;
  n = 0;
  while ((text = va_arg (arg_ptr, const char *)) && n < DIM (buf)-3 )
    {
      if (n)
        {
          *p++ = ' ';
          n++;
        }
      for ( ; *text && n < DIM (buf)-3; n++, text++)
        {
          if (*text == '\n')
            {
              *p++ = '\\';
              *p++ = 'n';
              n++;
            }
          else if (*text == '\r')
            {
              *p++ = '\\';
              *p++ = 'r';
              n++;
            }
          else
            *p++ = *text;
        }
    }
  *p = 0;
  err = assuan_write_status (ctx, keyword, buf);

  return err;
}


/* See vprint_assuan_status_strings.  */
gpg_error_t
print_assuan_status_strings (assuan_context_t ctx, const char *keyword, ...)
{
  va_list arg_ptr;
  gpg_error_t err;

  va_start (arg_ptr, keyword);
  err = vprint_assuan_status_strings (ctx, keyword, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* This function is similar to print_assuan_status but takes a CTRL
 * arg instead of an assuan context as first argument.  */
gpg_error_t
status_printf (ctrl_t ctrl, const char *keyword, const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx;

  if (!ctrl || !the_assuan_ctx_func || !(ctx = the_assuan_ctx_func (ctrl)))
    return 0;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, keyword, format, arg_ptr);
  va_end (arg_ptr);
  return err;
}


/* Same as status_printf but takes a status number instead of a
 * keyword.  */
gpg_error_t
status_no_printf (ctrl_t ctrl, int no, const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  assuan_context_t ctx;

  if (!ctrl || !the_assuan_ctx_func || !(ctx = the_assuan_ctx_func (ctrl)))
    return 0;

  va_start (arg_ptr, format);
  err = vprint_assuan_status (ctx, get_status_string (no), format, arg_ptr);
  va_end (arg_ptr);
  return err;
}
