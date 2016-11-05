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

/* Helper function to print an assuan status line using a printf
   format string.  */
gpg_error_t
vprint_assuan_status (assuan_context_t ctx,
                      const char *keyword,
                      const char *format, va_list arg_ptr)
{
  int rc;
  char *buf;

  rc = gpgrt_vasprintf (&buf, format, arg_ptr);
  if (rc < 0)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
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
