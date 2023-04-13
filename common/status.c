/* status.c - status code helper functions
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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
#include <stdlib.h>

#include "util.h"
#include "status.h"
#include "status-codes.h"

/* The stream to output the status information.  Output is disabled if
 * this is NULL.  */
static estream_t statusfp;


/* Return the status string for code NO. */
const char *
get_status_string ( int no )
{
  int idx = statusstr_msgidxof (no);
  if (idx == -1)
    return "?";
  else
    return statusstr_msgstr + statusstr_msgidx[idx];
}


/* Set a global status FD.  */
void
gnupg_set_status_fd (int fd)
{
  static int last_fd = -1;

  if (fd != -1 && last_fd == fd)
    return;

  if (statusfp && statusfp != es_stdout && statusfp != es_stderr)
    es_fclose (statusfp);
  statusfp = NULL;
  if (fd == -1)
    return;

  if (fd == 1)
    statusfp = es_stdout;
  else if (fd == 2)
    statusfp = es_stderr;
  else
    statusfp = es_fdopen (fd, "w");
  if (!statusfp)
    {
      log_fatal ("can't open fd %d for status output: %s\n",
                 fd, gpg_strerror (gpg_error_from_syserror ()));
    }
  last_fd = fd;
}


/* Write a status line with code NO followed by the output of the
 * printf style FORMAT.  The caller needs to make sure that LFs and
 * CRs are not printed.  */
void
gnupg_status_printf (int no, const char *format, ...)
{
  va_list arg_ptr;

  if (!statusfp)
    return;  /* Not enabled.  */

  es_fputs ("[GNUPG:] ", statusfp);
  es_fputs (get_status_string (no), statusfp);
  if (format)
    {
      es_putc (' ', statusfp);
      va_start (arg_ptr, format);
      es_vfprintf (statusfp, format, arg_ptr);
      va_end (arg_ptr);
    }
  es_putc ('\n', statusfp);
}


/* Write a status line with code NO followed by the remaining
 * arguments which must be a list of strings terminated by a NULL.
 * Embedded CR and LFs in the strings are C-style escaped.  All
 * strings are printed with a space as delimiter.  */
gpg_error_t
gnupg_status_strings (ctrl_t dummy, int no, ...)
{
  va_list arg_ptr;
  const char *s;

  (void)dummy;

  if (!statusfp)
    return 0;  /* Not enabled. */

  va_start (arg_ptr, no);

  es_fputs ("[GNUPG:] ", statusfp);
  es_fputs (get_status_string (no), statusfp);
  while ((s = va_arg (arg_ptr, const char*)))
    {
      if (*s)
        es_putc (' ', statusfp);
      for (; *s; s++)
        {
          if (*s == '\n')
            es_fputs ("\\n", statusfp);
          else if (*s == '\r')
            es_fputs ("\\r", statusfp);
          else
            es_fputc (*(const byte *)s, statusfp);
        }
    }
  es_putc ('\n', statusfp);
  es_fflush (statusfp);

  va_end (arg_ptr);
  return 0;
}


const char *
get_inv_recpsgnr_code (gpg_error_t err)
{
  const char *errstr;

  switch (gpg_err_code (err))
    {
    case GPG_ERR_NO_PUBKEY:       errstr = "1"; break;
    case GPG_ERR_AMBIGUOUS_NAME:  errstr = "2"; break;
    case GPG_ERR_WRONG_KEY_USAGE: errstr = "3"; break;
    case GPG_ERR_CERT_REVOKED:    errstr = "4"; break;
    case GPG_ERR_CERT_EXPIRED:    errstr = "5"; break;
    case GPG_ERR_NO_CRL_KNOWN:
    case GPG_ERR_INV_CRL_OBJ:     errstr = "6"; break;
    case GPG_ERR_CRL_TOO_OLD:     errstr = "7"; break;
    case GPG_ERR_NO_POLICY_MATCH: errstr = "8"; break;

    case GPG_ERR_UNUSABLE_SECKEY:
    case GPG_ERR_NO_SECKEY:       errstr = "9"; break;

    case GPG_ERR_NOT_TRUSTED:     errstr = "10"; break;
    case GPG_ERR_MISSING_CERT:    errstr = "11"; break;
    case GPG_ERR_MISSING_ISSUER_CERT: errstr = "12"; break;
    default:                      errstr = "0"; break;
    }

  return errstr;
}
