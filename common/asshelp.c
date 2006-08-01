/* asshelp.c - Helper functions for Assuan
 * Copyright (C) 2002, 2004 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "util.h"

#include "asshelp.h"


static gpg_error_t
send_one_option (assuan_context_t ctx, gpg_err_source_t errsource,
                 const char *name, const char *value)
{
  gpg_error_t err;
  char *optstr;

  if (!value || !*value)
    err = 0;  /* Avoid sending empty strings.  */
  else if (asprintf (&optstr, "OPTION %s=%s", name, value ) < 0)
    err = gpg_error_from_errno (errno);
  else
    {
      assuan_error_t ae;

      ae = assuan_transact (ctx, optstr, NULL, NULL, NULL, NULL, NULL, NULL);
      err = ae? map_assuan_err_with_source (errsource, ae) : 0;
      free (optstr);
    }

  return err;
}


/* Send the assuan commands pertaining to the pinenry environment.  The
   OPT_* arguments are optional and may be used to override the
   defaults taken from the current locale. */
gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           gpg_err_source_t errsource,
                           const char *opt_display,
                           const char *opt_ttyname,
                           const char *opt_ttytype,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages)
{
  gpg_error_t err = 0;
  char *dft_display = NULL;
  char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
  char *old_lc = NULL; 
  char *dft_lc = NULL;

  /* Send the DISPLAY variable.  */
  dft_display = getenv ("DISPLAY");
  if (opt_display || dft_display)
    {
      err = send_one_option (ctx, errsource, "display", 
                             opt_display ? opt_display : dft_display);
      if (err)
        return err;
    }

  /* Send the name of the TTY.  */
  if (!opt_ttyname)
    {
      dft_ttyname = getenv ("GPG_TTY");
      if ((!dft_ttyname || !*dft_ttyname) && ttyname (0))
        dft_ttyname = ttyname (0);
    }
  if (opt_ttyname || dft_ttyname)
    {
      err = send_one_option (ctx, errsource, "ttyname", 
                             opt_ttyname ? opt_ttyname : dft_ttyname);
      if (err)
        return err;
    }

  /* Send the type of the TTY.  */
  dft_ttytype = getenv ("TERM");
  if (opt_ttytype || (dft_ttyname && dft_ttytype))
    {
      err = send_one_option (ctx, errsource, "ttytype", 
                             opt_ttyname ? opt_ttytype : dft_ttytype);
      if (err)
        return err;
    }

  /* Send the value for LC_CTYPE.  */
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale (LC_CTYPE, NULL);
  if (old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
        return gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_CTYPE, "");
#endif
  if (opt_lc_ctype || (dft_ttyname && dft_lc))
    {
      err = send_one_option (ctx, errsource, "lc-ctype", 
                             opt_lc_ctype ? opt_lc_ctype : dft_lc);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      free (old_lc);
    }
#endif
  if (err)
    return err;

  /* Send the value for LC_MESSAGES.  */
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale (LC_MESSAGES, NULL);
  if (old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
        return gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_MESSAGES, "");
#endif
  if (opt_lc_messages || (dft_ttyname && dft_lc))
    {
      err = send_one_option (ctx, errsource, "lc-messages", 
                             opt_lc_messages ? opt_lc_messages : dft_lc);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      free (old_lc);
    }
#endif
  if (err)
    return err;

  return 0;
}

