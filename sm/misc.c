/* misc.c - Miscellaneous fucntions
 * Copyright (C) 2004, 2009 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpgsm.h"
#include "i18n.h"
#include "setenv.h"

/* Setup the environment so that the pinentry is able to get all
   required information.  This is used prior to an exec of the
   protect-tool. */
void
setup_pinentry_env (void)
{
#ifndef HAVE_W32_SYSTEM
  char *lc;
  const char *name, *value;
  int iterator;

  /* Try to make sure that GPG_TTY has been set.  This is needed if we
     call for example the protect-tools with redirected stdin and thus
     it won't be able to ge a default by itself.  Try to do it here
     but print a warning.  */
  value = session_env_getenv (opt.session_env, "GPG_TTY");
  if (value)
    setenv ("GPG_TTY", value, 1);
  else if (!(lc=getenv ("GPG_TTY")) || !*lc)
    {
      log_error (_("GPG_TTY has not been set - "
                   "using maybe bogus default\n"));
      lc = ttyname (0);
      if (!lc)
        lc = "/dev/tty";
      setenv ("GPG_TTY", lc, 1);
    }

  if (opt.lc_ctype)
    setenv ("LC_CTYPE", opt.lc_ctype, 1);
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  else if ( (lc = setlocale (LC_CTYPE, "")) )
    setenv ("LC_CTYPE", lc, 1);
#endif

  if (opt.lc_messages)
    setenv ("LC_MESSAGES", opt.lc_messages, 1);
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  else if ( (lc = setlocale (LC_MESSAGES, "")) )
    setenv ("LC_MESSAGES", lc, 1);
#endif

  iterator = 0;
  while ((name = session_env_list_stdenvnames (&iterator, NULL)))
    {
      if (!strcmp (name, "GPG_TTY"))
        continue;  /* Already set.  */
      value = session_env_getenv (opt.session_env, name);
      if (value)
        setenv (name, value, 1);
    }

#endif /*!HAVE_W32_SYSTEM*/
}

