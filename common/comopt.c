/* comopt.c - Common options for GnUPG (common.conf)
 * Copyright (C) 2021 g10 Code GmbH
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
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "util.h"
#include "i18n.h"
#include "comopt.h"


enum opt_values
  {
    aNull = 0,

    oLogFile = 500,
    oUseKeyboxd,
    oKeyboxdProgram,
    oNoAutostart,

    oNoop
  };

static gpgrt_opt_t opts[] = {
  ARGPARSE_s_s (oLogFile,        "log-file", "@"),
  ARGPARSE_s_n (oUseKeyboxd,     "use-keyboxd", "@"),
  ARGPARSE_s_n (oNoAutostart,    "no-autostart", "@"),
  ARGPARSE_s_s (oKeyboxdProgram, "keyboxd-program", "@"),

  ARGPARSE_end ()
};


struct gnupg_comopt_s comopt = {NULL};


/* Parse the common options in the homedir and etc.  This needs to be
 * called after the gpgrt config directories are set.  MODULE_ID is one of
 * the GNUPG_MODULE_NAME_ constants.  If verbose is true info about
 * the parsing is printed.  Note that this function is not
 * thread-safe. */
gpg_error_t
parse_comopt (int module_id, int verbose)
{
  gpg_error_t err = 0;
  gpgrt_argparse_t pargs;
  int argc = 0;
  char **argv = NULL;

  /* Reset all options in case we are called a second time.  */
  xfree (comopt.logfile);
  xfree (comopt.keyboxd_program);
  memset (&comopt, 0, sizeof comopt);

  /* Start the parser.  */
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = (ARGPARSE_FLAG_NOVERSION
                 | ARGPARSE_FLAG_SYS
                 | ARGPARSE_FLAG_USER
                 );
  while (gpgrt_argparser (&pargs, opts, "common" EXTSEP_S "conf" ))
    {
      switch (pargs.r_opt)
        {
        case ARGPARSE_CONFFILE:
          if (verbose)
            log_info (_("reading options from '%s'\n"),
                      pargs.r_type? pargs.r.ret_str: "[cmdline]");
          break;

        case oLogFile:
          comopt.logfile = pargs.r.ret_str;
          break;

        case oUseKeyboxd:
          comopt.use_keyboxd = 1;
          break;

        case oNoAutostart:
          comopt.no_autostart = 1;
          break;

        case oKeyboxdProgram:
          comopt.keyboxd_program = pargs.r.ret_str;
          break;

        default:
          pargs.err = ARGPARSE_PRINT_WARNING;
          err = gpg_error (GPG_ERR_GENERAL);
          break;
        }
    }

  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (comopt.logfile && !(!strncmp (comopt.logfile, "socket:", 7)
                          || !strncmp (comopt.logfile, "tcp:", 4)) )
    {
      /* Letting all modules write to the same log file is not a good
       * idea.  Append the module name.  */
      char *p;

      p = xstrconcat (comopt.logfile, "-", gnupg_module_name (module_id), NULL);
      xfree (comopt.logfile);
      comopt.logfile = p;
    }

  return err;
}
