/* call-syshelp.c - Communication with g13-syshelp
 * Copyright (C) 2015 Werner Koch
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <npth.h>

#include "g13.h"
#include <assuan.h>
#include "i18n.h"
#include "utils.h"

/* Local data for this module.  A pointer to this is stored in the
   CTRL object of each connection.  */
struct call_syshelp_s
{
  assuan_context_t assctx;  /* The Assuan context for the current
                               g13-syshep connection.  */
};


/* Fork off the syshelp tool if this has not already been done.  */
static gpg_error_t
start_syshelp (ctrl_t ctrl)
{
  gpg_error_t err;
  assuan_context_t ctx;
  assuan_fd_t no_close_list[3];
  int i;

  if (ctrl->syshelp_local->assctx)
    return 0; /* Already set.  */

  if (opt.verbose)
    log_info ("starting a new syshelp\n");

  if (es_fflush (NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("error flushing pending output: %s\n", gpg_strerror (err));
      return err;
    }

  i = 0;
  if (log_get_fd () != -1)
    no_close_list[i++] = assuan_fd_from_posix_fd (log_get_fd ());
  no_close_list[i++] = assuan_fd_from_posix_fd (es_fileno (es_stderr));
  no_close_list[i] = ASSUAN_INVALID_FD;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (err));
      return err;
    }

  /* Call userv to start g13-syshelp.  This userv script needs tpo be
     installed under the name "gnupg-g13-syshelp":

       if ( glob service-user root
          )
           reset
           suppress-args
           execute /home/wk/b/gnupg/g13/g13-syshelp -v
       else
           error Nothing to do for this service-user
       fi
       quit
  */
  {
    const char *argv[3];

    argv[0] = "userv";
    argv[1] = "gnupg-g13-syshelp";
    argv[2] = NULL;

    err = assuan_pipe_connect (ctx, "/usr/bin/userv", argv,
                               no_close_list, NULL, NULL, 0);
  }
  if (err)
    {
      log_error ("can't connect to '%s' - : %s\n",
                 "g13-syshelp", gpg_strerror (err));
      log_info ("(is userv and its gnupg-g13-syshelp script installed?)\n");
      assuan_release (ctx);
      return err;
    }
  ctrl->syshelp_local->assctx = ctx;

  if (DBG_IPC)
    log_debug ("connection to g13-syshelp established\n");

  return 0;
}


/* Release local resources associated with CTRL.  */
void
call_syshelp_release (ctrl_t ctrl)
{
  if (!ctrl)
    return;
  if (ctrl->syshelp_local)
    {
      assuan_release (ctrl->syshelp_local->assctx);
      ctrl->syshelp_local->assctx = NULL;
    }
}
