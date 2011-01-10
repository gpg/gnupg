/* call-dirmngr.c - GPG operations to the Dirmngr.
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <unistd.h> 
#include <time.h>
#include <assert.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#include "gpg.h"
#include <assuan.h>
#include "util.h"
#include "membuf.h"
#include "options.h"
#include "i18n.h"
#include "asshelp.h"
#include "call-dirmngr.h"


/* Data used to associate an session with dirmngr contexts.  We can't
   use a simple one to one mapping because we sometimes need two
   connection s to the dirmngr; for example while doing a listing and
   being in a data callback we may want to retrieve a key.  The local
   dirmngr data takes care of this.  At the end of the session the
   function dirmngr_deinit_session_data is called bu gpg.c to cleanup
   these resources.  Note that gpg.h defines a typedef dirmngr_local_t
   for this structure. */
struct dirmngr_local_s 
{
  /* Link to other contexts which are used simultaneously.  */
  struct dirmngr_local_s *next;

  /* The active Assuan context. */
  static assuan_context_t ctx;

  /* Flag set to true while an operation is running on CTX.  */
  int is_active;
};



/* Deinitialize all session data of dirmngr pertaining to CTRL.  */
void
gpg_dirmngr_deinit_session_data (ctrl_t ctrl)
{
  dirmngr_local_t dml;

  while ((dml = ctrl->dirmngr_local))
    {
      ctrl->dirmngr_local = dml->next;
      if (dml->is_active)
        log_error ("oops: trying to cleanup an active dirmngr context\n");
      else
        assuan_release (dml->ctx);
      xfree (dml);
    }
}


/* Try to connect to the Dirmngr via a socket or fork it off if
   possible.  Handle the server's initial greeting and set global
   options.  */
static gpg_error_t
create_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;
  err = start_new_dirmngr (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           opt.homedir,
                           NULL,
                           opt.verbose, DBG_ASSUAN,
                           NULL /*gpg_status2*/, ctrl);
  if (!err)
    {
      keyserver_spec_t ksi;

      /* Tell the dirmngr that we want to collect audit event. */
      /* err = assuan_transact (agent_ctx, "OPTION audit-events=1", */
      /*                        NULL, NULL, NULL, NULL, NULL, NULL); */
      
      /* Set all configured keyservers.  We clear existing keyservers
         so that any keyserver configured in GPG overrides keyservers
         possibly configured in Dirmngr. */
      if (ksi = opt.keyservers; !err && ksi; ksi = ksi->next)
        {
          char *line;
          
          line = xtryasprintf ("KEYSERVER%s %s",
                               ksi == opt.keyservers? " --clear":"", ksi->uri);
          if (!line)
            err = gpg_error_from_syserror ();
          else
            {
              err = assuan_transact (ctx, line,
                                     NULL, NULL, NULL, NULL, NULL, NULL);
              xfree (line);
            }
        }
    }

  if (err)
    assuan_release (ctx);
  else
    {
      /* audit_log_ok (ctrl->audit, AUDIT_DIRMNGR_READY, err); */
      *r_ctx = ctx;
    }
  
  return err;
}


/* Get a context for accessing dirmngr.  If no context is available a
   new one is created and - if requred - dirmngr started.  On success
   an assuan context is stored at R_CTX.  This Context may only be
   released by means of close_context.  Note that NULL is stored at
   R_CTX on error.  */
static gpg_error_t
open_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  dirmngr_local_t dml;

  *r_ctx = NULL;
  for (;;)
    {
      for (dml = ctrl->dirmngr_local; dml && dml->is_active; dml = dml->next)
        ;
      if (dml)
        {
          /* Found an inactive local session - return that.  */
          assert (!dml->is_active);
          dml->is_active = 1;
          return dml;
        }
      
      dml = xtrycalloc (1, sizeof *dml);
      if (!dml)
        return gpg_error_from_syserror ();
      err = create_context (ctrl, &dml->ctx);
      if (err)
        {
          xfree (dml);
          return err;
        }
      /* To be on the Pth thread safe site we need to add it to a
         list; this is far easier than to have a lock for this
         function.  It should not happen anyway but the code is free
         because we need it for the is_active check above.  */
      dml->next = ctrl->dirmngr_local;
      ctrl->dirmngr_local = dml;
    }
}


/* Close the assuan context CTX or return it to a pool of unused
   contexts.  If CTX is NULL, the function does nothing.  */
static void
close_context (ctrl_t ctrl, assuan_context_t ctx)
{
  dirmngr_local_t dml;

  if (!ctx)
    return;

  for (dml = ctrl->dirmngr_local; dml; dml = dml->next)
    {
      if (dml->ctx == ctx)
        {
          if (!ctx->is_active)
            log_fatal ("closing inactive dirmngr context %p\n", ctx);
          ctx->is_active = 0;
          return;
        }
    }
  log_fatal ("closing unknown dirmngr ctx %p\n", ctx);
}




int 
gpg_dirmngr_ks_search (ctrl_t ctrl, strlist_t names,
                       void (*cb)(void*, ksba_cert_t), void *cb_value)
{ 
  gpg_error_t err;
  assuan_context_t ctx;
  char *pattern;
  char line[ASSUAN_LINELENGTH];

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  pattern = pattern_from_strlist (names);
  if (!pattern)
    {
      if (ctx == dirmngr_ctx)
	release_dirmngr (ctrl);
      else
	release_dirmngr2 (ctrl);

      return out_of_core ();
    }
  snprintf (line, DIM(line)-1, "LOOKUP%s %s", 
            cache_only? " --cache-only":"", pattern);
  line[DIM(line)-1] = 0;
  xfree (pattern);

  parm.ctrl = ctrl;
  parm.ctx = ctx;
  parm.cb = cb;
  parm.cb_value = cb_value;
  parm.error = 0;
  init_membuf (&parm.data, 4096);

  rc = assuan_transact (ctx, line, lookup_cb, &parm,
                        NULL, NULL, lookup_status_cb, &parm);
  xfree (get_membuf (&parm.data, &len));

  if (ctx == dirmngr_ctx)
    release_dirmngr (ctrl);
  else
    release_dirmngr2 (ctrl);

  if (rc)
      return rc;

  close_context (ctrl, ctx);
  return parm.error;
}
