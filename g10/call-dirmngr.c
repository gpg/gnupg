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
#include "keyserver.h"
#include "call-dirmngr.h"


/* Parameter structure used with the KS_SEARCH command.  */
struct ks_search_parm_s
{
  gpg_error_t lasterr;  /* Last error code.  */
  membuf_t saveddata;   /* Buffer to build complete lines.  */
  char *helpbuf;        /* NULL or malloced buffer.  */
  size_t helpbufsize;   /* Allocated size of HELPBUF.  */
  gpg_error_t (*data_cb)(void*, char*);  /* Callback.  */
  void *data_cb_value;  /* First argument for DATA_CB.  */
};


/* Parameter structure used with the KS_GET command.  */
struct ks_get_parm_s
{
  estream_t memfp;
};


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
  assuan_context_t ctx;

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
      for (ksi = opt.keyserver; !err && ksi; ksi = ksi->next)
        {
          char *line;
          
          line = xtryasprintf ("KEYSERVER%s %s",
                               ksi == opt.keyserver? " --clear":"", ksi->uri);
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
          *r_ctx = dml->ctx;
          return 0;
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
          if (!dml->is_active)
            log_fatal ("closing inactive dirmngr context %p\n", ctx);
          dml->is_active = 0;
          return;
        }
    }
  log_fatal ("closing unknown dirmngr ctx %p\n", ctx);
}



/* Data callback for the KS_SEARCH command. */
static gpg_error_t
ks_search_data_cb (void *opaque, const void *data, size_t datalen)
{
  gpg_error_t err = 0;
  struct ks_search_parm_s *parm = opaque;
  const char *line, *s;
  size_t rawlen, linelen;
  char fixedbuf[256];

  if (parm->lasterr)
    return 0;

  if (!data)
    return 0;  /* Ignore END commands.  */

  put_membuf (&parm->saveddata, data, datalen);

 again:
  line = peek_membuf (&parm->saveddata, &rawlen);
  if (!line)
    {
      parm->lasterr = gpg_error_from_syserror ();
      return parm->lasterr; /* Tell the server about our problem.  */
    }
  if ((s = memchr (line, '\n', rawlen)))
    {
      linelen = s - line;  /* That is the length excluding the LF.  */
      if (linelen + 1 < sizeof fixedbuf)
        {
          /* We can use the static buffer.  */
          memcpy (fixedbuf, line, linelen);
          fixedbuf[linelen] = 0;
          if (linelen && fixedbuf[linelen-1] == '\r')
            fixedbuf[linelen-1] = 0;
          err = parm->data_cb (parm->data_cb_value, fixedbuf);
        }
      else 
        {
          if (linelen + 1 >= parm->helpbufsize)
            {
              xfree (parm->helpbuf);
              parm->helpbufsize = linelen + 1 + 1024;
              parm->helpbuf = xtrymalloc (parm->helpbufsize);
              if (!parm->helpbuf)
                {
                  parm->lasterr = gpg_error_from_syserror ();
                  return parm->lasterr;
                }
            }
          memcpy (parm->helpbuf, line, linelen);
          parm->helpbuf[linelen] = 0;
          if (linelen && parm->helpbuf[linelen-1] == '\r')
            parm->helpbuf[linelen-1] = 0;
          err = parm->data_cb (parm->data_cb_value, parm->helpbuf);
        }
      if (err)
        parm->lasterr = err;
      else
        {
          clear_membuf (&parm->saveddata, linelen+1);
          goto again;  /* There might be another complete line.  */
        }
    }

  return err;
}


/* Run the KS_SEARCH command using the search string SEARCHSTR.  All
   data lines are passed to the CB function.  That function is called
   with CB_VALUE as its first argument and the decoded data line as
   second argument.  The callback function may modify the data line
   and it is guaranteed that this data line is a complete line with a
   terminating 0 character but without the linefeed.  NULL is passed
   to the callback to indicate EOF.  */
gpg_error_t
gpg_dirmngr_ks_search (ctrl_t ctrl, const char *searchstr,
                       gpg_error_t (*cb)(void*, char *), void *cb_value)
{ 
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_search_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  {
    char *escsearchstr = percent_plus_escape (searchstr);
    if (!escsearchstr)
      {
        err = gpg_error_from_syserror ();
        close_context (ctrl, ctx);
        return err;
      }
    snprintf (line, sizeof line, "KS_SEARCH -- %s", escsearchstr);
    xfree (escsearchstr);
  }

  memset (&parm, 0, sizeof parm);
  init_membuf (&parm.saveddata, 1024);
  parm.data_cb = cb;
  parm.data_cb_value = cb_value;

  err = assuan_transact (ctx, line, ks_search_data_cb, &parm,
                        NULL, NULL, NULL, NULL);
  if (!err)
    err = cb (cb_value, NULL);  /* Send EOF.  */

  xfree (get_membuf (&parm.saveddata, NULL));
  xfree (parm.helpbuf);

  close_context (ctrl, ctx);
  return err;
}



/* Data callback for the KS_GET command. */
static gpg_error_t
ks_get_data_cb (void *opaque, const void *data, size_t datalen)
{
  gpg_error_t err = 0;
  struct ks_get_parm_s *parm = opaque;
  size_t nwritten;

  if (!data)
    return 0;  /* Ignore END commands.  */

  if (es_write (parm->memfp, data, datalen, &nwritten))
    err = gpg_error_from_syserror ();

  return err;
}


/* Run the KS_GET command using the patterns in the array PATTERN.  On
   success an estream object is returned to retrieve the keys.  On
   error an error code is returned and NULL stored at R_FP.

   The pattern may only use search specification which a keyserver can
   use to retriev keys.  Because we know the format of the pattern we
   don't need to escape the patterns before sending them to the
   server.

   If there are too many patterns the function returns an error.  That
   could be fixed by issuing several search commands or by
   implementing a different interface.  However with long keyids we
   are able to ask for (1000-10-1)/(2+8+1) = 90 keys at once.  */
gpg_error_t
gpg_dirmngr_ks_get (ctrl_t ctrl, char **pattern, estream_t *r_fp)
{ 
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_get_parm_s parm;
  char *line = NULL;
  size_t linelen;
  membuf_t mb;
  int idx;

  memset (&parm, 0, sizeof parm);

  *r_fp = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  /* Lump all patterns into one string.  */
  init_membuf (&mb, 1024);
  put_membuf_str (&mb, "KS_GET --");
  for (idx=0; pattern[idx]; idx++)
    {
      put_membuf (&mb, " ", 1); /* Append Delimiter.  */
      put_membuf_str (&mb, pattern[idx]);
    }
  put_membuf (&mb, "", 1); /* Append Nul.  */
  line = get_membuf (&mb, &linelen);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (linelen + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_MANY);
      goto leave;
    }

  parm.memfp = es_fopenmem (0, "rwb");
  if (!parm.memfp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = assuan_transact (ctx, line, ks_get_data_cb, &parm,
                         NULL, NULL, NULL, NULL);
  if (err)
    goto leave;

  es_rewind (parm.memfp);
  *r_fp = parm.memfp;
  parm.memfp = NULL;

 leave:
  es_fclose (parm.memfp);
  xfree (line);
  close_context (ctrl, ctx);
  return err;
}
