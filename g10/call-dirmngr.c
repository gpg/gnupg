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


/* Parameter structure used to gather status info.  */
struct ks_status_parm_s
{
  char *source;
};


/* Parameter structure used with the KS_SEARCH command.  */
struct ks_search_parm_s
{
  gpg_error_t lasterr;  /* Last error code.  */
  membuf_t saveddata;   /* Buffer to build complete lines.  */
  char *helpbuf;        /* NULL or malloced buffer.  */
  size_t helpbufsize;   /* Allocated size of HELPBUF.  */
  gpg_error_t (*data_cb)(void*, int, char*);  /* Callback.  */
  void *data_cb_value;  /* First argument for DATA_CB.  */
  struct ks_status_parm_s *stparm; /* Link to the status parameter.  */
};


/* Parameter structure used with the KS_GET command.  */
struct ks_get_parm_s
{
  estream_t memfp;
};


/* Parameter structure used with the KS_PUT command.  */
struct ks_put_parm_s
{
  assuan_context_t ctx;
  kbnode_t keyblock;  /* The optional keyblock.  */
  const void *data;   /* The key in OpenPGP binary format.  */
  size_t datalen;     /* The length of DATA.  */
};


/* Data used to associate an session with dirmngr contexts.  We can't
   use a simple one to one mapping because we sometimes need two
   connections to the dirmngr; for example while doing a listing and
   being in a data callback we may want to retrieve a key.  The local
   dirmngr data takes care of this.  At the end of the session the
   function dirmngr_deinit_session_data is called by gpg.c to cleanup
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


/* Try to connect to the Dirmngr via a socket or spawn it if possible.
   Handle the server's initial greeting and set global options.  */
static gpg_error_t
create_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;
  err = start_new_dirmngr (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           opt.homedir,
                           opt.dirmngr_program,
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
         possibly still configured in Dirmngr for the session (Note
         that the keyserver list of a session in Dirmngr survives a
         RESET. */
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
   new one is created and - if required - dirmngr started.  On success
   an assuan context is stored at R_CTX.  This context may only be
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
      /* To be on the nPth thread safe site we need to add it to a
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



/* Status callback for ks_get and ks_search.  */
static gpg_error_t
ks_status_cb (void *opaque, const char *line)
{
  struct ks_status_parm_s *parm = opaque;
  gpg_error_t err = 0;
  const char *s;

  if ((s = has_leading_keyword (line, "SOURCE")))
    {
      if (!parm->source)
        {
          parm->source = xtrystrdup (s);
          if (!parm->source)
            err = gpg_error_from_syserror ();
        }
    }

  return err;
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

  if (parm->stparm->source)
    {
      err = parm->data_cb (parm->data_cb_value, 1, parm->stparm->source);
      if (err)
        {
          parm->lasterr = err;
          return err;
        }
      /* Clear it so that we won't get back here unless the server
         accidentally sends a second source status line.  Note that
         will not see all accidentally sent source lines because it
         depends on whether data lines have been send in between.  */
      xfree (parm->stparm->source);
      parm->stparm->source = NULL;
    }

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
          err = parm->data_cb (parm->data_cb_value, 0, fixedbuf);
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
          err = parm->data_cb (parm->data_cb_value, 0, parm->helpbuf);
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
   with CB_VALUE as its first argument, a 0 as second argument, and
   the decoded data line as third argument.  The callback function may
   modify the data line and it is guaranteed that this data line is a
   complete line with a terminating 0 character but without the
   linefeed.  NULL is passed to the callback to indicate EOF.  */
gpg_error_t
gpg_dirmngr_ks_search (ctrl_t ctrl, const char *searchstr,
                       gpg_error_t (*cb)(void*, int, char *), void *cb_value)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_status_parm_s stparm;
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

  memset (&stparm, 0, sizeof stparm);
  memset (&parm, 0, sizeof parm);
  init_membuf (&parm.saveddata, 1024);
  parm.data_cb = cb;
  parm.data_cb_value = cb_value;
  parm.stparm = &stparm;

  err = assuan_transact (ctx, line, ks_search_data_cb, &parm,
                        NULL, NULL, ks_status_cb, &stparm);
  if (!err)
    err = cb (cb_value, 0, NULL);  /* Send EOF.  */

  xfree (get_membuf (&parm.saveddata, NULL));
  xfree (parm.helpbuf);
  xfree (stparm.source);

  close_context (ctrl, ctx);
  return err;
}



/* Data callback for the KS_GET and KS_FETCH commands. */
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

   If R_SOURCE is not NULL the source of the data is stored as a
   malloced string there.  If a source is not known NULL is stored.

   If there are too many patterns the function returns an error.  That
   could be fixed by issuing several search commands or by
   implementing a different interface.  However with long keyids we
   are able to ask for (1000-10-1)/(2+8+1) = 90 keys at once.  */
gpg_error_t
gpg_dirmngr_ks_get (ctrl_t ctrl, char **pattern,
                    estream_t *r_fp, char **r_source)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_status_parm_s stparm;
  struct ks_get_parm_s parm;
  char *line = NULL;
  size_t linelen;
  membuf_t mb;
  int idx;

  memset (&stparm, 0, sizeof stparm);
  memset (&parm, 0, sizeof parm);

  *r_fp = NULL;
  if (r_source)
    *r_source = NULL;

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
                         NULL, NULL, ks_status_cb, &stparm);
  if (err)
    goto leave;

  es_rewind (parm.memfp);
  *r_fp = parm.memfp;
  parm.memfp = NULL;

  if (r_source)
    {
      *r_source = stparm.source;
      stparm.source = NULL;
    }

 leave:
  es_fclose (parm.memfp);
  xfree (stparm.source);
  xfree (line);
  close_context (ctrl, ctx);
  return err;
}


/* Run the KS_FETCH and pass URL as argument.  On success an estream
   object is returned to retrieve the keys.  On error an error code is
   returned and NULL stored at R_FP.

   The url is expected to point to a small set of keys; in many cases
   only to one key.  However, schemes like finger may return several
   keys.  Note that the configured keyservers are ignored by the
   KS_FETCH command.  */
gpg_error_t
gpg_dirmngr_ks_fetch (ctrl_t ctrl, const char *url, estream_t *r_fp)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_get_parm_s parm;
  char *line = NULL;

  memset (&parm, 0, sizeof parm);

  *r_fp = NULL;

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  line = strconcat ("KS_FETCH -- ", url, NULL);
  if (!line)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (line) + 2 >= ASSUAN_LINELENGTH)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
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



/* Handle the KS_PUT inquiries. */
static gpg_error_t
ks_put_inq_cb (void *opaque, const char *line)
{
  struct ks_put_parm_s *parm = opaque;
  gpg_error_t err = 0;

  if (has_leading_keyword (line, "KEYBLOCK"))
    {
      if (parm->data)
        err = assuan_send_data (parm->ctx, parm->data, parm->datalen);
    }
  else if (has_leading_keyword (line, "KEYBLOCK_INFO"))
    {
      kbnode_t node;
      estream_t fp;

      /* Parse the keyblock and send info lines back to the server.  */
      fp = es_fopenmem (0, "rw");
      if (!fp)
        err = gpg_error_from_syserror ();

      for (node = parm->keyblock; !err && node; node=node->next)
        {
          switch(node->pkt->pkttype)
            {
            case PKT_PUBLIC_KEY:
            case PKT_PUBLIC_SUBKEY:
              {
                PKT_public_key *pk = node->pkt->pkt.public_key;

                keyid_from_pk (pk, NULL);

                es_fprintf (fp, "%s:%08lX%08lX:%u:%u:%u:%u:%s%s:\n",
                            node->pkt->pkttype==PKT_PUBLIC_KEY? "pub" : "sub",
                            (ulong)pk->keyid[0], (ulong)pk->keyid[1],
                            pk->pubkey_algo,
                            nbits_from_pk (pk),
                            pk->timestamp,
                            pk->expiredate,
                            pk->flags.revoked? "r":"",
                            pk->has_expired? "e":"");
              }
              break;

            case PKT_USER_ID:
              {
                PKT_user_id *uid = node->pkt->pkt.user_id;
                int r;

                if (!uid->attrib_data)
                  {
                    es_fprintf (fp, "uid:");

                    /* Quote ':', '%', and any 8-bit characters.  */
                    for (r=0; r < uid->len; r++)
                      {
                        if (uid->name[r] == ':'
                            || uid->name[r]== '%'
                            || (uid->name[r]&0x80))
                          es_fprintf (fp, "%%%02X", (byte)uid->name[r]);
                        else
                          es_putc (uid->name[r], fp);
                      }

                    es_fprintf (fp, ":%u:%u:%s%s:\n",
                                uid->created,uid->expiredate,
                                uid->is_revoked? "r":"",
                                uid->is_expired? "e":"");
                  }
              }
              break;

              /* This bit is really for the benefit of people who
                 store their keys in LDAP servers.  It makes it easy
                 to do queries for things like "all keys signed by
                 Isabella".  */
            case PKT_SIGNATURE:
              {
                PKT_signature *sig = node->pkt->pkt.signature;

                if (IS_UID_SIG (sig))
                  {
                    es_fprintf (fp, "sig:%08lX%08lX:%X:%u:%u:\n",
                                (ulong)sig->keyid[0],(ulong)sig->keyid[1],
                                sig->sig_class, sig->timestamp,
                                sig->expiredate);
                  }
              }
              break;

            default:
              continue;
            }
          /* Given that the last operation was an es_fprintf we should
             get the correct ERRNO if ferror indicates an error.  */
          if (es_ferror (fp))
            err = gpg_error_from_syserror ();
        }

      /* Without an error and if we have an keyblock at all, send the
         data back.  */
      if (!err && parm->keyblock)
        {
          int rc;
          char buffer[512];
          size_t nread;

          es_rewind (fp);
          while (!(rc=es_read (fp, buffer, sizeof buffer, &nread)) && nread)
            {
              err = assuan_send_data (parm->ctx, buffer, nread);
              if (err)
                break;
            }
          if (!err && rc)
            err = gpg_error_from_syserror ();
        }
      es_fclose (fp);
    }
  else
    return gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);

  return err;
}


/* Send a key to the configured server.  {DATA,DATLEN} contains the
   key in OpenPGP binary transport format.  If KEYBLOCK is not NULL it
   has the internal representaion of that key; this is for example
   used to convey meta data to LDAP keyservers.  */
gpg_error_t
gpg_dirmngr_ks_put (ctrl_t ctrl, void *data, size_t datalen, kbnode_t keyblock)
{
  gpg_error_t err;
  assuan_context_t ctx;
  struct ks_put_parm_s parm;

  memset (&parm, 0, sizeof parm);

  /* We are going to parse the keyblock, thus we better make sure the
     all information is readily available.  */
  if (keyblock)
    merge_keys_and_selfsig (keyblock);

  err = open_context (ctrl, &ctx);
  if (err)
    return err;

  parm.ctx = ctx;
  parm.keyblock = keyblock;
  parm.data = data;
  parm.datalen = datalen;

  err = assuan_transact (ctx, "KS_PUT", NULL, NULL,
                         ks_put_inq_cb, &parm, NULL, NULL);

  close_context (ctrl, ctx);
  return err;
}
